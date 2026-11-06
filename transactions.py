import base64
import hashlib
import json
import time
from decimal import Decimal, InvalidOperation

from authenticator.identity import (
    sign_message,
    verify_signature,
)

from database import (
    MAX_TRANSACTION_PAISE,
    get_trusted_device,
    get_payment_request,
    process_wallet_transfer,
)


TRANSACTION_TTL_SECONDS = 24 * 60 * 60
MAX_CLOCK_SKEW_SECONDS = 30


# ============================================================
# CANONICAL SERIALIZATION AND DIGEST
# ============================================================

def canonical_json(data):
    """Serialize data consistently before signing."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


def transaction_digest(transaction):
    """Calculate the SHA-256 digest of transaction data."""
    return hashlib.sha256(
        canonical_json(transaction)
    ).hexdigest()


# ============================================================
# AMOUNT VALIDATION
# ============================================================

def validate_amount(amount):
    """Convert rupees to integer paise."""

    try:
        value = Decimal(str(amount))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Invalid transaction amount.")

    if not value.is_finite() or value <= 0:
        raise ValueError(
            "Amount must be a positive finite number."
        )

    if value.as_tuple().exponent < -2:
        raise ValueError(
            "Amount cannot have more than two decimal places."
        )

    amount_paise = int(value * 100)

    if amount_paise > MAX_TRANSACTION_PAISE:
        raise ValueError(
            "Transaction exceeds the ₹5,000 limit."
        )

    return amount_paise


# ============================================================
# CREATE SIGNED TRANSACTION
# ============================================================

def create_transaction(
    sender_identity,
    receiver_device_id,
    amount,
    payment_request_id=None,
):
    """
    Create a signed transaction proposal.

    Amount is supplied in rupees.

    When payment_request_id is supplied, the proposal is bound
    to the specified merchant payment request. The request must
    exist, be pending, be unexpired, and match the receiver device
    and amount.

    Creating a proposal does not move money.
    """

    if not isinstance(sender_identity, dict):
        raise ValueError("Invalid sender identity.")

    sender_device_id = sender_identity.get("device_id")

    if not isinstance(sender_device_id, str) or not sender_device_id:
        raise ValueError("Sender device ID is required.")

    if (
        not isinstance(receiver_device_id, str)
        or not receiver_device_id
    ):
        raise ValueError("Receiver device ID is required.")

    if sender_device_id == receiver_device_id:
        raise ValueError(
            "Sender and receiver devices must be different."
        )

    amount_paise = validate_amount(amount)
    now = int(time.time())

    # Validate and bind the transaction to the merchant request.
    if payment_request_id is not None:
        if (
            not isinstance(payment_request_id, str)
            or not payment_request_id.strip()
        ):
            raise ValueError("Invalid payment request ID.")

        payment_request = get_payment_request(payment_request_id)

        if payment_request is None:
            raise ValueError("Payment request not found.")

        if payment_request["status"] != "pending":
            raise ValueError(
                "Payment request is no longer pending."
            )

        if payment_request["expires_at"] <= now:
            raise ValueError("Payment request has expired.")

        if payment_request["currency"] != "INR":
            raise ValueError("Unsupported payment currency.")

        if (
            payment_request["receiver_device_id"]
            != receiver_device_id
        ):
            raise ValueError(
                "Receiver device does not match the payment request."
            )

        if payment_request["amount_paise"] != amount_paise:
            raise ValueError(
                "Amount does not match the payment request."
            )

    transaction = {
        "transaction_id": hashlib.sha256(
            (
                f"{sender_device_id}:"
                f"{receiver_device_id}:"
                f"{now}:"
                f"{time.time_ns()}:"
                f"{secrets_token()}"
            ).encode("utf-8")
        ).hexdigest(),

        "sender_device_id": sender_device_id,
        "receiver_device_id": receiver_device_id,
        "amount_paise": amount_paise,
        "currency": "INR",
        "created_at": now,
        "expires_at": now + TRANSACTION_TTL_SECONDS,
        "nonce": hashlib.sha256(
            (
                f"{time.time_ns()}:"
                f"{sender_device_id}:"
                f"{secrets_token()}"
            ).encode("utf-8")
        ).hexdigest(),
        "status": "pending",
    }

    if payment_request_id is not None:
        transaction["payment_request_id"] = payment_request_id

    payload = canonical_json(transaction)
    signature = sign_message(sender_identity, payload)

    return {
        "transaction": transaction,
        "signature": signature,
        "digest": transaction_digest(transaction),
    }


def secrets_token():
    """Return fresh entropy for transaction identifiers."""
    import secrets
    return secrets.token_hex(16)


# ============================================================
# VERIFY AND PROCESS SIGNED TRANSACTION
# ============================================================

def process_transaction(signed_transaction, totp_otp=None):
    """
    Verify a signed transaction and process it through SQLite.

    Sender and receiver wallet IDs are derived from trusted
    device records, never from caller-supplied wallet IDs.

    If the signed transaction contains payment_request_id,
    the database independently validates the merchant request
    and consumes it atomically with the wallet transfer.
    """

    if not isinstance(signed_transaction, dict):
        return {
            "status": "rejected",
            "message": "Invalid transaction record.",
        }

    transaction = signed_transaction.get("transaction")
    signature = signed_transaction.get("signature")
    supplied_digest = signed_transaction.get("digest")

    if not isinstance(transaction, dict) or not signature:
        return {
            "status": "rejected",
            "message": "Transaction or signature is missing.",
        }

    required_fields = {
        "transaction_id",
        "sender_device_id",
        "receiver_device_id",
        "amount_paise",
        "currency",
        "created_at",
        "expires_at",
        "nonce",
        "status",
    }

    if not required_fields.issubset(transaction):
        return {
            "status": "rejected",
            "message": "Required transaction fields are missing.",
        }

    # --------------------------------------------------------
    # TRANSACTION STATE AND CURRENCY
    # --------------------------------------------------------

    if transaction["status"] != "pending":
        return {
            "status": "rejected",
            "message": "Transaction is not pending.",
        }

    if transaction["currency"] != "INR":
        return {
            "status": "rejected",
            "message": "Unsupported currency.",
        }

    transaction_id = transaction["transaction_id"]
    sender_device_id = transaction["sender_device_id"]
    receiver_device_id = transaction["receiver_device_id"]
    nonce = transaction["nonce"]
    payment_request_id = transaction.get("payment_request_id")

    if not all([
        isinstance(transaction_id, str) and transaction_id,
        isinstance(sender_device_id, str) and sender_device_id,
        isinstance(receiver_device_id, str) and receiver_device_id,
    ]):
        return {
            "status": "rejected",
            "message": "Invalid transaction identifiers.",
        }

    if sender_device_id == receiver_device_id:
        return {
            "status": "rejected",
            "message": "Sender and receiver must be different.",
        }

    if not isinstance(nonce, str) or not nonce.strip():
        return {
            "status": "rejected",
            "message": "Invalid transaction nonce.",
        }

    if payment_request_id is not None and (
        not isinstance(payment_request_id, str)
        or not payment_request_id.strip()
    ):
        return {
            "status": "rejected",
            "message": "Invalid payment request ID.",
        }

    # --------------------------------------------------------
    # AMOUNT AND TIMESTAMP VALIDATION
    # --------------------------------------------------------

    amount_paise = transaction["amount_paise"]
    created_at = transaction["created_at"]
    expires_at = transaction["expires_at"]

    if type(amount_paise) is not int:
        return {
            "status": "rejected",
            "message": "Amount must be an integer in paise.",
        }

    if type(created_at) is not int or type(expires_at) is not int:
        return {
            "status": "rejected",
            "message": "Invalid transaction timestamps.",
        }

    if amount_paise <= 0 or amount_paise > MAX_TRANSACTION_PAISE:
        return {
            "status": "rejected",
            "message": "Amount exceeds the allowed limit.",
        }

    now = int(time.time())

    if created_at > now + MAX_CLOCK_SKEW_SECONDS:
        return {
            "status": "rejected",
            "message": "Transaction timestamp is in the future.",
        }

    if expires_at <= now or expires_at <= created_at:
        return {
            "status": "rejected",
            "message": "Transaction has expired or has invalid expiry.",
        }

    if expires_at - created_at > TRANSACTION_TTL_SECONDS:
        return {
            "status": "rejected",
            "message": "Transaction lifetime exceeds the allowed limit.",
        }

    # --------------------------------------------------------
    # TRUSTED DEVICE VALIDATION
    # --------------------------------------------------------

    sender = get_trusted_device(sender_device_id)
    receiver = get_trusted_device(receiver_device_id)

    if not sender or sender["status"] != "trusted":
        return {
            "status": "rejected",
            "message": "Sender device is not trusted.",
        }

    if not receiver or receiver["status"] != "trusted":
        return {
            "status": "rejected",
            "message": "Receiver device is not trusted.",
        }

    # --------------------------------------------------------
    # SENDER PUBLIC KEY VALIDATION
    # --------------------------------------------------------

    sender_public_key = sender["public_key"]

    try:
        public_key_bytes = base64.b64decode(
            sender_public_key,
            validate=True,
        )

        expected_sender_id = hashlib.sha256(
            public_key_bytes
        ).hexdigest()

    except (ValueError, TypeError):
        return {
            "status": "rejected",
            "message": "Sender public key is invalid.",
        }

    if expected_sender_id != sender_device_id:
        return {
            "status": "rejected",
            "message": "Sender public key does not match device ID.",
        }

    # --------------------------------------------------------
    # SIGNATURE AND DIGEST VALIDATION
    # --------------------------------------------------------

    payload = canonical_json(transaction)

    try:
        signature_is_valid = verify_signature(
            sender_public_key,
            payload,
            signature,
        )
    except Exception:
        signature_is_valid = False

    if not signature_is_valid:
        return {
            "status": "rejected",
            "message": "Transaction signature verification failed.",
        }

    expected_digest = transaction_digest(transaction)

    if (
        not isinstance(supplied_digest, str)
        or not secrets_compare(supplied_digest, expected_digest)
    ):
        return {
            "status": "rejected",
            "message": "Transaction digest verification failed.",
        }

    # --------------------------------------------------------
    # DERIVE WALLETS FROM TRUSTED DEVICE RECORDS
    # --------------------------------------------------------

    sender_user_id = sender["owner_user_id"]
    receiver_user_id = receiver["owner_user_id"]

    if sender_user_id == receiver_user_id:
        return {
            "status": "rejected",
            "message": "Sender and receiver must use different wallets.",
        }

    # --------------------------------------------------------
    # VALIDATE REQUEST BEFORE PROCESSING
    # --------------------------------------------------------

    if payment_request_id is not None:
        payment_request = get_payment_request(payment_request_id)

        if payment_request is None:
            return {
                "status": "rejected",
                "message": "Payment request not found.",
            }

        if payment_request["status"] != "pending":
            return {
                "status": "rejected",
                "message": "Payment request is no longer pending.",
            }

        if payment_request["expires_at"] <= now:
            return {
                "status": "rejected",
                "message": "Payment request has expired.",
            }

        if payment_request["merchant_id"] != receiver_user_id:
            return {
                "status": "rejected",
                "message": "Payment request belongs to another merchant.",
            }

        if (
            payment_request["receiver_device_id"]
            != receiver_device_id
        ):
            return {
                "status": "rejected",
                "message": "Receiver device does not match the request.",
            }

        if payment_request["amount_paise"] != amount_paise:
            return {
                "status": "rejected",
                "message": "Amount does not match the payment request.",
            }

        if payment_request["currency"] != transaction["currency"]:
            return {
                "status": "rejected",
                "message": "Currency does not match the payment request.",
            }

    # --------------------------------------------------------
    # ATOMIC DATABASE PROCESSING
    # --------------------------------------------------------

    return process_wallet_transfer(
    transaction_id=transaction_id,
    sender_id=sender_user_id,
    receiver_id=receiver_user_id,
    amount_paise=amount_paise,
    sender_device_id=sender_device_id,
    receiver_device_id=receiver_device_id,
    signature=signature,
    digest=expected_digest,
    signature_verified=True,
    nonce=nonce,
    payment_request_id=payment_request_id,
    totp_otp=totp_otp,
    )


def secrets_compare(first, second):
    """Compare digest strings in constant time."""
    import secrets
    return secrets.compare_digest(first, second)