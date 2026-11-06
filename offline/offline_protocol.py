# offline_protocol.py

import hashlib
import json
import secrets
import time
from decimal import Decimal, InvalidOperation

from authenticator.identity import sign_message, verify_signature


PROTOCOL_VERSION = "netbridge-offline-v1"
CURRENCY = "INR"
SIMULATION_MODE = "simulation_only"

MAX_TRANSACTION_PAISE = 500_000  # ₹5,000
REQUEST_TTL_SECONDS = 5 * 60
AUTHORIZATION_TTL_SECONDS = 5 * 60


def canonical_json(data):
    """Return deterministic JSON bytes for cryptographic signatures."""
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def calculate_digest(data):
    """Calculate SHA-256 over canonical JSON."""
    return hashlib.sha256(canonical_json(data)).hexdigest()


def amount_to_paise(amount_rupees):
    """Convert rupees to integer paise without floating-point arithmetic."""
    try:
        amount = Decimal(str(amount_rupees))
    except (InvalidOperation, ValueError, TypeError):
        raise ValueError("Invalid payment amount.") from None

    if not amount.is_finite() or amount <= 0:
        raise ValueError("Payment amount must be positive.")

    if amount.as_tuple().exponent < -2:
        raise ValueError("Amount cannot have more than two decimal places.")

    paise = int(amount * 100)

    if paise > MAX_TRANSACTION_PAISE:
        raise ValueError("Offline payment exceeds the ₹5,000 limit.")

    return paise


def _require_text(value, field):
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Missing or invalid {field}.")

    return value


def _require_timestamp(value, field):
    if type(value) is not int or value <= 0:
        raise ValueError(f"Invalid {field}.")

    return value


def create_payment_request(
    merchant_identity,
    merchant_user_id,
    amount_rupees,
    ttl_seconds=REQUEST_TTL_SECONDS,
):
    """
    Create a merchant-signed payment request for QR encoding.

    This creates a request only; it does not transfer money.
    """
    merchant_device_id = _require_text(
        merchant_identity.get("device_id"),
        "merchant device ID",
    )
    merchant_user_id = _require_text(
        merchant_user_id,
        "merchant user ID",
    )

    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 900:
        raise ValueError("Request lifetime must be between 1 and 900 seconds.")

    now = int(time.time())

    request = {
        "protocol": PROTOCOL_VERSION,
        "mode": SIMULATION_MODE,
        "request_id": secrets.token_hex(16),
        "merchant_user_id": merchant_user_id,
        "merchant_device_id": merchant_device_id,
        "amount_paise": amount_to_paise(amount_rupees),
        "currency": CURRENCY,
        "created_at": now,
        "expires_at": now + ttl_seconds,
        "nonce": secrets.token_hex(32),
    }

    signature = sign_message(
        merchant_identity,
        canonical_json(request),
    )

    return {
        "request": request,
        "merchant_signature": signature,
        "merchant_public_key": merchant_identity["public_key"],
    }


def verify_payment_request(
    signed_request,
    trusted_merchant_public_key,
    now=None,
):
    """
    Verify a merchant QR request offline.

    trusted_merchant_public_key must come from a previously trusted
    merchant identity, not merely from the scanned QR code.
    """
    if not isinstance(signed_request, dict):
        raise ValueError("Invalid payment request.")

    request = signed_request.get("request")
    signature = signed_request.get("merchant_signature")
    supplied_public_key = signed_request.get("merchant_public_key")

    if not isinstance(request, dict):
        raise ValueError("Payment request data is missing.")

    if not isinstance(signature, str) or not signature:
        raise ValueError("Merchant signature is missing.")

    if not isinstance(trusted_merchant_public_key, str):
        raise ValueError("Trusted merchant public key is required.")

    if supplied_public_key != trusted_merchant_public_key:
        raise ValueError("QR public key does not match the trusted merchant.")

    required = {
        "protocol",
        "mode",
        "request_id",
        "merchant_user_id",
        "merchant_device_id",
        "amount_paise",
        "currency",
        "created_at",
        "expires_at",
        "nonce",
    }

    if set(request) != required:
        raise ValueError("Unexpected or missing payment request fields.")

    if request["protocol"] != PROTOCOL_VERSION:
        raise ValueError("Unsupported payment protocol.")

    if request["mode"] != SIMULATION_MODE:
        raise ValueError("Only simulation payments are supported.")

    if request["currency"] != CURRENCY:
        raise ValueError("Unsupported currency.")

    _require_text(request["request_id"], "request ID")
    _require_text(request["merchant_user_id"], "merchant user ID")
    _require_text(request["merchant_device_id"], "merchant device ID")
    _require_text(request["nonce"], "request nonce")

    amount = request["amount_paise"]
    if type(amount) is not int or not 1 <= amount <= MAX_TRANSACTION_PAISE:
        raise ValueError("Invalid payment amount.")

    created_at = _require_timestamp(request["created_at"], "creation time")
    expires_at = _require_timestamp(request["expires_at"], "expiry time")
    current_time = int(time.time()) if now is None else now

    if type(current_time) is not int:
        raise ValueError("Invalid verification time.")

    if expires_at <= created_at or expires_at - created_at > 900:
        raise ValueError("Invalid payment request lifetime.")

    if created_at > current_time + 30:
        raise ValueError("Payment request is dated in the future.")

    if expires_at <= current_time:
        raise ValueError("Payment request has expired.")

    if not verify_signature(
        trusted_merchant_public_key,
        canonical_json(request),
        signature,
    ):
        raise ValueError("Merchant signature verification failed.")

    return {
        "valid": True,
        "request": request,
        "request_digest": calculate_digest(request),
        "message": "Merchant request verified. Customer review is required.",
    }


def create_customer_authorization(
    customer_identity,
    customer_user_id,
    verified_request,
    ttl_seconds=AUTHORIZATION_TTL_SECONDS,
):
    """
    Create a customer-signed authorization bound to a verified request.

    The caller must verify the request and show its merchant and amount
    to the customer before asking for authorization.
    """
    if not isinstance(verified_request, dict):
        raise ValueError("Verified payment request is required.")

    request = verified_request.get("request")
    expected_digest = verified_request.get("request_digest")

    if verified_request.get("valid") is not True or not isinstance(request, dict):
        raise ValueError("A valid verified payment request is required.")

    if expected_digest != calculate_digest(request):
        raise ValueError("Verified request digest does not match.")

    now = int(time.time())
    request_expiry = _require_timestamp(
        request.get("expires_at"), "payment request expiry"
    )
    if request_expiry <= now:
        raise ValueError("Payment request has expired; create a new QR request.")

    if type(ttl_seconds) is not int or not 1 <= ttl_seconds <= 900:
        raise ValueError("Authorization lifetime must be between 1 and 900 seconds.")

    customer_device_id = _require_text(
        customer_identity.get("device_id"),
        "customer device ID",
    )
    customer_user_id = _require_text(
        customer_user_id,
        "customer user ID",
    )

    if customer_device_id == request["merchant_device_id"]:
        raise ValueError("Customer and merchant devices must be different.")

    authorization_expiry = min(now + ttl_seconds, request_expiry)

    authorization = {
        "protocol": PROTOCOL_VERSION,
        "mode": SIMULATION_MODE,
        "authorization_id": secrets.token_hex(16),
        "request_digest": expected_digest,
        "customer_user_id": customer_user_id,
        "customer_device_id": customer_device_id,
        "merchant_user_id": request["merchant_user_id"],
        "merchant_device_id": request["merchant_device_id"],
        "amount_paise": request["amount_paise"],
        "currency": CURRENCY,
        "created_at": now,
        "expires_at": authorization_expiry,
        "nonce": secrets.token_hex(32),
        "status": "pending_reconciliation",
    }

    signature = sign_message(
        customer_identity,
        canonical_json(authorization),
    )

    return {
        "authorization": authorization,
        "customer_signature": signature,
        "customer_public_key": customer_identity["public_key"],
    }


def verify_customer_authorization(
    signed_authorization,
    verified_request,
    trusted_customer_public_key,
    now=None,
):
    """
    Verify a customer authorization offline at the merchant.

    The customer public key must be obtained from a trusted local
    identity registry, not blindly accepted from the QR itself.
    """
    if not isinstance(signed_authorization, dict):
        raise ValueError("Invalid customer authorization.")

    if not isinstance(verified_request, dict):
        raise ValueError("Verified merchant request is required.")

    authorization = signed_authorization.get("authorization")
    signature = signed_authorization.get("customer_signature")
    supplied_public_key = signed_authorization.get("customer_public_key")

    if not isinstance(authorization, dict):
        raise ValueError("Authorization data is missing.")

    if not isinstance(signature, str) or not signature:
        raise ValueError("Customer signature is missing.")

    if not isinstance(trusted_customer_public_key, str):
        raise ValueError("Trusted customer public key is required.")

    if supplied_public_key != trusted_customer_public_key:
        raise ValueError("QR public key does not match the trusted customer.")

    request = verified_request.get("request")
    request_digest = verified_request.get("request_digest")

    if verified_request.get("valid") is not True or not isinstance(request, dict):
        raise ValueError("A valid verified merchant request is required.")

    if request_digest != calculate_digest(request):
        raise ValueError("Merchant request digest does not match.")

    required = {
        "protocol",
        "mode",
        "authorization_id",
        "request_digest",
        "customer_user_id",
        "customer_device_id",
        "merchant_user_id",
        "merchant_device_id",
        "amount_paise",
        "currency",
        "created_at",
        "expires_at",
        "nonce",
        "status",
    }

    if set(authorization) != required:
        raise ValueError("Unexpected or missing authorization fields.")

    if authorization["protocol"] != PROTOCOL_VERSION:
        raise ValueError("Unsupported authorization protocol.")

    if authorization["mode"] != SIMULATION_MODE:
        raise ValueError("Only simulation payments are supported.")

    if authorization["currency"] != CURRENCY:
        raise ValueError("Unsupported currency.")

    if authorization["status"] != "pending_reconciliation":
        raise ValueError("Authorization has an invalid status.")

    _require_text(authorization["authorization_id"], "authorization ID")
    _require_text(authorization["customer_user_id"], "customer user ID")
    _require_text(authorization["customer_device_id"], "customer device ID")
    _require_text(authorization["nonce"], "authorization nonce")

    if authorization["request_digest"] != request_digest:
        raise ValueError("Authorization belongs to a different payment request.")

    fields_to_match = (
        "merchant_user_id",
        "merchant_device_id",
        "amount_paise",
        "currency",
    )

    for field in fields_to_match:
        if authorization[field] != request[field]:
            raise ValueError(f"Authorization does not match request field: {field}.")

    if authorization["customer_device_id"] == request["merchant_device_id"]:
        raise ValueError("Customer and merchant devices must be different.")

    amount = authorization["amount_paise"]
    if type(amount) is not int or not 1 <= amount <= MAX_TRANSACTION_PAISE:
        raise ValueError("Invalid authorization amount.")

    created_at = _require_timestamp(
        authorization["created_at"],
        "authorization creation time",
    )
    expires_at = _require_timestamp(
        authorization["expires_at"],
        "authorization expiry time",
    )
    current_time = int(time.time()) if now is None else now

    if type(current_time) is not int:
        raise ValueError("Invalid verification time.")

    request_created_at = _require_timestamp(request.get("created_at"), "request creation time")
    request_expires_at = _require_timestamp(request.get("expires_at"), "request expiry time")
    if request_expires_at <= request_created_at or request_expires_at <= current_time:
        raise ValueError("The merchant payment request has expired.")

    if expires_at <= created_at or expires_at - created_at > 900:
        raise ValueError("Invalid authorization lifetime.")

    if expires_at > request_expires_at:
        raise ValueError("Authorization cannot outlive the merchant payment request.")

    if created_at > current_time + 30:
        raise ValueError("Authorization is dated in the future.")

    if expires_at <= current_time:
        raise ValueError("Customer authorization has expired.")

    if not verify_signature(
        trusted_customer_public_key,
        canonical_json(authorization),
        signature,
    ):
        raise ValueError("Customer signature verification failed.")

    return {
        "valid": True,
        "authorization": authorization,
        "authorization_digest": calculate_digest(authorization),
        "message": (
            "Authorization verified locally. "
            "It is not yet reconciled or globally settled."
        ),
    }