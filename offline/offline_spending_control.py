# offline_spending_controls.py

import sqlite3
import time

from offline.offline_ledger import (
    get_ledger_connection,
    MAX_TRANSACTION_PAISE,
)
from offline.offline_protocol import calculate_digest, canonical_json


# NetBridge simulation-only spending policy
MAX_SINGLE_PAYMENT_PAISE = 500_000       # ₹5,000
MAX_24_HOUR_SPENDING_PAISE = 1_000_000   # ₹10,000
SPENDING_WINDOW_SECONDS = 24 * 60 * 60


def _validate_authorization(verification_result, signed_authorization):
    """Validate the supplied cryptographic verification result."""

    if not isinstance(verification_result, dict):
        raise ValueError("Verification result is required.")

    if verification_result.get("valid") is not True:
        raise ValueError("Authorization has not been verified.")

    if not isinstance(signed_authorization, dict):
        raise ValueError("Signed authorization is required.")

    authorization = signed_authorization.get("authorization")

    if not isinstance(authorization, dict):
        raise ValueError("Authorization data is missing.")

    required_fields = {
        "authorization_id",
        "request_digest",
        "customer_user_id",
        "customer_device_id",
        "merchant_user_id",
        "merchant_device_id",
        "amount_paise",
        "currency",
        "nonce",
        "status",
        "created_at",
        "expires_at",
    }

    if not required_fields.issubset(authorization):
        raise ValueError("Authorization fields are incomplete.")

    if authorization["status"] != "pending_reconciliation":
        raise ValueError("Unexpected authorization status.")

    created_at = authorization["created_at"]
    expires_at = authorization["expires_at"]
    current_time = int(time.time())
    if (
        type(created_at) is not int
        or type(expires_at) is not int
        or created_at <= 0
        or expires_at <= created_at
        or expires_at - created_at > 900
        or created_at > current_time + 30
    ):
        raise ValueError("Invalid authorization validity period.")
    if expires_at <= current_time:
        raise ValueError("Customer authorization has expired.")

    amount = authorization["amount_paise"]

    if (
        type(amount) is not int
        or not 1 <= amount <= MAX_SINGLE_PAYMENT_PAISE
        or amount > MAX_TRANSACTION_PAISE
    ):
        raise ValueError("Payment exceeds the single-payment limit.")

    if authorization["currency"] != "INR":
        raise ValueError("Unsupported currency.")

    for field in (
        "authorization_id",
        "request_digest",
        "customer_user_id",
        "customer_device_id",
        "merchant_user_id",
        "merchant_device_id",
        "nonce",
    ):
        value = authorization[field]

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Invalid {field}.")

    digest = calculate_digest(authorization)

    if verification_result.get("authorization_digest") != digest:
        raise ValueError("Authorization digest does not match.")

    if verification_result.get("authorization") != authorization:
        raise ValueError("Verified authorization data does not match.")

    return authorization, amount, digest


def get_customer_offline_spending(
    customer_user_id,
    database_path=None,
):
    """
    Calculate the customer's recorded spending in the rolling
    24-hour window.

    All recorded statuses count except rejected records.
    """

    if (
        not isinstance(customer_user_id, str)
        or not customer_user_id.strip()
    ):
        raise ValueError("Customer ID is required.")

    cutoff = int(time.time()) - SPENDING_WINDOW_SECONDS

    connection = get_ledger_connection(database_path)

    try:
        row = connection.execute(
            """
            SELECT COALESCE(SUM(amount_paise), 0) AS total
            FROM offline_payments
            WHERE customer_user_id = ?
              AND received_at >= ?
              AND status != 'rejected'
            """,
            (customer_user_id, cutoff),
        ).fetchone()

        total_paise = int(row["total"])

        return {
            "customer_user_id": customer_user_id,
            "spent_paise": total_paise,
            "spent_rupees": total_paise / 100,
            "limit_paise": MAX_24_HOUR_SPENDING_PAISE,
            "limit_rupees": MAX_24_HOUR_SPENDING_PAISE / 100,
            "remaining_paise": max(
                0,
                MAX_24_HOUR_SPENDING_PAISE - total_paise,
            ),
            "remaining_rupees": max(
                0,
                MAX_24_HOUR_SPENDING_PAISE - total_paise,
            ) / 100,
            "window_seconds": SPENDING_WINDOW_SECONDS,
        }

    finally:
        connection.close()


def record_authorization_with_spending_limits(
    verification_result,
    signed_authorization,
    database_path=None,
):
    """
    Enforce offline spending limits and record an authorization
    atomically in the local SQLite ledger.

    This function replaces a direct call to
    record_verified_authorization() when spending limits are required.

    The caller must first verify the customer's signature against
    a previously trusted public key.
    """

    authorization, amount, authorization_digest = (
        _validate_authorization(
            verification_result,
            signed_authorization,
        )
    )

    authorization_json = canonical_json(
        signed_authorization
    ).decode("utf-8")

    now = int(time.time())
    cutoff = now - SPENDING_WINDOW_SECONDS

    connection = get_ledger_connection(database_path)

    try:
        # Acquire the write lock before checking spending.
        # This prevents concurrent writers from both spending
        # the same remaining allowance in this database.
        connection.execute("BEGIN IMMEDIATE")

        existing = connection.execute(
            """
            SELECT authorization_id
            FROM offline_payments
            WHERE authorization_id = ?
               OR request_digest = ?
               OR authorization_digest = ?
               OR nonce = ?
            LIMIT 1
            """,
            (
                authorization["authorization_id"],
                authorization["request_digest"],
                authorization_digest,
                authorization["nonce"],
            ),
        ).fetchone()

        if existing:
            raise ValueError(
                "Duplicate authorization, request, or nonce."
            )

        spending_row = connection.execute(
            """
            SELECT COALESCE(SUM(amount_paise), 0) AS total
            FROM offline_payments
            WHERE customer_user_id = ?
              AND received_at >= ?
              AND status != 'rejected'
            """,
            (
                authorization["customer_user_id"],
                cutoff,
            ),
        ).fetchone()

        spent_paise = int(spending_row["total"])

        if spent_paise + amount > MAX_24_HOUR_SPENDING_PAISE:
            remaining_paise = max(
                0,
                MAX_24_HOUR_SPENDING_PAISE - spent_paise,
            )

            raise ValueError(
                "Offline spending limit exceeded. "
                f"Recorded spending: ₹{spent_paise / 100:.2f}; "
                f"remaining allowance: ₹{remaining_paise / 100:.2f}."
            )

        connection.execute(
            """
            INSERT INTO offline_payments (
                authorization_id,
                request_digest,
                authorization_digest,
                nonce,
                customer_user_id,
                customer_device_id,
                merchant_user_id,
                merchant_device_id,
                amount_paise,
                currency,
                status,
                authorization_json,
                received_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                authorization["authorization_id"],
                authorization["request_digest"],
                authorization_digest,
                authorization["nonce"],
                authorization["customer_user_id"],
                authorization["customer_device_id"],
                authorization["merchant_user_id"],
                authorization["merchant_device_id"],
                amount,
                authorization["currency"],
                "pending_reconciliation",
                authorization_json,
                now,
            ),
        )

        connection.commit()

        new_total = spent_paise + amount

        return {
            "status": "accepted_locally",
            "authorization_id": authorization["authorization_id"],
            "amount_paise": amount,
            "currency": "INR",
            "ledger_status": "pending_reconciliation",
            "spending_paise": new_total,
            "spending_rupees": new_total / 100,
            "remaining_paise": (
                MAX_24_HOUR_SPENDING_PAISE - new_total
            ),
            "remaining_rupees": (
                MAX_24_HOUR_SPENDING_PAISE - new_total
            ) / 100,
            "message": (
                "Authorization stored locally within the spending "
                "limit. Global settlement has not been established."
            ),
        }

    except sqlite3.IntegrityError as exc:
        connection.rollback()

        raise ValueError(
            "The ledger rejected a duplicate or invalid record."
        ) from exc

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()