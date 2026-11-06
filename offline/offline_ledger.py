# offline_ledger.py

import json
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path

from offline.offline_protocol import calculate_digest, canonical_json


PROJECT_DIR = Path(__file__).resolve().parent
DATA_DIR = PROJECT_DIR.parent / "data"
LEDGER_DATABASE = DATA_DIR / "offline_ledger.db"

MAX_TRANSACTION_PAISE = 500_000


def get_ledger_connection(database_path=None):
    """Open a local SQLite ledger connection safely."""
    path = Path(database_path) if database_path else LEDGER_DATABASE
    path.parent.mkdir(parents=True, exist_ok=True)

    connection = sqlite3.connect(
        str(path),
        timeout=10,
        isolation_level=None,
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")

    return connection


@contextmanager
def closing_ledger_connection(database_path=None):
    """Commit or roll back changes, then always close the connection."""
    connection = get_ledger_connection(database_path)

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_ledger(database_path=None):
    """Create ledger tables without deleting existing records."""
    with closing_ledger_connection(database_path) as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS offline_payments (
                authorization_id TEXT PRIMARY KEY,
                request_digest TEXT NOT NULL UNIQUE,
                authorization_digest TEXT NOT NULL UNIQUE,
                nonce TEXT NOT NULL UNIQUE,
                customer_user_id TEXT NOT NULL,
                customer_device_id TEXT NOT NULL,
                merchant_user_id TEXT NOT NULL,
                merchant_device_id TEXT NOT NULL,
                amount_paise INTEGER NOT NULL
                    CHECK(amount_paise > 0 AND amount_paise <= 500000),
                currency TEXT NOT NULL CHECK(currency = 'INR'),
                status TEXT NOT NULL
                    CHECK(status IN (
                        'pending_reconciliation',
                        'reconciled',
                        'conflict',
                        'rejected'
                    )),
                authorization_json TEXT NOT NULL,
                received_at INTEGER NOT NULL
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_offline_payments_status
            ON offline_payments(status, received_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_offline_payments_customer
            ON offline_payments(customer_user_id, received_at)
        """)

    return True


def record_verified_authorization(
    verification_result,
    signed_authorization,
    database_path=None,
):
    """
    Store an authorization that has passed cryptographic verification.

    The caller must verify the customer's signature against a
    previously trusted public key before calling this function.
    """
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
    received_at = int(time.time())
    if (
        type(created_at) is not int
        or type(expires_at) is not int
        or created_at <= 0
        or expires_at <= created_at
        or expires_at - created_at > 900
        or created_at > received_at + 30
    ):
        raise ValueError("Invalid authorization validity period.")
    if expires_at <= received_at:
        raise ValueError("Customer authorization has expired.")

    amount = authorization["amount_paise"]

    if type(amount) is not int or not 1 <= amount <= MAX_TRANSACTION_PAISE:
        raise ValueError("Invalid payment amount.")

    if authorization["currency"] != "INR":
        raise ValueError("Unsupported currency.")

    authorization_digest = calculate_digest(authorization)

    if (
        verification_result.get("authorization_digest")
        != authorization_digest
    ):
        raise ValueError("Verified authorization digest does not match.")

    if verification_result.get("authorization") != authorization:
        raise ValueError("Verified authorization data does not match.")

    required_text_fields = (
        "authorization_id",
        "request_digest",
        "customer_user_id",
        "customer_device_id",
        "merchant_user_id",
        "merchant_device_id",
        "nonce",
    )

    for field in required_text_fields:
        value = authorization[field]

        if not isinstance(value, str) or not value.strip():
            raise ValueError(f"Invalid {field}.")

    authorization_json = canonical_json(
        signed_authorization
    ).decode("utf-8")

    connection = get_ledger_connection(database_path)

    try:
        connection.execute("BEGIN IMMEDIATE")

        connection.execute("""
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
        """, (
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
            received_at,
        ))

        connection.commit()

        return {
            "status": "accepted_locally",
            "authorization_id": authorization["authorization_id"],
            "amount_paise": amount,
            "currency": "INR",
            "ledger_status": "pending_reconciliation",
            "message": (
                "Authorization stored locally. "
                "Global settlement has not been established."
            ),
        }

    except sqlite3.IntegrityError as exc:
        connection.rollback()

        raise ValueError(
            "Duplicate authorization, request, or nonce. "
            "The local ledger did not accept this record."
        ) from exc

    except Exception:
        connection.rollback()
        raise

    finally:
        connection.close()


def list_offline_payments(
    status="pending_reconciliation",
    limit=100,
    database_path=None,
):
    """Return recent local payment records."""
    allowed_statuses = {
        "pending_reconciliation",
        "reconciled",
        "conflict",
        "rejected",
    }

    if status not in allowed_statuses:
        raise ValueError("Invalid ledger status.")

    if type(limit) is not int or not 1 <= limit <= 1000:
        raise ValueError("Limit must be between 1 and 1000.")

    connection = get_ledger_connection(database_path)

    try:
        rows = connection.execute("""
            SELECT
                authorization_id,
                request_digest,
                authorization_digest,
                customer_user_id,
                customer_device_id,
                merchant_user_id,
                merchant_device_id,
                amount_paise,
                currency,
                status,
                received_at
            FROM offline_payments
            WHERE status = ?
            ORDER BY received_at DESC
            LIMIT ?
        """, (status, limit)).fetchall()

        return [dict(row) for row in rows]

    finally:
        connection.close()


def get_offline_payment(authorization_id, database_path=None):
    """Look up one local payment by authorization ID."""
    if not isinstance(authorization_id, str) or not authorization_id.strip():
        raise ValueError("Authorization ID is required.")

    connection = get_ledger_connection(database_path)

    try:
        row = connection.execute("""
            SELECT *
            FROM offline_payments
            WHERE authorization_id = ?
        """, (authorization_id,)).fetchone()

        return dict(row) if row else None

    finally:
        connection.close()