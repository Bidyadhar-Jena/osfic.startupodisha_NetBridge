import sqlite3
import os
import hashlib
import secrets
import time
from contextlib import closing


# ============================================================
# CONFIGURATION
# ============================================================

DATABASE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "netbridge.db"
)

MAX_TRANSACTION_PAISE = 500000       # ₹5,000
MAX_WALLET_BALANCE_PAISE = 1000000   # ₹10,000

DEFAULT_PAYMENT_REQUEST_TTL = 300    # 5 minutes


# ============================================================
# PIN SECURITY
# ============================================================

def hash_pin(pin, salt=None):
    if not isinstance(pin, str) or not pin:
        raise ValueError("PIN must be a non-empty string.")

    if salt is None:
        salt = secrets.token_hex(16)

    pin_hash = hashlib.pbkdf2_hmac(
        "sha256",
        pin.encode("utf-8"),
        salt.encode("utf-8"),
        600_000
    ).hex()

    return f"{salt}${pin_hash}"


def verify_pin(pin, stored_hash):
    try:
        if not isinstance(pin, str):
            return False

        salt, expected_hash = stored_hash.split("$", 1)

        actual_hash = hashlib.pbkdf2_hmac(
            "sha256",
            pin.encode("utf-8"),
            salt.encode("utf-8"),
            600_000
        ).hex()

        return secrets.compare_digest(
            actual_hash,
            expected_hash
        )

    except (ValueError, AttributeError, TypeError):
        return False


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():
    connection = sqlite3.connect(
        DATABASE,
        timeout=10
    )

    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")

    return connection


# ============================================================
# DATABASE INITIALIZATION AND MIGRATIONS
# ============================================================

def initialize_database():
    with closing(get_connection()) as connection:

        # ----------------------------------------------------
        # WALLETS
        # ----------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS wallets (
                user_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                balance INTEGER NOT NULL CHECK(balance >= 0),
                pin_hash TEXT NOT NULL
            )
        """)

        # ----------------------------------------------------
        # TRANSACTIONS
        # ----------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                transaction_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                amount INTEGER NOT NULL CHECK(amount > 0),
                status TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id)
                    REFERENCES wallets(user_id),
                FOREIGN KEY(receiver_id)
                    REFERENCES wallets(user_id)
            )
        """)

        # Preserve existing transaction records while adding
        # any columns required by the signed-transaction system.

        existing_columns = {
            row["name"]
            for row in connection.execute(
                "PRAGMA table_info(transactions)"
            ).fetchall()
        }

        new_columns = {
            "sender_device_id": "TEXT",
            "receiver_device_id": "TEXT",
            "signature": "TEXT",
            "digest": "TEXT",
            "expires_at": "INTEGER",
            "processed_at": "TEXT",
            "nonce": "TEXT",
        }

        for column_name, column_type in new_columns.items():
            if column_name not in existing_columns:
                connection.execute(
                    f"ALTER TABLE transactions "
                    f"ADD COLUMN {column_name} {column_type}"
                )

        # ----------------------------------------------------
        # TRUSTED DEVICES
        # ----------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS trusted_devices (
                device_id TEXT PRIMARY KEY,
                owner_user_id TEXT NOT NULL,
                public_key TEXT NOT NULL,
                device_name TEXT NOT NULL DEFAULT 'Unnamed device',
                status TEXT NOT NULL DEFAULT 'trusted'
                    CHECK(status IN ('trusted', 'revoked')),
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(owner_user_id)
                    REFERENCES wallets(user_id)
            )
        """)

        # ----------------------------------------------------
        # MERCHANT PAYMENT REQUESTS
        # ----------------------------------------------------

        connection.execute("""
            CREATE TABLE IF NOT EXISTS payment_requests (
                request_id TEXT PRIMARY KEY,
                merchant_id TEXT NOT NULL,
                receiver_device_id TEXT NOT NULL,
                amount_paise INTEGER NOT NULL
                    CHECK(amount_paise > 0),
                currency TEXT NOT NULL DEFAULT 'INR'
                    CHECK(currency = 'INR'),
                status TEXT NOT NULL DEFAULT 'pending'
                    CHECK(status IN (
                        'pending',
                        'processed',
                        'expired',
                        'cancelled'
                    )),
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                transaction_id TEXT UNIQUE,
                FOREIGN KEY(merchant_id)
                    REFERENCES wallets(user_id),
                FOREIGN KEY(transaction_id)
                    REFERENCES transactions(transaction_id)
            )
        """)

        # Receipts created by the two-QR offline simulation are recorded
        # separately from wallet transfers. Accepting a receipt must never
        # write a transaction row or change either wallet balance.
        connection.execute("""
            CREATE TABLE IF NOT EXISTS offline_qr_receipts (
                receipt_id TEXT PRIMARY KEY,
                request_id TEXT NOT NULL UNIQUE,
                customer_user_id TEXT NOT NULL,
                merchant_user_id TEXT NOT NULL,
                merchant_device_id TEXT NOT NULL,
                amount_paise INTEGER NOT NULL
                    CHECK(amount_paise > 0 AND amount_paise <= 500000),
                currency TEXT NOT NULL CHECK(currency = 'INR'),
                payment_status TEXT NOT NULL
                    CHECK(payment_status = 'accepted_for_simulation_review'),
                settlement_status TEXT NOT NULL
                    CHECK(settlement_status = 'pending_reconciliation'),
                receipt_created_at INTEGER NOT NULL,
                received_at INTEGER NOT NULL,
                FOREIGN KEY(request_id) REFERENCES payment_requests(request_id),
                FOREIGN KEY(customer_user_id) REFERENCES wallets(user_id),
                FOREIGN KEY(merchant_user_id) REFERENCES wallets(user_id)
            )
        """)

        # ----------------------------------------------------
        # INDEXES
        # ----------------------------------------------------

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_sender
            ON transactions(sender_id, created_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_receiver
            ON transactions(receiver_id, created_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_transactions_status
            ON transactions(status)
        """)

        connection.execute("""
            CREATE UNIQUE INDEX IF NOT EXISTS idx_transactions_nonce
            ON transactions(nonce)
            WHERE nonce IS NOT NULL
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_payment_requests_merchant
            ON payment_requests(merchant_id, created_at)
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_payment_requests_status_expiry
            ON payment_requests(status, expires_at)
        """)

        # ----------------------------------------------------
        # DEMO ACCOUNTS
        # ----------------------------------------------------

        demo_accounts = [
            ("CUSTOMER001", "Demo Customer", 50000, "1234"),
            ("CUSTOMER002", "Demo Receiver", 50000, "4321"),
            ("MERCHANT001", "Demo Merchant", 10000, "5678"),
        ]

        for user_id, name, balance, pin in demo_accounts:
            connection.execute("""
                INSERT OR IGNORE INTO wallets (
                    user_id,
                    name,
                    balance,
                    pin_hash
                )
                VALUES (?, ?, ?, ?)
            """, (
                user_id,
                name,
                balance,
                hash_pin(pin)
            ))

        connection.commit()


def reset_demo_wallets_and_history():
    """Restore the fictional demo wallets when a new app.py run starts."""
    with closing(get_connection()) as connection:
        connection.execute("BEGIN IMMEDIATE")
        # Child rows must be deleted before their referenced rows.
        connection.execute("DELETE FROM offline_qr_receipts")
        connection.execute("DELETE FROM payment_requests")
        connection.execute("DELETE FROM transactions")
        connection.execute(
            "UPDATE wallets SET balance = ? WHERE user_id = ?",
            (50000, "CUSTOMER001"),
        )
        connection.execute(
            "UPDATE wallets SET balance = ? WHERE user_id = ?",
            (50000, "CUSTOMER002"),
        )
        connection.execute(
            "UPDATE wallets SET balance = ? WHERE user_id = ?",
            (10000, "MERCHANT001"),
        )
        connection.commit()


def process_demo_far_payment(sender_id, receiver_id, amount_paise, transaction_id):
    """Atomically settle one simulation-only remote payment, idempotently."""
    if (not isinstance(sender_id, str) or not isinstance(receiver_id, str)
            or sender_id == receiver_id or type(amount_paise) is not int
            or amount_paise <= 0 or amount_paise > MAX_TRANSACTION_PAISE
            or not isinstance(transaction_id, str) or not transaction_id):
        return {"status": "error", "message": "Invalid remote payment details."}

    with closing(get_connection()) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT sender_id, receiver_id, amount, status FROM transactions WHERE transaction_id = ?",
                (transaction_id,),
            ).fetchone()
            if existing:
                if (existing["sender_id"] != sender_id
                        or existing["receiver_id"] != receiver_id
                        or int(existing["amount"]) != amount_paise
                        or existing["status"] != "far_payment_delivered_simulation"):
                    connection.rollback()
                    return {"status": "error", "message": "Payment reference was already used."}
                sender = connection.execute("SELECT balance FROM wallets WHERE user_id = ?", (sender_id,)).fetchone()
                receiver = connection.execute("SELECT balance FROM wallets WHERE user_id = ?", (receiver_id,)).fetchone()
                connection.commit()
                return {
                    "status": "success", "duplicate": True,
                    "sender_balance_paise": int(sender["balance"]),
                    "receiver_balance_paise": int(receiver["balance"]),
                }

            sender = connection.execute("SELECT balance FROM wallets WHERE user_id = ?", (sender_id,)).fetchone()
            receiver = connection.execute("SELECT balance FROM wallets WHERE user_id = ?", (receiver_id,)).fetchone()
            if sender is None or receiver is None:
                connection.rollback()
                return {"status": "error", "message": "NetBridge recipient was not found."}
            sender_balance = int(sender["balance"])
            receiver_balance = int(receiver["balance"])
            if sender_balance < amount_paise:
                connection.rollback()
                return {"status": "error", "message": "Insufficient demo wallet balance."}
            if receiver_balance + amount_paise > MAX_WALLET_BALANCE_PAISE:
                connection.rollback()
                return {"status": "error", "message": "Recipient demo wallet balance limit would be exceeded."}

            connection.execute("UPDATE wallets SET balance = balance - ? WHERE user_id = ?", (amount_paise, sender_id))
            connection.execute("UPDATE wallets SET balance = balance + ? WHERE user_id = ?", (amount_paise, receiver_id))
            connection.execute(
                "INSERT INTO transactions (transaction_id, sender_id, receiver_id, amount, status) VALUES (?, ?, ?, ?, ?)",
                (transaction_id, sender_id, receiver_id, amount_paise, "far_payment_delivered_simulation"),
            )
            connection.commit()
            return {
                "status": "success", "duplicate": False,
                "sender_balance_paise": sender_balance - amount_paise,
                "receiver_balance_paise": receiver_balance + amount_paise,
            }
        except Exception:
            connection.rollback()
            raise


# ============================================================
# WALLET OPERATIONS
# ============================================================

def get_wallet(user_id):
    with closing(get_connection()) as connection:
        row = connection.execute("""
            SELECT user_id, name, balance
            FROM wallets
            WHERE user_id = ?
        """, (user_id,)).fetchone()

        return dict(row) if row else None


def verify_wallet_pin(user_id, pin):
    with closing(get_connection()) as connection:
        row = connection.execute("""
            SELECT pin_hash
            FROM wallets
            WHERE user_id = ?
        """, (user_id,)).fetchone()

        if row is None:
            return False

        return verify_pin(pin, row["pin_hash"])


def get_wallet_balance(user_id):
    wallet = get_wallet(user_id)

    if wallet is None:
        return None

    return wallet["balance"]


# ============================================================
# TRUSTED DEVICE OPERATIONS
# ============================================================

def register_trusted_device(
    device_id,
    owner_user_id,
    public_key,
    device_name="Unnamed device",
    approved=False
):
    """
    Register a device only after explicit user approval.

    The caller must verify that device_id is the SHA-256
    fingerprint of the supplied public key.
    """

    if approved is not True:
        return {
            "status": "error",
            "message": "Explicit device approval is required."
        }

    if not all([
        device_id,
        owner_user_id,
        public_key,
        device_name
    ]):
        return {
            "status": "error",
            "message": "All device details are required."
        }

    with closing(get_connection()) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")

            existing = connection.execute("""
                SELECT status, owner_user_id, public_key
                FROM trusted_devices
                WHERE device_id = ?
            """, (device_id,)).fetchone()

            if existing:
                if existing["status"] == "revoked":
                    connection.rollback()

                    return {
                        "status": "error",
                        "message": (
                            "Revoked devices cannot be "
                            "reactivated automatically."
                        )
                    }

                if (
                    existing["owner_user_id"] != owner_user_id
                    or existing["public_key"] != public_key
                ):
                    connection.rollback()

                    return {
                        "status": "error",
                        "message": (
                            "Device identity conflicts "
                            "with an existing record."
                        )
                    }

                connection.commit()

                return {
                    "status": "success",
                    "message": "Device is already registered.",
                    "device_id": device_id
                }

            connection.execute("""
                INSERT INTO trusted_devices (
                    device_id,
                    owner_user_id,
                    public_key,
                    device_name,
                    status
                )
                VALUES (?, ?, ?, ?, 'trusted')
            """, (
                device_id,
                owner_user_id,
                public_key,
                device_name
            ))

            connection.commit()

            return {
                "status": "success",
                "message": "Trusted device registered.",
                "device_id": device_id
            }

        except sqlite3.Error:
            connection.rollback()
            raise


def get_trusted_device(device_id):
    with closing(get_connection()) as connection:
        row = connection.execute("""
            SELECT
                device_id,
                owner_user_id,
                public_key,
                device_name,
                status,
                created_at,
                updated_at
            FROM trusted_devices
            WHERE device_id = ?
        """, (device_id,)).fetchone()

        return dict(row) if row else None


def is_device_trusted(device_id, owner_user_id=None):
    with closing(get_connection()) as connection:

        if owner_user_id is None:
            row = connection.execute("""
                SELECT 1
                FROM trusted_devices
                WHERE device_id = ?
                  AND status = 'trusted'
            """, (device_id,)).fetchone()

        else:
            row = connection.execute("""
                SELECT 1
                FROM trusted_devices
                WHERE device_id = ?
                  AND owner_user_id = ?
                  AND status = 'trusted'
            """, (
                device_id,
                owner_user_id
            )).fetchone()

        return row is not None


def list_trusted_devices(owner_user_id=None):
    with closing(get_connection()) as connection:

        if owner_user_id is None:
            rows = connection.execute("""
                SELECT *
                FROM trusted_devices
                ORDER BY created_at DESC
            """).fetchall()

        else:
            rows = connection.execute("""
                SELECT *
                FROM trusted_devices
                WHERE owner_user_id = ?
                ORDER BY created_at DESC
            """, (owner_user_id,)).fetchall()

        return [dict(row) for row in rows]


def revoke_trusted_device(device_id):
    with closing(get_connection()) as connection:
        cursor = connection.execute("""
            UPDATE trusted_devices
            SET status = 'revoked',
                updated_at = CURRENT_TIMESTAMP
            WHERE device_id = ?
              AND status = 'trusted'
        """, (device_id,))

        connection.commit()

        if cursor.rowcount == 0:
            return {
                "status": "error",
                "message": "Trusted device not found or already revoked."
            }

        return {
            "status": "success",
            "message": "Device revoked.",
            "device_id": device_id
        }


# ============================================================
# MERCHANT PAYMENT REQUEST OPERATIONS
# ============================================================

def create_payment_request(
    merchant_id,
    receiver_device_id,
    amount_paise,
    expiry_seconds=DEFAULT_PAYMENT_REQUEST_TTL,
    require_trusted_device=True,
):
    """
    Create a simulation-only merchant payment request.

    Amount is stored as integer paise.
    Trusted-device enforcement remains enabled by default for legacy
    callers. The single-QR simulation flow may explicitly disable it;
    that flow validates the QR against this server-stored request instead.
    """

    if not isinstance(merchant_id, str) or not merchant_id.strip():
        return {
            "status": "error",
            "message": "Invalid merchant ID."
        }

    if (
        not isinstance(receiver_device_id, str)
        or not receiver_device_id.strip()
    ):
        return {
            "status": "error",
            "message": "Invalid receiver device ID."
        }

    if type(amount_paise) is not int or amount_paise <= 0:
        return {
            "status": "error",
            "message": "Amount must be a positive integer in paise."
        }

    if amount_paise > MAX_TRANSACTION_PAISE:
        return {
            "status": "error",
            "message": "Payment exceeds the ₹5,000 limit."
        }

    if (
        type(expiry_seconds) is not int
        or not 1 <= expiry_seconds <= 300
    ):
        return {
            "status": "error",
            "message": "Expiry must be between 1 and 300 seconds."
        }

    now = int(time.time())
    expires_at = now + expiry_seconds
    request_id = secrets.token_urlsafe(24)

    with closing(get_connection()) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")

            merchant = connection.execute("""
                SELECT user_id
                FROM wallets
                WHERE user_id = ?
            """, (merchant_id,)).fetchone()

            if merchant is None:
                connection.rollback()

                return {
                    "status": "error",
                    "message": "Merchant wallet not found."
                }

            if require_trusted_device is True:
                device = connection.execute("""
                    SELECT device_id
                    FROM trusted_devices
                    WHERE device_id = ?
                      AND owner_user_id = ?
                      AND status = 'trusted'
                """, (
                    receiver_device_id,
                    merchant_id
                )).fetchone()

                if device is None:
                    connection.rollback()
                    return {
                        "status": "error",
                        "message": (
                            "Merchant device is not trusted "
                            "for this merchant."
                        )
                    }

            connection.execute("""
                INSERT INTO payment_requests (
                    request_id,
                    merchant_id,
                    receiver_device_id,
                    amount_paise,
                    currency,
                    status,
                    created_at,
                    expires_at
                )
                VALUES (?, ?, ?, ?, 'INR', 'pending', ?, ?)
            """, (
                request_id,
                merchant_id,
                receiver_device_id,
                amount_paise,
                now,
                expires_at
            ))

            connection.commit()

            return {
                "status": "success",
                "request_id": request_id,
                "merchant_id": merchant_id,
                "receiver_device_id": receiver_device_id,
                "amount_paise": amount_paise,
                "currency": "INR",
                "created_at": now,
                "expires_at": expires_at,
                "payment_status": "pending",
                "mode": "simulation_only"
            }

        except sqlite3.Error:
            connection.rollback()
            raise


def get_payment_request(request_id):
    """
    Retrieve a payment request.

    Expired pending requests are marked expired.
    """

    if not isinstance(request_id, str) or not request_id.strip():
        return None

    with closing(get_connection()) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute("""
                SELECT *
                FROM payment_requests
                WHERE request_id = ?
            """, (request_id,)).fetchone()

            if row is None:
                connection.commit()
                return None

            payment_request = dict(row)

            if (
                payment_request["status"] == "pending"
                and payment_request["expires_at"] <= int(time.time())
            ):
                connection.execute("""
                    UPDATE payment_requests
                    SET status = 'expired'
                    WHERE request_id = ?
                      AND status = 'pending'
                """, (request_id,))

                payment_request["status"] = "expired"

            connection.commit()

            return payment_request

        except sqlite3.Error:
            connection.rollback()
            raise


def list_payment_requests(merchant_id, limit=50):
    """Return recent payment requests belonging to one merchant."""

    if not isinstance(merchant_id, str) or not merchant_id.strip():
        return []

    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500.")

    now = int(time.time())

    with closing(get_connection()) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")

            connection.execute("""
                UPDATE payment_requests
                SET status = 'expired'
                WHERE merchant_id = ?
                  AND status = 'pending'
                  AND expires_at <= ?
            """, (merchant_id, now))

            rows = connection.execute("""
                SELECT *
                FROM payment_requests
                WHERE merchant_id = ?
                ORDER BY created_at DESC
                LIMIT ?
            """, (
                merchant_id,
                limit
            )).fetchall()

            connection.commit()

            return [dict(row) for row in rows]

        except sqlite3.Error:
            connection.rollback()
            raise


def update_payment_request_status(
    request_id,
    new_status,
    transaction_id=None
):
    """
    Cancel a pending request or mark it processed.

    Processing should normally happen inside the same database
    transaction as the wallet transfer, using process_wallet_transfer.
    """

    if new_status not in {"processed", "cancelled"}:
        return {
            "status": "error",
            "message": "Invalid payment-request status."
        }

    if new_status == "processed" and not transaction_id:
        return {
            "status": "error",
            "message": "Transaction ID is required."
        }

    with closing(get_connection()) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute("""
                SELECT status, expires_at
                FROM payment_requests
                WHERE request_id = ?
            """, (request_id,)).fetchone()

            if row is None:
                connection.rollback()

                return {
                    "status": "error",
                    "message": "Payment request not found."
                }

            if row["status"] != "pending":
                connection.rollback()

                return {
                    "status": "error",
                    "message": (
                        "Payment request is not pending."
                    )
                }

            now = int(time.time())

            if row["expires_at"] <= now:
                connection.execute("""
                    UPDATE payment_requests
                    SET status = 'expired'
                    WHERE request_id = ?
                      AND status = 'pending'
                """, (request_id,))

                connection.commit()

                return {
                    "status": "error",
                    "message": "Payment request has expired."
                }

            connection.execute("""
                UPDATE payment_requests
                SET status = ?,
                    transaction_id = ?
                WHERE request_id = ?
                  AND status = 'pending'
            """, (
                new_status,
                transaction_id,
                request_id
            ))

            connection.commit()

            return {
                "status": "success",
                "request_id": request_id,
                "payment_status": new_status
            }

        except sqlite3.Error:
            connection.rollback()
            raise


def record_offline_qr_receipt(receipt, request_id):
    """Consume a pending request and record its scanned receipt atomically."""
    required = {
        "receipt_id", "request_id", "customer_user_id", "merchant_user_id",
        "merchant_device_id", "amount_paise", "currency", "created_at",
    }
    if not isinstance(receipt, dict) or not required.issubset(receipt):
        return {"status": "error", "message": "Receipt details are incomplete."}
    if receipt.get("request_id") != request_id:
        return {"status": "error", "message": "Receipt request ID does not match."}
    if type(receipt.get("amount_paise")) is not int or not 1 <= receipt["amount_paise"] <= 500000:
        return {"status": "error", "message": "Invalid receipt amount."}
    if type(receipt.get("created_at")) is not int:
        return {"status": "error", "message": "Invalid receipt timestamp."}

    now = int(time.time())
    with closing(get_connection()) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM payment_requests WHERE request_id = ?",
                (request_id,),
            ).fetchone()
            if row is None or row["status"] != "pending" or row["expires_at"] <= now:
                connection.rollback()
                return {"status": "error", "message": "Payment request is no longer pending."}
            if (
                row["merchant_id"] != receipt["merchant_user_id"]
                or row["receiver_device_id"] != receipt["merchant_device_id"]
                or row["amount_paise"] != receipt["amount_paise"]
                or row["currency"] != receipt["currency"]
            ):
                connection.rollback()
                return {"status": "error", "message": "Receipt does not match the stored payment request."}

            connection.execute("""
                INSERT INTO offline_qr_receipts (
                    receipt_id, request_id, customer_user_id,
                    merchant_user_id, merchant_device_id, amount_paise,
                    currency, payment_status, settlement_status,
                    receipt_created_at, received_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                receipt["receipt_id"], request_id,
                receipt["customer_user_id"], receipt["merchant_user_id"],
                receipt["merchant_device_id"], receipt["amount_paise"],
                receipt["currency"], "accepted_for_simulation_review",
                "pending_reconciliation", receipt["created_at"], now,
            ))
            updated = connection.execute("""
                UPDATE payment_requests
                SET status = 'processed', transaction_id = NULL
                WHERE request_id = ? AND status = 'pending'
            """, (request_id,))
            if updated.rowcount != 1:
                connection.rollback()
                return {"status": "error", "message": "Payment request was already consumed."}
            connection.commit()
            return {"status": "success", "receipt_id": receipt["receipt_id"], "received_at": now}
        except sqlite3.IntegrityError as exc:
            connection.rollback()
            return {"status": "error", "message": "Receipt or payment request was already recorded."}
        except sqlite3.Error:
            connection.rollback()
            raise


def list_offline_qr_receipts(user_id, limit=100):
    """List accepted two-QR simulation receipts for either wallet."""
    if not isinstance(user_id, str) or not user_id.strip():
        return []
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500.")
    with closing(get_connection()) as connection:
        rows = connection.execute("""
            SELECT receipt_id, request_id, customer_user_id,
                   merchant_user_id, merchant_device_id, amount_paise,
                   currency, payment_status, settlement_status,
                   receipt_created_at, received_at
            FROM offline_qr_receipts
            WHERE customer_user_id = ? OR merchant_user_id = ?
            ORDER BY received_at DESC
            LIMIT ?
        """, (user_id, user_id, limit)).fetchall()
        return [dict(row) for row in rows]


# ============================================================
# ATOMIC WALLET TRANSFERS
# ============================================================

# ============================================================
# ATOMIC WALLET TRANSFERS WITH TOTP AUTHORIZATION
# ============================================================

def process_wallet_transfer(
    transaction_id,
    sender_id,
    receiver_id,
    amount_paise,
    sender_device_id,
    receiver_device_id,
    signature,
    digest,
    signature_verified=False,
    nonce=None,
    payment_request_id=None,
    totp_otp=None
):
    """
    Execute a simulation-only wallet transfer atomically.

    Requirements:
    - Cryptographic signature must already be verified.
    - Sender and receiver devices must be trusted.
    - Sender must have enabled TOTP authentication.
    - A valid, unused TOTP code is required.
    - TOTP consumption and payment commit occur together.
    - QR payment requests are validated and consumed atomically.
    """

    if signature_verified is not True:
        return {
            "status": "rejected",
            "message": "Transaction signature has not been verified."
        }

    if not all([
        transaction_id,
        sender_id,
        receiver_id,
        sender_device_id,
        receiver_device_id,
        signature,
        digest
    ]):
        return {
            "status": "rejected",
            "message": "Required transaction fields are missing."
        }

    if not isinstance(totp_otp, str) or not (
        len(totp_otp) == 6 and totp_otp.isdigit()
    ):
        return {
            "status": "rejected",
            "message": "A valid 6-digit authenticator code is required."
        }

    if nonce is not None and (
        not isinstance(nonce, str) or not nonce.strip()
    ):
        return {
            "status": "rejected",
            "message": "Invalid transaction nonce."
        }

    if sender_id == receiver_id:
        return {
            "status": "rejected",
            "message": "Sender and receiver must be different."
        }

    if sender_device_id == receiver_device_id:
        return {
            "status": "rejected",
            "message": "Sender and receiver devices must be different."
        }

    if type(amount_paise) is not int or amount_paise <= 0:
        return {
            "status": "rejected",
            "message": "Amount must be a positive integer in paise."
        }

    if amount_paise > MAX_TRANSACTION_PAISE:
        return {
            "status": "rejected",
            "message": "Transaction exceeds the ₹5,000 limit."
        }

    if payment_request_id is not None and (
        not isinstance(payment_request_id, str)
        or not payment_request_id.strip()
    ):
        return {
            "status": "rejected",
            "message": "Invalid payment request ID."
        }

    # Use the existing standard-library TOTP implementation.
    from authenticator.totp import verify_otp

    with closing(get_connection()) as connection:
        try:
            # Serialize concurrent payment attempts.
            connection.execute("BEGIN IMMEDIATE")

            # ------------------------------------------------
            # TOTP ENROLLMENT AND LOCKOUT CHECK
            # ------------------------------------------------

            totp_record = connection.execute("""
                SELECT
                    secret,
                    enabled,
                    last_used_counter,
                    failed_attempts,
                    locked_until
                FROM wallet_totp
                WHERE user_id = ?
            """, (sender_id,)).fetchone()

            if (
                totp_record is None
                or totp_record["enabled"] != 1
                or not totp_record["secret"]
            ):
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Authenticator setup is required "
                        "before making payments."
                    )
                }

            now = int(time.time())

            if totp_record["locked_until"] > now:
                retry_after = totp_record["locked_until"] - now
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Authenticator is temporarily locked. "
                        f"Try again in {retry_after} seconds."
                    )
                }

            # ------------------------------------------------
            # VERIFY TOTP
            # ------------------------------------------------

            matched_counter = verify_otp(
                totp_record["secret"],
                totp_otp,
                timestamp=now,
                window=1
            )

            if matched_counter is None:
                failed_attempts = (
                    totp_record["failed_attempts"] + 1
                )

                lockout_until = (
                    now + 300
                    if failed_attempts >= 5
                    else 0
                )

                connection.execute("""
                    UPDATE wallet_totp
                    SET failed_attempts = ?,
                        locked_until = ?,
                        updated_at = ?
                    WHERE user_id = ?
                """, (
                    failed_attempts,
                    lockout_until,
                    now,
                    sender_id
                ))

                # Persist failed-attempt tracking even though
                # the payment itself is rejected.
                connection.commit()

                return {
                    "status": "rejected",
                    "message": (
                        "Invalid authenticator code."
                        if lockout_until == 0
                        else (
                            "Too many invalid authenticator codes. "
                            "Payments are locked for 5 minutes."
                        )
                    )
                }

            # Reject codes from a time-step already used.
            if matched_counter <= totp_record["last_used_counter"]:
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "This authenticator code has already "
                        "been used. Wait for a new code."
                    )
                }

            # ------------------------------------------------
            # DUPLICATE TRANSACTION CHECK
            # ------------------------------------------------

            existing = connection.execute("""
                SELECT digest
                FROM transactions
                WHERE transaction_id = ?
            """, (transaction_id,)).fetchone()

            if existing:
                connection.rollback()

                if existing["digest"] != digest:
                    return {
                        "status": "rejected",
                        "message": (
                            "Transaction ID reused with "
                            "different data."
                        )
                    }

                return {
                    "status": "rejected",
                    "message": "Duplicate transaction detected."
                }

            # ------------------------------------------------
            # NONCE REUSE CHECK
            # ------------------------------------------------

            if nonce is not None:
                existing_nonce = connection.execute("""
                    SELECT transaction_id
                    FROM transactions
                    WHERE nonce = ?
                    LIMIT 1
                """, (nonce,)).fetchone()

                if existing_nonce:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Transaction nonce has "
                            "already been used."
                        )
                    }

            # ------------------------------------------------
            # TRUSTED DEVICE CHECKS
            # ------------------------------------------------

            sender_device = connection.execute("""
                SELECT owner_user_id, status
                FROM trusted_devices
                WHERE device_id = ?
            """, (sender_device_id,)).fetchone()

            receiver_device = connection.execute("""
                SELECT owner_user_id, status
                FROM trusted_devices
                WHERE device_id = ?
            """, (receiver_device_id,)).fetchone()

            if (
                not sender_device
                or sender_device["status"] != "trusted"
                or sender_device["owner_user_id"] != sender_id
            ):
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Sender device is not trusted "
                        "for this wallet."
                    )
                }

            if (
                not receiver_device
                or receiver_device["status"] != "trusted"
                or receiver_device["owner_user_id"] != receiver_id
            ):
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Receiver device is not trusted "
                        "for this wallet."
                    )
                }

            # ------------------------------------------------
            # PAYMENT REQUEST VALIDATION
            # ------------------------------------------------

            if payment_request_id is not None:
                payment_request = connection.execute("""
                    SELECT
                        request_id,
                        merchant_id,
                        receiver_device_id,
                        amount_paise,
                        currency,
                        status,
                        expires_at
                    FROM payment_requests
                    WHERE request_id = ?
                """, (payment_request_id,)).fetchone()

                if payment_request is None:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": "Payment request not found."
                    }

                if payment_request["status"] != "pending":
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Payment request is no longer pending."
                        )
                    }

                if payment_request["expires_at"] <= int(time.time()):
                    connection.execute("""
                        UPDATE payment_requests
                        SET status = 'expired'
                        WHERE request_id = ?
                          AND status = 'pending'
                    """, (payment_request_id,))

                    connection.commit()

                    return {
                        "status": "rejected",
                        "message": "Payment request has expired."
                    }

                if payment_request["currency"] != "INR":
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": "Unsupported payment currency."
                    }

                if payment_request["merchant_id"] != receiver_id:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Payment request does not belong "
                            "to the receiver wallet."
                        )
                    }

                if (
                    payment_request["receiver_device_id"]
                    != receiver_device_id
                ):
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Receiver device does not match "
                            "the payment request."
                        )
                    }

                if payment_request["amount_paise"] != amount_paise:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Transaction amount does not match "
                            "the payment request."
                        )
                    }

            # ------------------------------------------------
            # WALLET VALIDATION
            # ------------------------------------------------

            sender = connection.execute("""
                SELECT balance
                FROM wallets
                WHERE user_id = ?
            """, (sender_id,)).fetchone()

            receiver = connection.execute("""
                SELECT balance
                FROM wallets
                WHERE user_id = ?
            """, (receiver_id,)).fetchone()

            if sender is None or receiver is None:
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Sender or receiver wallet "
                        "does not exist."
                    )
                }

            if sender["balance"] < amount_paise:
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": "Insufficient balance."
                }

            if (
                receiver["balance"] + amount_paise
                > MAX_WALLET_BALANCE_PAISE
            ):
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Receiver wallet balance limit "
                        "would be exceeded."
                    )
                }

            # ------------------------------------------------
            # CONSUME OTP INSIDE THE PAYMENT TRANSACTION
            # ------------------------------------------------

            cursor = connection.execute("""
                UPDATE wallet_totp
                SET last_used_counter = ?,
                    failed_attempts = 0,
                    locked_until = 0,
                    updated_at = ?
                WHERE user_id = ?
                  AND enabled = 1
                  AND last_used_counter < ?
            """, (
                matched_counter,
                int(time.time()),
                sender_id,
                matched_counter
            ))

            if cursor.rowcount != 1:
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Authenticator code could not be "
                        "consumed safely. Try a new code."
                    )
                }

            # ------------------------------------------------
            # DEBIT SENDER
            # ------------------------------------------------

            connection.execute("""
                UPDATE wallets
                SET balance = balance - ?
                WHERE user_id = ?
                  AND balance >= ?
            """, (
                amount_paise,
                sender_id,
                amount_paise
            ))

            changed = connection.execute(
                "SELECT changes()"
            ).fetchone()[0]

            if changed != 1:
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Sender balance changed; "
                        "transaction cancelled."
                    )
                }

            # ------------------------------------------------
            # CREDIT RECEIVER
            # ------------------------------------------------

            connection.execute("""
                UPDATE wallets
                SET balance = balance + ?
                WHERE user_id = ?
            """, (
                amount_paise,
                receiver_id
            ))

            # ------------------------------------------------
            # RECORD TRANSACTION
            # ------------------------------------------------

            connection.execute("""
                INSERT INTO transactions (
                    transaction_id,
                    sender_id,
                    receiver_id,
                    amount,
                    status,
                    sender_device_id,
                    receiver_device_id,
                    signature,
                    digest,
                    nonce,
                    processed_at
                )
                VALUES (
                    ?, ?, ?, ?, 'processed',
                    ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
                )
            """, (
                transaction_id,
                sender_id,
                receiver_id,
                amount_paise,
                sender_device_id,
                receiver_device_id,
                signature,
                digest,
                nonce
            ))

            # ------------------------------------------------
            # MARK PAYMENT REQUEST PROCESSED
            # ------------------------------------------------

            if payment_request_id is not None:
                cursor = connection.execute("""
                    UPDATE payment_requests
                    SET status = 'processed',
                        transaction_id = ?
                    WHERE request_id = ?
                      AND status = 'pending'
                      AND expires_at > ?
                """, (
                    transaction_id,
                    payment_request_id,
                    int(time.time())
                ))

                if cursor.rowcount != 1:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Payment request could not be "
                            "consumed. Transaction cancelled."
                        )
                    }

            # ------------------------------------------------
            # READ RESULTING BALANCES
            # ------------------------------------------------

            sender_balance = connection.execute("""
                SELECT balance
                FROM wallets
                WHERE user_id = ?
            """, (sender_id,)).fetchone()["balance"]

            receiver_balance = connection.execute("""
                SELECT balance
                FROM wallets
                WHERE user_id = ?
            """, (receiver_id,)).fetchone()["balance"]

            # OTP consumption, wallet transfer, transaction
            # record, and payment-request update commit together.
            connection.commit()

            return {
                "status": "success",
                "message": "Simulated transfer completed.",
                "transaction_id": transaction_id,
                "payment_request_id": payment_request_id,
                "amount_paise": amount_paise,
                "sender_balance_paise": sender_balance,
                "receiver_balance_paise": receiver_balance,
                "mode": "simulation_only"
            }

        except sqlite3.IntegrityError:
            connection.rollback()

            return {
                "status": "rejected",
                "message": (
                    "Database constraint rejected "
                    "the transaction."
                )
            }

        except sqlite3.Error:
            connection.rollback()
            raise
            # ------------------------------------------------
            # NONCE REUSE CHECK
            # ------------------------------------------------

            if nonce is not None:
                existing_nonce = connection.execute("""
                    SELECT transaction_id
                    FROM transactions
                    WHERE nonce = ?
                    LIMIT 1
                """, (nonce,)).fetchone()

                if existing_nonce:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Transaction nonce has "
                            "already been used."
                        )
                    }

            # ------------------------------------------------
            # TRUSTED DEVICE CHECKS
            # ------------------------------------------------

            sender_device = connection.execute("""
                SELECT owner_user_id, status
                FROM trusted_devices
                WHERE device_id = ?
            """, (sender_device_id,)).fetchone()

            receiver_device = connection.execute("""
                SELECT owner_user_id, status
                FROM trusted_devices
                WHERE device_id = ?
            """, (receiver_device_id,)).fetchone()

            if (
                not sender_device
                or sender_device["status"] != "trusted"
                or sender_device["owner_user_id"] != sender_id
            ):
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Sender device is not trusted "
                        "for this wallet."
                    )
                }

            if (
                not receiver_device
                or receiver_device["status"] != "trusted"
                or receiver_device["owner_user_id"] != receiver_id
            ):
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Receiver device is not trusted "
                        "for this wallet."
                    )
                }

            # ------------------------------------------------
            # PAYMENT REQUEST VALIDATION
            # ------------------------------------------------

            if payment_request_id is not None:
                payment_request = connection.execute("""
                    SELECT
                        request_id,
                        merchant_id,
                        receiver_device_id,
                        amount_paise,
                        currency,
                        status,
                        expires_at
                    FROM payment_requests
                    WHERE request_id = ?
                """, (payment_request_id,)).fetchone()

                if payment_request is None:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": "Payment request not found."
                    }

                if payment_request["status"] != "pending":
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Payment request is no longer pending."
                        )
                    }

                if payment_request["expires_at"] <= int(time.time()):
                    connection.execute("""
                        UPDATE payment_requests
                        SET status = 'expired'
                        WHERE request_id = ?
                          AND status = 'pending'
                    """, (payment_request_id,))

                    connection.commit()

                    return {
                        "status": "rejected",
                        "message": "Payment request has expired."
                    }

                if payment_request["currency"] != "INR":
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": "Unsupported payment currency."
                    }

                if payment_request["merchant_id"] != receiver_id:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Payment request does not belong "
                            "to the receiver wallet."
                        )
                    }

                if (
                    payment_request["receiver_device_id"]
                    != receiver_device_id
                ):
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Receiver device does not match "
                            "the payment request."
                        )
                    }

                if payment_request["amount_paise"] != amount_paise:
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Transaction amount does not match "
                            "the payment request."
                        )
                    }

            # ------------------------------------------------
            # WALLET VALIDATION
            # ------------------------------------------------

            sender = connection.execute("""
                SELECT balance
                FROM wallets
                WHERE user_id = ?
            """, (sender_id,)).fetchone()

            receiver = connection.execute("""
                SELECT balance
                FROM wallets
                WHERE user_id = ?
            """, (receiver_id,)).fetchone()

            if sender is None or receiver is None:
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Sender or receiver wallet "
                        "does not exist."
                    )
                }

            if sender["balance"] < amount_paise:
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": "Insufficient balance."
                }

            if (
                receiver["balance"] + amount_paise
                > MAX_WALLET_BALANCE_PAISE
            ):
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Receiver wallet balance limit "
                        "would be exceeded."
                    )
                }

            # ------------------------------------------------
            # DEBIT SENDER
            # ------------------------------------------------

            connection.execute("""
                UPDATE wallets
                SET balance = balance - ?
                WHERE user_id = ?
                  AND balance >= ?
            """, (
                amount_paise,
                sender_id,
                amount_paise
            ))

            changed = connection.execute(
                "SELECT changes()"
            ).fetchone()[0]

            if changed != 1:
                connection.rollback()

                return {
                    "status": "rejected",
                    "message": (
                        "Sender balance changed; "
                        "transaction cancelled."
                    )
                }

            # ------------------------------------------------
            # CREDIT RECEIVER
            # ------------------------------------------------

            connection.execute("""
                UPDATE wallets
                SET balance = balance + ?
                WHERE user_id = ?
            """, (
                amount_paise,
                receiver_id
            ))

            # ------------------------------------------------
            # RECORD TRANSACTION
            # ------------------------------------------------

            connection.execute("""
                INSERT INTO transactions (
                    transaction_id,
                    sender_id,
                    receiver_id,
                    amount,
                    status,
                    sender_device_id,
                    receiver_device_id,
                    signature,
                    digest,
                    nonce,
                    processed_at
                )
                VALUES (
                    ?, ?, ?, ?, 'processed',
                    ?, ?, ?, ?, ?, CURRENT_TIMESTAMP
                )
            """, (
                transaction_id,
                sender_id,
                receiver_id,
                amount_paise,
                sender_device_id,
                receiver_device_id,
                signature,
                digest,
                nonce
            ))

            # ------------------------------------------------
            # MARK PAYMENT REQUEST PROCESSED
            # ------------------------------------------------

            if payment_request_id is not None:
                cursor = connection.execute("""
                    UPDATE payment_requests
                    SET status = 'processed',
                        transaction_id = ?
                    WHERE request_id = ?
                      AND status = 'pending'
                      AND expires_at > ?
                """, (
                    transaction_id,
                    payment_request_id,
                    int(time.time())
                ))

                if cursor.rowcount != 1:
                    # Rolls back the debit, credit and transaction
                    # record if the request cannot be consumed.
                    connection.rollback()

                    return {
                        "status": "rejected",
                        "message": (
                            "Payment request could not be "
                            "consumed. Transaction cancelled."
                        )
                    }

            # ------------------------------------------------
            # READ RESULTING BALANCES
            # ------------------------------------------------

            sender_balance = connection.execute("""
                SELECT balance
                FROM wallets
                WHERE user_id = ?
            """, (sender_id,)).fetchone()["balance"]

            receiver_balance = connection.execute("""
                SELECT balance
                FROM wallets
                WHERE user_id = ?
            """, (receiver_id,)).fetchone()["balance"]

            # Commit all wallet and request changes together.
            connection.commit()

            return {
                "status": "success",
                "message": "Simulated transfer completed.",
                "transaction_id": transaction_id,
                "payment_request_id": payment_request_id,
                "amount_paise": amount_paise,
                "sender_balance_paise": sender_balance,
                "receiver_balance_paise": receiver_balance,
                "mode": "simulation_only"
            }

        except sqlite3.IntegrityError:
            connection.rollback()

            return {
                "status": "rejected",
                "message": (
                    "Database constraint rejected "
                    "the transaction."
                )
            }

        except sqlite3.Error:
            connection.rollback()
            raise


# ============================================================
# TRANSACTION HISTORY
# ============================================================

def get_transaction(transaction_id):
    with closing(get_connection()) as connection:
        row = connection.execute("""
            SELECT *
            FROM transactions
            WHERE transaction_id = ?
        """, (transaction_id,)).fetchone()

        return dict(row) if row else None


def get_transaction_history(user_id, limit=50):
    if type(limit) is not int or not 1 <= limit <= 500:
        raise ValueError("Limit must be between 1 and 500.")

    with closing(get_connection()) as connection:
        rows = connection.execute("""
            SELECT
                transaction_id,
                sender_id,
                receiver_id,
                amount,
                status,
                created_at,
                sender_device_id,
                receiver_device_id,
                digest,
                processed_at
            FROM transactions
            WHERE sender_id = ? OR receiver_id = ?
            ORDER BY created_at DESC
            LIMIT ?
        """, (
            user_id,
            user_id,
            limit
        )).fetchall()

        return [dict(row) for row in rows]


# ============================================================
# INITIALIZE WHEN RUN DIRECTLY
# ============================================================

if __name__ == "__main__":
    initialize_database()

    print("NetBridge database initialized.")
    print("Database path:", DATABASE)
    print("Demo Customer PIN: 1234")
    print("Demo Merchant PIN: 5678")
    print("Demo balances are stored in paise.")
    print("Payment request storage is available.")
    print("Real payments are disabled.")
