"""
NetBridge TOTP storage and enrollment.

Uses the existing NetBridge SQLite database.

Features:
- Wallet-specific TOTP enrollment
- Persistent enrollment
- Pending enrollment until OTP confirmation
- Failed-attempt lockout
- Replay protection using accepted TOTP time-step

Prototype warning:
TOTP secrets are stored in SQLite without encryption at rest.
Production deployments require authenticated encryption and
secure key management.
"""

import sqlite3
import time
from contextlib import closing

from database import get_connection
from authenticator.totp import generate_secret, verify_otp


# ============================================================
# SECURITY SETTINGS
# ============================================================

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_SECONDS = 300
OTP_WINDOW = 1


# ============================================================
# DATABASE SETUP
# ============================================================

def initialize_totp_storage():
    """Create the TOTP storage table if it does not exist."""

    with closing(get_connection()) as connection:

        connection.execute("""
            CREATE TABLE IF NOT EXISTS wallet_totp (
                user_id TEXT PRIMARY KEY,
                secret TEXT,
                pending_secret TEXT,

                enabled INTEGER NOT NULL DEFAULT 0
                    CHECK (enabled IN (0, 1)),

                last_used_counter INTEGER NOT NULL DEFAULT -1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL,

                FOREIGN KEY(user_id)
                    REFERENCES wallets(user_id)
                    ON DELETE CASCADE
            )
        """)

        connection.execute("""
            CREATE INDEX IF NOT EXISTS idx_wallet_totp_enabled
            ON wallet_totp(enabled)
        """)

        connection.commit()


def reset_totp_enrollments():
    """Delete saved Authenticator enrollments for a fresh app run."""
    initialize_totp_storage()
    with closing(get_connection()) as connection:
        connection.execute("DELETE FROM wallet_totp")
        connection.commit()


# ============================================================
# VALIDATION
# ============================================================

def _valid_user_id(user_id):
    return (
        isinstance(user_id, str)
        and bool(user_id.strip())
    )


def _wallet_exists(connection, user_id):

    row = connection.execute(
        """
        SELECT 1
        FROM wallets
        WHERE user_id = ?
        """,
        (user_id,),
    ).fetchone()

    return row is not None


# ============================================================
# ENROLLMENT
# ============================================================

def begin_totp_enrollment(user_id):
    """
    Begin enrollment.

    An already-enabled Authenticator is never overwritten.
    """

    if not _valid_user_id(user_id):
        raise ValueError("A valid wallet ID is required.")

    user_id = user_id.strip()
    now = int(time.time())

    initialize_totp_storage()

    with closing(get_connection()) as connection:

        try:
            connection.execute("BEGIN IMMEDIATE")

            if not _wallet_exists(connection, user_id):
                raise ValueError("Wallet not found.")

            existing = connection.execute(
                """
                SELECT enabled
                FROM wallet_totp
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            if existing and existing["enabled"]:
                raise ValueError(
                    "Authenticator is already enabled."
                )

            # Generate a secret only for a new pending enrollment.
            secret = generate_secret()

            connection.execute(
                """
                INSERT INTO wallet_totp (
                    user_id,
                    secret,
                    pending_secret,
                    enabled,
                    last_used_counter,
                    failed_attempts,
                    locked_until,
                    updated_at
                )
                VALUES (?, NULL, ?, 0, -1, 0, 0, ?)

                ON CONFLICT(user_id) DO UPDATE SET
                    pending_secret = excluded.pending_secret,
                    failed_attempts = 0,
                    locked_until = 0,
                    updated_at = excluded.updated_at
                """,
                (user_id, secret, now),
            )

            connection.commit()
            return secret

        except Exception:
            connection.rollback()
            raise


def confirm_totp_enrollment(user_id, otp):
    """Confirm and activate a pending enrollment."""

    if not _valid_user_id(user_id):
        return False

    user_id = user_id.strip()
    now = int(time.time())

    initialize_totp_storage()

    with closing(get_connection()) as connection:

        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT
                    pending_secret,
                    enabled,
                    failed_attempts,
                    locked_until
                FROM wallet_totp
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            if row is None or row["enabled"]:
                connection.rollback()
                return False

            if not row["pending_secret"]:
                connection.rollback()
                return False

            if row["locked_until"] > now:
                connection.rollback()
                return False

            matched_counter = verify_otp(
                row["pending_secret"],
                otp,
                window=OTP_WINDOW,
            )

            if matched_counter is None:
                _record_failure(connection, user_id, row, now)
                connection.commit()
                return False

            connection.execute(
                """
                UPDATE wallet_totp
                SET
                    secret = pending_secret,
                    pending_secret = NULL,
                    enabled = 1,
                    last_used_counter = ?,
                    failed_attempts = 0,
                    locked_until = 0,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (matched_counter, now, user_id),
            )

            connection.commit()
            return True

        except Exception:
            connection.rollback()
            raise


# ============================================================
# FAILED ATTEMPT PROTECTION
# ============================================================

def _record_failure(connection, user_id, row, now):

    attempts = row["failed_attempts"] + 1

    if attempts >= MAX_FAILED_ATTEMPTS:

        connection.execute(
            """
            UPDATE wallet_totp
            SET
                failed_attempts = 0,
                locked_until = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (now + LOCKOUT_SECONDS, now, user_id),
        )

    else:

        connection.execute(
            """
            UPDATE wallet_totp
            SET
                failed_attempts = ?,
                updated_at = ?
            WHERE user_id = ?
            """,
            (attempts, now, user_id),
        )


# ============================================================
# AUTHENTICATOR STATUS
# ============================================================

def is_totp_enabled(user_id):
    """
    Read persistent enrollment status from SQLite.

    This function does not generate a new secret or reset enrollment.
    """

    if not _valid_user_id(user_id):
        return False

    initialize_totp_storage()

    with closing(get_connection()) as connection:

        row = connection.execute(
            """
            SELECT enabled
            FROM wallet_totp
            WHERE user_id = ?
            """,
            (user_id.strip(),),
        ).fetchone()

        return bool(row and row["enabled"])


def get_totp_secret(user_id):
    """Return an enabled secret for a PIN and OTP authenticated setup flow."""
    if not _valid_user_id(user_id):
        return None
    initialize_totp_storage()
    with closing(get_connection()) as connection:
        row = connection.execute(
            "SELECT secret, enabled FROM wallet_totp WHERE user_id = ?",
            (user_id.strip(),),
        ).fetchone()
        if row is None or not row["enabled"] or not row["secret"]:
            return None
        return row["secret"]


# ============================================================
# PAYMENT OTP VERIFICATION
# ============================================================

def verify_and_consume_totp(user_id, otp):
    """
    Verify an enabled wallet's OTP and consume its time-step.

    The same time-step cannot authorize two payments.
    SQLite BEGIN IMMEDIATE prevents simultaneous reuse.
    """

    if not _valid_user_id(user_id):
        return False

    user_id = user_id.strip()
    now = int(time.time())

    initialize_totp_storage()

    with closing(get_connection()) as connection:

        try:
            connection.execute("BEGIN IMMEDIATE")

            row = connection.execute(
                """
                SELECT
                    secret,
                    enabled,
                    last_used_counter,
                    failed_attempts,
                    locked_until
                FROM wallet_totp
                WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()

            if (
                row is None
                or not row["enabled"]
                or not row["secret"]
            ):
                connection.rollback()
                return False

            if row["locked_until"] > now:
                connection.rollback()
                return False

            matched_counter = verify_otp(
                row["secret"],
                otp,
                window=OTP_WINDOW,
            )

            if matched_counter is None:

                _record_failure(
                    connection,
                    user_id,
                    row,
                    now,
                )

                connection.commit()
                return False

            if matched_counter <= row["last_used_counter"]:
                connection.rollback()
                return False

            connection.execute(
                """
                UPDATE wallet_totp
                SET
                    last_used_counter = ?,
                    failed_attempts = 0,
                    locked_until = 0,
                    updated_at = ?
                WHERE user_id = ?
                """,
                (matched_counter, now, user_id),
            )

            connection.commit()
            return True

        except Exception:
            connection.rollback()
            raise


def verify_totp_for_reconnect(user_id, otp):
    """Verify a current OTP for device reconnect without consuming its time-step.

    Reconnecting the local Authenticator cache is not a payment authorization.
    Failed attempts still use the normal lockout protection; only a successful
    payment may advance ``last_used_counter``.
    """
    if not _valid_user_id(user_id):
        return False

    user_id = user_id.strip()
    now = int(time.time())
    initialize_totp_storage()

    with closing(get_connection()) as connection:
        try:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT secret, enabled, failed_attempts, locked_until
                FROM wallet_totp WHERE user_id = ?
                """,
                (user_id,),
            ).fetchone()
            if row is None or not row["enabled"] or not row["secret"]:
                connection.rollback()
                return False
            if row["locked_until"] > now:
                connection.rollback()
                return False

            matched_counter = verify_otp(row["secret"], otp, window=OTP_WINDOW)
            if matched_counter is None:
                _record_failure(connection, user_id, row, now)
                connection.commit()
                return False

            connection.execute(
                """
                UPDATE wallet_totp
                SET failed_attempts = 0, locked_until = 0, updated_at = ?
                WHERE user_id = ?
                """,
                (now, user_id),
            )
            connection.commit()
            return True
        except Exception:
            connection.rollback()
            raise
