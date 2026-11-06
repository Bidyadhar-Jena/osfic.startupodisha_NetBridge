"""
NetBridge TOTP authentication module.

Compatible with Google Authenticator and other RFC 6238-compatible apps.
Uses the Python standard library.

Configuration:
- 6-digit OTP
- 30-second time step
- 20-byte random secret
- Base32 secret encoding

This module generates and verifies OTPs.
Persistent enrollment and replay prevention will be integrated
with the database in a later backend step.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time

from urllib.parse import quote, urlencode


# ============================================================
# TOTP CONFIGURATION
# ============================================================

OTP_DIGITS = 6
OTP_INTERVAL_SECONDS = 30
SECRET_BYTES = 20

DEFAULT_ISSUER = "NetBridge"


# ============================================================
# SECRET GENERATION
# ============================================================

def generate_secret():
    """
    Generate a cryptographically secure Base32 TOTP secret.

    Store this secret securely during enrollment.
    Never expose it through ordinary payment API responses.
    """
    random_bytes = secrets.token_bytes(SECRET_BYTES)

    return base64.b32encode(
        random_bytes
    ).decode("ascii").rstrip("=")


def _decode_secret(secret):
    """Decode and validate a Base32 TOTP secret."""
    if not isinstance(secret, str) or not secret:
        raise ValueError("A valid TOTP secret is required.")

    normalized = secret.strip().replace(" ", "").upper()

    try:
        padding = "=" * ((8 - len(normalized) % 8) % 8)

        decoded = base64.b32decode(
            normalized + padding,
            casefold=False,
        )

    except Exception as error:
        raise ValueError("The TOTP secret is invalid.") from error

    if len(decoded) < 16:
        raise ValueError("The TOTP secret is too short.")

    return decoded


# ============================================================
# OTP GENERATION
# ============================================================

def generate_otp(secret, timestamp=None):
    """
    Generate the six-digit TOTP for the specified time.

    timestamp:
        Optional Unix timestamp for deterministic testing.
        If omitted, the current system time is used.
    """
    key = _decode_secret(secret)

    if timestamp is None:
        timestamp = time.time()

    if not isinstance(timestamp, (int, float)):
        raise ValueError("Timestamp must be numeric.")

    if timestamp < 0:
        raise ValueError("Timestamp cannot be negative.")

    counter = int(timestamp) // OTP_INTERVAL_SECONDS

    message = struct.pack(">Q", counter)

    digest = hmac.new(
        key,
        message,
        hashlib.sha1,
    ).digest()

    offset = digest[-1] & 0x0F

    truncated = struct.unpack(
        ">I",
        digest[offset:offset + 4],
    )[0] & 0x7FFFFFFF

    otp = truncated % (10 ** OTP_DIGITS)

    return f"{otp:0{OTP_DIGITS}d}"


# ============================================================
# OTP VERIFICATION
# ============================================================

def verify_otp(secret, otp, timestamp=None, window=1):
    """
    Verify a TOTP code.

    A window of 1 permits the previous, current, or next 30-second
    time step to account for small clock differences.

    Returns:
        The matched time-step counter on success.
        None on failure.

    IMPORTANT:
        This function does not prevent OTP reuse by itself.
        The caller must atomically record and reject previously
        accepted counters during payment authorization.
    """
    if not isinstance(otp, str):
        return None

    otp = otp.strip()

    if (
        len(otp) != OTP_DIGITS
        or not otp.isascii()
        or not otp.isdigit()
    ):
        return None

    if type(window) is not int or not 0 <= window <= 2:
        raise ValueError("Window must be an integer from 0 to 2.")

    if timestamp is None:
        timestamp = time.time()

    if not isinstance(timestamp, (int, float)) or timestamp < 0:
        return None

    current_counter = int(timestamp) // OTP_INTERVAL_SECONDS

    for offset in range(-window, window + 1):
        candidate_counter = current_counter + offset

        if candidate_counter < 0:
            continue

        expected = generate_otp(
            secret,
            timestamp=candidate_counter * OTP_INTERVAL_SECONDS,
        )

        if hmac.compare_digest(expected, otp):
            return candidate_counter

    return None


# ============================================================
# AUTHENTICATOR SETUP URI
# ============================================================

def get_provisioning_uri(
    secret,
    account_name,
    issuer=DEFAULT_ISSUER,
):
    """
    Create an otpauth:// URI for compatible authenticator apps.

    The URI contains the secret. Treat it as sensitive and only
    display it during the explicitly authorized enrollment process.
    """
    _decode_secret(secret)

    if not isinstance(account_name, str) or not account_name.strip():
        raise ValueError("A valid account name is required.")

    if not isinstance(issuer, str) or not issuer.strip():
        raise ValueError("A valid issuer is required.")

    account_name = account_name.strip()
    issuer = issuer.strip()

    label = quote(
        f"{issuer}:{account_name}",
        safe="",
    )

    parameters = urlencode({
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": OTP_DIGITS,
        "period": OTP_INTERVAL_SECONDS,
    })

    return f"otpauth://totp/{label}?{parameters}"