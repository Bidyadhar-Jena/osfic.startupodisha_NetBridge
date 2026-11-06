"""Validation helpers for NetBridge's QR-only simulated payment receipt.

This module validates receipt structure and binds it to the merchant's
payment request. It is NOT cryptographic proof of customer identity or OTP
verification. A QR payload can be copied or forged; use only for the clearly
labelled classroom simulation.
"""

import secrets
import time

from offline.offline_protocol import (
    CURRENCY,
    MAX_TRANSACTION_PAISE,
    PROTOCOL_VERSION,
    SIMULATION_MODE,
)

RECEIPT_TTL_SECONDS = 5 * 60


def create_payment_receipt(request, customer_user_id, approved=True, now=None):
    """Create a compact customer receipt to display as a QR code."""
    if not isinstance(request, dict):
        raise ValueError("Payment request is missing.")
    if approved is not True:
        raise ValueError("Customer has not approved this payment.")

    required = (
        "request_id", "merchant_user_id", "merchant_device_id",
        "amount_paise", "currency", "created_at", "expires_at", "nonce",
    )
    if any(key not in request for key in required):
        raise ValueError("Payment request is incomplete.")

    if not isinstance(customer_user_id, str) or not customer_user_id.strip():
        raise ValueError("Customer ID is required.")

    amount = request["amount_paise"]
    if type(amount) is not int or not 1 <= amount <= MAX_TRANSACTION_PAISE:
        raise ValueError("Invalid payment amount.")
    if request["currency"] != CURRENCY:
        raise ValueError("Unsupported currency.")

    current = int(time.time()) if now is None else now
    if type(current) is not int:
        raise ValueError("Invalid receipt timestamp.")
    if type(request["expires_at"]) is not int or request["expires_at"] <= current:
        raise ValueError("Payment request has expired.")

    return {
        "protocol": PROTOCOL_VERSION,
        "mode": SIMULATION_MODE,
        "receipt_id": secrets.token_hex(16),
        "request_id": request["request_id"],
        "request_nonce": request["nonce"],
        "customer_user_id": customer_user_id.strip(),
        "merchant_user_id": request["merchant_user_id"],
        "merchant_device_id": request["merchant_device_id"],
        "amount_paise": amount,
        "currency": CURRENCY,
        "approved": True,
        "created_at": current,
        "expires_at": min(request["expires_at"], current + RECEIPT_TTL_SECONDS),
    }


def validate_payment_receipt(receipt, request, now=None):
    """Validate a receipt against the exact request shown to the customer."""
    if not isinstance(receipt, dict) or not isinstance(request, dict):
        raise ValueError("Receipt or payment request is invalid.")

    expected_fields = {
        "protocol", "mode", "receipt_id", "request_id", "request_nonce",
        "customer_user_id", "merchant_user_id", "merchant_device_id",
        "amount_paise", "currency", "approved", "created_at", "expires_at",
    }
    if set(receipt) != expected_fields:
        raise ValueError("Receipt has missing or unexpected fields.")

    if receipt["protocol"] != PROTOCOL_VERSION or receipt["mode"] != SIMULATION_MODE:
        raise ValueError("Unsupported receipt protocol or mode.")
    if receipt["approved"] is not True:
        raise ValueError("Payment was not approved by the customer.")
    for field in ("receipt_id", "customer_user_id", "request_id", "request_nonce"):
        if not isinstance(receipt[field], str) or not receipt[field].strip():
            raise ValueError(f"Invalid receipt {field}.")

    bindings = {
        "request_id": "request_id",
        "request_nonce": "nonce",
        "merchant_user_id": "merchant_user_id",
        "merchant_device_id": "merchant_device_id",
        "amount_paise": "amount_paise",
        "currency": "currency",
    }
    for receipt_field, request_field in bindings.items():
        if receipt[receipt_field] != request.get(request_field):
            raise ValueError(f"Receipt does not match payment request ({receipt_field}).")

    amount = receipt["amount_paise"]
    if type(amount) is not int or not 1 <= amount <= MAX_TRANSACTION_PAISE:
        raise ValueError("Invalid receipt amount.")

    current = int(time.time()) if now is None else now
    created = receipt["created_at"]
    expires = receipt["expires_at"]
    if type(created) is not int or type(expires) is not int:
        raise ValueError("Invalid receipt validity period.")
    if created > current + 30 or expires <= created or expires - created > RECEIPT_TTL_SECONDS:
        raise ValueError("Invalid receipt validity period.")
    if expires <= current:
        raise ValueError("Customer receipt has expired.")
    if expires > request.get("expires_at", 0):
        raise ValueError("Receipt outlives its payment request.")

    return {
        "valid": True,
        "receipt_id": receipt["receipt_id"],
        "customer_user_id": receipt["customer_user_id"],
        "merchant_user_id": receipt["merchant_user_id"],
        "amount_paise": amount,
        "currency": CURRENCY,
        "status": "accepted_for_simulation_review",
        "security_note": "Structural validation only; QR contents are not cryptographic proof of customer identity.",
    }
