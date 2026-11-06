# offline_qr.py

import json
from pathlib import Path

import qrcode


PROTOCOL_VERSION = "netbridge-offline-v1"
SIMULATION_MODE = "simulation_only"

MAX_QR_PAYLOAD_BYTES = 20_000


def _validate_payload(payload):
    """Validate a NetBridge QR payload."""

    if not isinstance(payload, dict):
        raise ValueError("QR payload must be a dictionary.")

    if payload.get("protocol") != PROTOCOL_VERSION:
        raise ValueError("Unsupported QR protocol.")

    if payload.get("mode") != SIMULATION_MODE:
        raise ValueError("Unsupported payment mode.")

    payload_type = payload.get("type")

    if payload_type not in {
        "payment_request",
        "payment_authorization",
        "payment_receipt",
    }:
        raise ValueError("Unsupported QR payload type.")

    data = payload.get("data")

    if not isinstance(data, dict):
        raise ValueError("QR data is missing.")

    if not isinstance(data.get("request"), dict) and (
        payload_type == "payment_request"
    ):
        raise ValueError("Payment request data is missing.")

    expected_data_key = {
        "payment_authorization": "authorization",
        "payment_receipt": "receipt",
    }.get(payload_type)
    if expected_data_key and not isinstance(data.get(expected_data_key), dict):
        raise ValueError(f"Payment {payload_type.replace('_', ' ')} data is missing.")

    return payload


def create_qr_payload(payload_type, signed_data):
    """
    Convert a signed payment request or signed authorization
    into a compact JSON string suitable for a QR code.

    This function packages data; it does not verify signatures.
    """

    if payload_type not in {
        "payment_request",
        "payment_authorization",
        "payment_receipt",
    }:
        raise ValueError("Unsupported QR payload type.")

    if not isinstance(signed_data, dict):
        raise ValueError("Signed payment data must be a dictionary.")

    if payload_type == "payment_request":
        if not isinstance(signed_data.get("request"), dict):
            raise ValueError("Signed payment request is missing.")
    else:
        expected_data_key = "authorization" if payload_type == "payment_authorization" else "receipt"
        if not isinstance(signed_data.get(expected_data_key), dict):
            raise ValueError(f"Payment {payload_type.replace('_', ' ')} data is missing.")

    payload = {
        "protocol": PROTOCOL_VERSION,
        "mode": SIMULATION_MODE,
        "type": payload_type,
        "data": signed_data,
    }

    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )

    if len(encoded.encode("utf-8")) > MAX_QR_PAYLOAD_BYTES:
        raise ValueError("QR payload is too large.")

    return encoded


def parse_qr_payload(qr_text):
    """
    Parse text decoded by a QR scanner.

    The returned data is untrusted until the receiving side validates
    its request binding, expiry, replay status and authorization proof.
    """

    if not isinstance(qr_text, str) or not qr_text.strip():
        raise ValueError("QR text is empty or invalid.")

    if len(qr_text.encode("utf-8")) > MAX_QR_PAYLOAD_BYTES:
        raise ValueError("QR payload is too large.")

    try:
        payload = json.loads(qr_text)
    except (json.JSONDecodeError, UnicodeError) as exc:
        raise ValueError("QR payload is not valid JSON.") from exc

    _validate_payload(payload)

    return payload


def create_qr_image(payload_type, signed_data, output_path):
    """
    Generate a QR image containing a payment request or authorization receipt.

    Returns the output image path as a string.
    """

    qr_text = create_qr_payload(
        payload_type=payload_type,
        signed_data=signed_data,
    )

    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=8,
        border=4,
    )

    qr.add_data(qr_text)
    qr.make(fit=True)

    image = qr.make_image(
        fill_color="black",
        back_color="white",
    )

    image.save(path)

    return str(path)
