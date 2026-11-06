import base64
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


DATA_DIR = Path(__file__).resolve().parent.parent / "data"
IDENTITY_FILE = DATA_DIR / "device_identity.json"


def _encode(data):
    return base64.b64encode(data).decode("ascii")


def _decode(data):
    return base64.b64decode(data, validate=True)


def generate_identity():
    """Generate a new Ed25519 device identity."""
    private_key = Ed25519PrivateKey.generate()

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    device_id = hashlib.sha256(public_key_bytes).hexdigest()

    return {
        "device_id": device_id,
        "public_key": _encode(public_key_bytes),
        "private_key": private_key,
    }


def save_identity(identity, path=None):
    """Save the local device identity."""
    destination = Path(path) if path else IDENTITY_FILE
    destination.parent.mkdir(parents=True, exist_ok=True)

    private_key = identity["private_key"]

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    document = {
        "device_id": identity["device_id"],
        "public_key": identity["public_key"],
        "private_key": _encode(private_pem),
    }

    # Create the file for this device identity.
    with destination.open("x", encoding="utf-8") as file:
        json.dump(document, file, indent=4)

    # Restrict permissions where supported.
    try:
        destination.chmod(0o600)
    except OSError:
        pass

    return destination


def load_identity(path=None):
    """Load the existing local device identity."""
    source = Path(path) if path else IDENTITY_FILE

    if not source.exists():
        return None

    with source.open("r", encoding="utf-8") as file:
        document = json.load(file)

    private_pem = _decode(document["private_key"])

    private_key = serialization.load_pem_private_key(
        private_pem,
        password=None,
    )

    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("The saved identity is not an Ed25519 key.")

    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )

    expected_device_id = hashlib.sha256(public_key_bytes).hexdigest()

    if (
        document["device_id"] != expected_device_id
        or document["public_key"] != _encode(public_key_bytes)
    ):
        raise ValueError("The saved device identity failed validation.")

    return {
        "device_id": expected_device_id,
        "public_key": _encode(public_key_bytes),
        "private_key": private_key,
    }


def get_or_create_identity():
    """Load the device identity, or create one if it doesn't exist."""
    identity = load_identity()

    if identity is not None:
        return identity

    identity = generate_identity()
    save_identity(identity)

    return identity


def sign_message(identity, message):
    """Sign bytes or a UTF-8 string with the device's private key."""
    if isinstance(message, str):
        message = message.encode("utf-8")

    signature = identity["private_key"].sign(message)
    return _encode(signature)


def verify_signature(public_key_b64, message, signature_b64):
    """Verify a signature using the supplied public key."""
    try:
        public_key_bytes = _decode(public_key_b64)
        signature = _decode(signature_b64)

        public_key = Ed25519PublicKey.from_public_bytes(
            public_key_bytes
        )

        if isinstance(message, str):
            message = message.encode("utf-8")

        public_key.verify(signature, message)
        return True

    except Exception:
        return False