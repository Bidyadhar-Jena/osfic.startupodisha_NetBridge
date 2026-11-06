"""
Compatibility layer for trusted-device operations.

SQLite is the single source of truth for NetBridge trusted devices.
This module preserves the existing registry function names so that
other modules can continue importing them.
"""

from database import (
    register_trusted_device,
    get_trusted_device,
    is_device_trusted,
    list_trusted_devices,
    revoke_trusted_device,
)


def register_device(
    device_id,
    public_key,
    approved=False,
    name="Unnamed device",
    path=None,
    owner_user_id=None,
):
    """
    Register a device in SQLite after explicit approval.

    owner_user_id is required because the database associates each
    trusted device with a wallet owner.

    The path argument is retained for compatibility with old callers.
    Custom JSON registry paths are no longer supported.
    """
    if path is not None:
        return {
            "status": "error",
            "message": (
                "Custom JSON registry paths are no longer supported. "
                "Trusted devices are stored in SQLite."
            ),
        }

    if approved is not True:
        return {
            "status": "error",
            "message": "Explicit device approval is required.",
        }

    if not isinstance(device_id, str) or not device_id:
        return {
            "status": "error",
            "message": "A valid device ID is required.",
        }

    if not isinstance(public_key, str) or not public_key:
        return {
            "status": "error",
            "message": "A valid public key is required.",
        }

    if not isinstance(owner_user_id, str) or not owner_user_id:
        return {
            "status": "error",
            "message": "A wallet owner ID is required.",
        }

    if not isinstance(name, str) or not name.strip():
        return {
            "status": "error",
            "message": "A device name is required.",
        }

    try:
        return register_trusted_device(
            device_id=device_id,
            owner_user_id=owner_user_id,
            public_key=public_key,
            device_name=name.strip(),
            approved=True,
        )

    except Exception:
        return {
            "status": "error",
            "message": "Trusted-device registration failed.",
        }


def is_trusted(device_id, path=None):
    """Return True only if the device is currently trusted."""
    if path is not None or not isinstance(device_id, str):
        return False

    try:
        return is_device_trusted(device_id)

    except Exception:
        return False


def get_device(device_id, path=None):
    """Return a trusted-device record, or None if unavailable."""
    if path is not None or not isinstance(device_id, str):
        return None

    try:
        device = get_trusted_device(device_id)
        return dict(device) if device else None

    except Exception:
        return None


def list_devices(path=None):
    """List devices stored in SQLite."""
    if path is not None:
        return []

    try:
        return [
            dict(device)
            for device in list_trusted_devices()
        ]

    except Exception:
        return []


def revoke_device(device_id, path=None):
    """Revoke a trusted device in SQLite."""
    if path is not None:
        return {
            "status": "error",
            "message": "Custom JSON registry paths are not supported.",
        }

    if not isinstance(device_id, str) or not device_id:
        return {
            "status": "error",
            "message": "A valid device ID is required.",
        }

    try:
        return revoke_trusted_device(device_id)

    except Exception:
        return {
            "status": "error",
            "message": "Device revocation failed.",
        }