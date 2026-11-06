import base64
import hashlib
import json
import secrets
import time
from threading import Lock

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PublicKey,
)


CHALLENGE_TTL_SECONDS = 60


def canonical_message(payload):
    """Serialize challenge data consistently for signing."""
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


class ChallengeManager:
    """Issue and verify short-lived, single-use challenges."""

    def __init__(self, ttl=CHALLENGE_TTL_SECONDS):
        if type(ttl) is not int or ttl < 1:
            raise ValueError("Challenge TTL must be a positive integer.")

        self.ttl = ttl
        self.pending = {}
        self.lock = Lock()

    @staticmethod
    def _error(message):
        """Return a consistent error format for API callers."""
        return {
            "success": False,
            "status": "error",
            "message": message,
        }

    def issue_challenge(self, device_id):
        """Create a challenge that expires after the configured TTL."""
        if not isinstance(device_id, str) or not device_id:
            raise ValueError("A valid device ID is required.")

        challenge_id = secrets.token_urlsafe(24)
        nonce = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + self.ttl

        payload = {
            "challenge_id": challenge_id,
            "device_id": device_id,
            "nonce": nonce,
            "expires_at": expires_at,
        }

        with self.lock:
            self._remove_expired()

            self.pending[challenge_id] = {
                **payload,
                "message": canonical_message(payload),
            }

        return {
            "challenge_id": challenge_id,
            "device_id": device_id,
            "nonce": nonce,
            "expires_at": expires_at,
        }

    def verify_response(
        self,
        device_id,
        challenge_id,
        nonce,
        signature,
        public_key_b64,
    ):
        """
        Verify that the device possesses the matching private key.

        A challenge is consumed on the first verification attempt,
        including unsuccessful attempts.
        """
        if not all(
            isinstance(value, str) and value
            for value in (
                device_id,
                challenge_id,
                nonce,
                signature,
                public_key_b64,
            )
        ):
            return self._error("Required challenge details are missing.")

        with self.lock:
            challenge = self.pending.pop(challenge_id, None)

        if challenge is None:
            return self._error(
                "Challenge missing, expired, or already used."
            )

        if int(time.time()) >= challenge["expires_at"]:
            return self._error("Challenge has expired.")

        if (
            device_id != challenge["device_id"]
            or nonce != challenge["nonce"]
        ):
            return self._error("Challenge details do not match.")

        try:
            public_key_bytes = base64.b64decode(
                public_key_b64,
                validate=True,
            )

            # Ed25519 raw public keys must be exactly 32 bytes.
            if len(public_key_bytes) != 32:
                return self._error("Invalid public-key length.")

            calculated_device_id = hashlib.sha256(
                public_key_bytes
            ).hexdigest()

            if calculated_device_id != device_id:
                return self._error(
                    "Device identity does not match its public key."
                )

            public_key = Ed25519PublicKey.from_public_bytes(
                public_key_bytes
            )

            signature_bytes = base64.b64decode(
                signature,
                validate=True,
            )

            public_key.verify(
                signature_bytes,
                challenge["message"],
            )

        except (ValueError, TypeError, InvalidSignature):
            return self._error("Cryptographic verification failed.")

        except Exception:
            return self._error("Invalid challenge response.")

        return {
            "success": True,
            "status": "success",
            "message": "Device proved possession of its private key.",
            "device_id": device_id,
        }

    def _remove_expired(self):
        """Remove expired challenges. Call while holding the lock."""
        now = int(time.time())

        expired_ids = [
            challenge_id
            for challenge_id, challenge in self.pending.items()
            if challenge["expires_at"] <= now
        ]

        for challenge_id in expired_ids:
            self.pending.pop(challenge_id, None)