import base64
import hashlib
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import database
import security
import transactions

from authenticator.identity import generate_identity, sign_message
from authenticator.challenge import ChallengeManager


class NetBridgeSecurityTests(unittest.TestCase):

    def setUp(self):
        """
        Give every test an isolated temporary SQLite database.
        The actual NetBridge database is not modified.
        """
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_database = (
            Path(self.temp_dir.name) / "test_netbridge.db"
        )

        self.database_patcher = patch.object(
            database,
            "DATABASE",
            str(self.test_database),
        )
        self.database_patcher.start()

        database.initialize_database()

    def tearDown(self):
        self.database_patcher.stop()
        self.temp_dir.cleanup()

    # --------------------------------------------------
    # 1. VALID TRANSACTION AMOUNTS
    # --------------------------------------------------

    def test_valid_transaction_amounts(self):
        self.assertEqual(security.validate_amount("1"), 100)
        self.assertEqual(security.validate_amount("10.50"), 1050)
        self.assertEqual(security.validate_amount("0.01"), 1)

    # --------------------------------------------------
    # 2. INVALID TRANSACTION AMOUNTS
    # --------------------------------------------------

    def test_invalid_transaction_amounts(self):
        invalid_values = [
            "0",
            "-1",
            "-100.50",
            "abc",
            "1.234",
            "",
            None,
            float("inf"),
            float("nan"),
        ]

        for value in invalid_values:
            with self.subTest(value=value):
                self.assertIsNone(
                    security.validate_amount(value)
                )

    # --------------------------------------------------
    # 3. TRANSACTION LIMIT
    # --------------------------------------------------

    def test_transaction_limit(self):
        self.assertEqual(
            transactions.validate_amount("5000"),
            500000,
        )

        with self.assertRaises(ValueError):
            transactions.validate_amount("5000.01")

    # --------------------------------------------------
    # 4. PIN VALIDATION
    # --------------------------------------------------

    def test_pin_validation(self):
        self.assertTrue(security.validate_pin("1234"))
        self.assertFalse(security.validate_pin("123"))
        self.assertFalse(security.validate_pin("12345"))
        self.assertFalse(security.validate_pin("abcd"))
        self.assertFalse(security.validate_pin("１２３４"))

    # --------------------------------------------------
    # 5. DEVICE IDENTITY
    # --------------------------------------------------

    def test_device_identity_matches_public_key(self):
        identity = generate_identity()

        public_key = base64.b64decode(
            identity["public_key"],
            validate=True,
        )

        expected_id = hashlib.sha256(public_key).hexdigest()

        self.assertEqual(
            identity["device_id"],
            expected_id,
        )

    # --------------------------------------------------
    # 6. VALID CHALLENGE AND REPLAY PROTECTION
    # --------------------------------------------------

    def test_valid_challenge_and_replay_rejection(self):
        identity = generate_identity()
        manager = ChallengeManager(ttl=60)

        challenge = manager.issue_challenge(
            identity["device_id"]
        )

        with manager.lock:
            stored = manager.pending.get(
                challenge["challenge_id"]
            )

        self.assertIsNotNone(stored)

        signature = sign_message(
            identity,
            stored["message"],
        )

        result = manager.verify_response(
            device_id=identity["device_id"],
            challenge_id=challenge["challenge_id"],
            nonce=challenge["nonce"],
            signature=signature,
            public_key_b64=identity["public_key"],
        )

        self.assertEqual(
            result["status"],
            "success",
            msg=f"Valid challenge failed: {result}",
        )

        # The same challenge must not work a second time.
        replay = manager.verify_response(
            device_id=identity["device_id"],
            challenge_id=challenge["challenge_id"],
            nonce=challenge["nonce"],
            signature=signature,
            public_key_b64=identity["public_key"],
        )

        self.assertEqual(replay["status"], "error")

    # --------------------------------------------------
    # 7. WRONG NONCE
    # --------------------------------------------------

    def test_wrong_challenge_nonce_is_rejected(self):
        identity = generate_identity()
        manager = ChallengeManager(ttl=60)

        challenge = manager.issue_challenge(
            identity["device_id"]
        )

        with manager.lock:
            stored = manager.pending.get(
                challenge["challenge_id"]
            )

        self.assertIsNotNone(stored)

        signature = sign_message(
            identity,
            stored["message"],
        )

        result = manager.verify_response(
            device_id=identity["device_id"],
            challenge_id=challenge["challenge_id"],
            nonce="incorrect-nonce",
            signature=signature,
            public_key_b64=identity["public_key"],
        )

        self.assertEqual(result["status"], "error")

    # --------------------------------------------------
    # 8. WRONG SIGNATURE
    # --------------------------------------------------

    def test_challenge_rejects_wrong_signature(self):
        identity = generate_identity()
        another_identity = generate_identity()
        manager = ChallengeManager(ttl=60)

        challenge = manager.issue_challenge(
            identity["device_id"]
        )

        with manager.lock:
            stored = manager.pending.get(
                challenge["challenge_id"]
            )

        self.assertIsNotNone(stored)

        wrong_signature = sign_message(
            another_identity,
            stored["message"],
        )

        result = manager.verify_response(
            device_id=identity["device_id"],
            challenge_id=challenge["challenge_id"],
            nonce=challenge["nonce"],
            signature=wrong_signature,
            public_key_b64=identity["public_key"],
        )

        self.assertEqual(result["status"], "error")

    # --------------------------------------------------
    # 9. EXPIRED CHALLENGE
    # --------------------------------------------------

    def test_expired_challenge_is_rejected(self):
        identity = generate_identity()
        manager = ChallengeManager(ttl=1)

        challenge = manager.issue_challenge(
            identity["device_id"]
        )

        with manager.lock:
            stored = manager.pending.get(
                challenge["challenge_id"]
            )

        self.assertIsNotNone(stored)

        signature = sign_message(
            identity,
            stored["message"],
        )

        time.sleep(2)

        result = manager.verify_response(
            device_id=identity["device_id"],
            challenge_id=challenge["challenge_id"],
            nonce=challenge["nonce"],
            signature=signature,
            public_key_b64=identity["public_key"],
        )

        self.assertEqual(result["status"], "error")

    # --------------------------------------------------
    # 10. REGISTRATION REQUIRES APPROVAL
    # --------------------------------------------------

    def test_device_registration_requires_approval(self):
        identity = generate_identity()

        result = database.register_trusted_device(
            device_id=identity["device_id"],
            owner_user_id="CUSTOMER001",
            public_key=identity["public_key"],
            device_name="NetBridge test device",
            approved=False,
        )

        self.assertEqual(
            result["status"],
            "error",
        )

        self.assertFalse(
            database.is_device_trusted(
                identity["device_id"]
            )
        )

    # --------------------------------------------------
    # 11. REVOKED DEVICE IS NO LONGER TRUSTED
    # --------------------------------------------------

    def test_revoked_device_is_not_trusted(self):
        identity = generate_identity()
        device_id = identity["device_id"]

        registered = database.register_trusted_device(
            device_id=device_id,
            owner_user_id="CUSTOMER001",
            public_key=identity["public_key"],
            device_name="NetBridge revocation test",
            approved=True,
        )

        self.assertEqual(
            registered["status"],
            "success",
            msg=f"Registration failed: {registered}",
        )

        self.assertTrue(
            database.is_device_trusted(device_id)
        )

        revoked = database.revoke_trusted_device(device_id)

        self.assertEqual(
            revoked["status"],
            "success",
            msg=f"Revocation failed: {revoked}",
        )

        self.assertFalse(
            database.is_device_trusted(device_id)
        )

    # --------------------------------------------------
    # 12. REVOKED DEVICE CANNOT BE RE-REGISTERED
    # --------------------------------------------------

    def test_revoked_device_cannot_be_re_registered(self):
        identity = generate_identity()
        device_id = identity["device_id"]

        registered = database.register_trusted_device(
            device_id=device_id,
            owner_user_id="CUSTOMER001",
            public_key=identity["public_key"],
            device_name="NetBridge re-registration test",
            approved=True,
        )

        self.assertEqual(
            registered["status"],
            "success",
            msg=f"Registration failed: {registered}",
        )

        revoked = database.revoke_trusted_device(device_id)

        self.assertEqual(
            revoked["status"],
            "success",
            msg=f"Revocation failed: {revoked}",
        )

        result = database.register_trusted_device(
            device_id=device_id,
            owner_user_id="CUSTOMER001",
            public_key=identity["public_key"],
            device_name="NetBridge re-registration test",
            approved=True,
        )

        self.assertEqual(
            result["status"],
            "error",
            msg=f"Revoked device was unexpectedly registered: {result}",
        )

        self.assertFalse(
            database.is_device_trusted(device_id)
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)