import os
import tempfile
import time
import unittest

import database

from authenticator.identity import generate_identity
from authenticator.totp import generate_otp
from authenticator.totp_store import (
    begin_totp_enrollment,
    confirm_totp_enrollment,
)
from transactions import (
    create_transaction,
    process_transaction,
)


class TestTransactionIntegration(unittest.TestCase):

    def setUp(self):
        # Use an isolated temporary database for every test.
        handle = tempfile.NamedTemporaryFile(
            suffix=".db",
            delete=False,
        )
        handle.close()

        self.test_db = handle.name
        self.original_db = database.DATABASE
        database.DATABASE = self.test_db

        database.initialize_database()

        # Generate two independent device identities.
        self.sender = generate_identity()
        self.receiver = generate_identity()

        # Register the sender and receiver with explicit approval.
        sender_result = database.register_trusted_device(
            device_id=self.sender["device_id"],
            owner_user_id="CUSTOMER001",
            public_key=self.sender["public_key"],
            device_name="Integration Sender",
            approved=True,
        )

        receiver_result = database.register_trusted_device(
            device_id=self.receiver["device_id"],
            owner_user_id="MERCHANT001",
            public_key=self.receiver["public_key"],
            device_name="Integration Receiver",
            approved=True,
        )

        self.assertEqual(sender_result["status"], "success")
        self.assertEqual(receiver_result["status"], "success")

        self.initial_sender_balance = database.get_wallet_balance(
            "CUSTOMER001"
        )
        self.initial_receiver_balance = database.get_wallet_balance(
            "MERCHANT001"
        )

        self.totp_secret = begin_totp_enrollment("CUSTOMER001")
        self.assertTrue(
            confirm_totp_enrollment(
                "CUSTOMER001",
                generate_otp(self.totp_secret),
            )
        )

    def current_otp(self):
        # Enrollment confirmation consumes its own time-step. Use the
        # next 30-second step for the payment test.
        return generate_otp(self.totp_secret, timestamp=time.time() + 30)

    def tearDown(self):
        database.DATABASE = self.original_db

        if os.path.exists(self.test_db):
            os.remove(self.test_db)

    def make_transaction(self, amount=10):
        return create_transaction(
            sender_identity=self.sender,
            receiver_device_id=self.receiver["device_id"],
            amount=amount,
        )

    def test_successful_simulated_transfer(self):
        signed = self.make_transaction(amount=10)

        result = process_transaction(
            signed,
            totp_otp=self.current_otp(),
        )

        self.assertEqual(result["status"], "success")
        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            self.initial_sender_balance - 1000,
        )
        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            self.initial_receiver_balance + 1000,
        )

    def test_invalid_signature_is_rejected(self):
        signed = self.make_transaction(amount=10)
        signed["signature"] = "invalid-signature"

        result = process_transaction(signed)

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            self.initial_sender_balance,
        )
        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            self.initial_receiver_balance,
        )

    def test_expired_transaction_is_rejected(self):
        signed = self.make_transaction(amount=10)

        # Expiry validation occurs before signature verification.
        signed["transaction"]["expires_at"] = int(time.time()) - 1

        result = process_transaction(signed)

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            self.initial_sender_balance,
        )
        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            self.initial_receiver_balance,
        )

    def test_duplicate_transaction_is_rejected(self):
        signed = self.make_transaction(amount=10)

        otp = self.current_otp()
        first_result = process_transaction(signed, totp_otp=otp)
        second_result = process_transaction(signed, totp_otp=otp)

        self.assertEqual(first_result["status"], "success")
        self.assertEqual(second_result["status"], "rejected")

        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            self.initial_sender_balance - 1000,
        )
        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            self.initial_receiver_balance + 1000,
        )

    def test_revoked_sender_device_is_rejected(self):
        signed = self.make_transaction(amount=10)

        revoke_result = database.revoke_trusted_device(
            self.sender["device_id"]
        )
        self.assertEqual(revoke_result["status"], "success")

        result = process_transaction(signed)

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            self.initial_sender_balance,
        )
        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            self.initial_receiver_balance,
        )

    def test_tampered_amount_is_rejected(self):
        signed = self.make_transaction(amount=10)

        # Change signed data without generating a new signature.
        signed["transaction"]["amount_paise"] = 2000

        result = process_transaction(signed)

        self.assertEqual(result["status"], "rejected")
        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            self.initial_sender_balance,
        )
        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            self.initial_receiver_balance,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)