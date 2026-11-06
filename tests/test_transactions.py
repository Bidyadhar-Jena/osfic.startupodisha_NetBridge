import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import database
import transactions

from authenticator.identity import generate_identity
from authenticator.totp import generate_otp
from authenticator.totp_store import (
    begin_totp_enrollment,
    confirm_totp_enrollment,
)
import time


class NetBridgeTransactionTests(unittest.TestCase):

    def setUp(self):
        # Use a separate temporary database for every test.
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db = str(
            Path(self.temp_dir.name) / "test_netbridge.db"
        )

        self.db_patcher = patch.object(
            database,
            "DATABASE",
            self.test_db,
        )
        self.db_patcher.start()

        database.initialize_database()

        # Demo wallets created by initialize_database():
        # CUSTOMER001: ₹500
        # MERCHANT001: ₹100
        self.sender = generate_identity()
        self.receiver = generate_identity()

        self.sender_id = self.sender["device_id"]
        self.receiver_id = self.receiver["device_id"]

        # Register sender and receiver as explicitly approved devices.
        sender_result = database.register_trusted_device(
            device_id=self.sender_id,
            owner_user_id="CUSTOMER001",
            public_key=self.sender["public_key"],
            device_name="Test Sender",
            approved=True,
        )

        receiver_result = database.register_trusted_device(
            device_id=self.receiver_id,
            owner_user_id="MERCHANT001",
            public_key=self.receiver["public_key"],
            device_name="Test Receiver",
            approved=True,
        )

        self.assertEqual(
            sender_result["status"],
            "success",
            msg=str(sender_result),
        )

        self.assertEqual(
            receiver_result["status"],
            "success",
            msg=str(receiver_result),
        )

        # Every successful simulated transfer requires an enrolled TOTP.
        self.totp_secret = begin_totp_enrollment("CUSTOMER001")
        enrollment_code = generate_otp(self.totp_secret)
        self.assertTrue(
            confirm_totp_enrollment("CUSTOMER001", enrollment_code)
        )

    def current_otp(self):
        # Enrollment confirmation consumes its own time-step. Use the
        # next 30-second step for the payment test.
        return generate_otp(self.totp_secret, timestamp=time.time() + 30)

    def tearDown(self):
        self.db_patcher.stop()
        self.temp_dir.cleanup()

    def make_transaction(self, amount="10.00"):
        return transactions.create_transaction(
            sender_identity=self.sender,
            receiver_device_id=self.receiver_id,
            amount=amount,
        )

    # --------------------------------------------------
    # 1. SUCCESSFUL TRANSFER
    # --------------------------------------------------

    def test_successful_transfer_updates_both_balances(self):
        before_sender = database.get_wallet_balance(
            "CUSTOMER001"
        )
        before_receiver = database.get_wallet_balance(
            "MERCHANT001"
        )

        signed_transaction = self.make_transaction("10.00")

        result = transactions.process_transaction(
            signed_transaction,
            totp_otp=self.current_otp(),
        )

        self.assertEqual(
            result["status"],
            "success",
            msg=str(result),
        )

        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            before_sender - 1000,
        )

        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            before_receiver + 1000,
        )

    # --------------------------------------------------
    # 2. DUPLICATE TRANSACTION REJECTION
    # --------------------------------------------------

    def test_duplicate_transaction_is_rejected(self):
        signed_transaction = self.make_transaction("5.00")

        otp = self.current_otp()
        first_result = transactions.process_transaction(
            signed_transaction,
            totp_otp=otp,
        )

        self.assertEqual(
            first_result["status"],
            "success",
            msg=str(first_result),
        )

        sender_after_first = database.get_wallet_balance(
            "CUSTOMER001"
        )
        receiver_after_first = database.get_wallet_balance(
            "MERCHANT001"
        )

        second_result = transactions.process_transaction(
            signed_transaction,
            totp_otp=otp,
        )

        self.assertEqual(
            second_result["status"],
            "rejected",
            msg=str(second_result),
        )

        # The duplicate must not change either balance.
        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            sender_after_first,
        )

        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            receiver_after_first,
        )

    # --------------------------------------------------
    # 3. INSUFFICIENT BALANCE
    # --------------------------------------------------

    def test_insufficient_balance_is_rejected(self):
        sender_before = database.get_wallet_balance(
            "CUSTOMER001"
        )
        receiver_before = database.get_wallet_balance(
            "MERCHANT001"
        )

        # The customer starts with ₹500.
        signed_transaction = self.make_transaction("501.00")

        result = transactions.process_transaction(
            signed_transaction
        )

        self.assertEqual(
            result["status"],
            "rejected",
            msg=str(result),
        )

        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            sender_before,
        )

        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            receiver_before,
        )

    # --------------------------------------------------
    # 4. INVALID AMOUNTS
    # --------------------------------------------------

    def test_invalid_amounts_are_rejected(self):
        invalid_amounts = [
            "0",
            "-1",
            "abc",
            "1.234",
            "5000.01",
        ]

        for amount in invalid_amounts:
            with self.subTest(amount=amount):
                with self.assertRaises(ValueError):
                    self.make_transaction(amount)

    # --------------------------------------------------
    # 5. UNTRUSTED SENDER
    # --------------------------------------------------

    def test_revoked_sender_cannot_transfer(self):
        revoked = database.revoke_trusted_device(
            self.sender_id
        )

        self.assertEqual(
            revoked["status"],
            "success",
            msg=str(revoked),
        )

        sender_before = database.get_wallet_balance(
            "CUSTOMER001"
        )
        receiver_before = database.get_wallet_balance(
            "MERCHANT001"
        )

        signed_transaction = self.make_transaction("10.00")

        result = transactions.process_transaction(
            signed_transaction
        )

        self.assertEqual(
            result["status"],
            "rejected",
            msg=str(result),
        )

        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            sender_before,
        )

        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            receiver_before,
        )

    # --------------------------------------------------
    # 6. MODIFIED TRANSACTION REJECTION
    # --------------------------------------------------

    def test_modified_amount_is_rejected(self):
        signed_transaction = self.make_transaction("10.00")

        # Change the amount without creating a new signature.
        signed_transaction["transaction"]["amount_paise"] = 2000

        result = transactions.process_transaction(
            signed_transaction
        )

        self.assertEqual(
            result["status"],
            "rejected",
            msg=str(result),
        )

        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            50000,
        )

        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            10000,
        )

    # --------------------------------------------------
    # 7. MISSING SIGNED TRANSACTION
    # --------------------------------------------------

    def test_missing_transaction_is_rejected(self):
        result = transactions.process_transaction({})

        self.assertEqual(result["status"], "rejected")

    # --------------------------------------------------
    # 8. UNSUPPORTED CURRENCY
    # --------------------------------------------------

    def test_unsupported_currency_is_rejected(self):
        signed_transaction = self.make_transaction("10.00")

        signed_transaction["transaction"]["currency"] = "USD"

        result = transactions.process_transaction(
            signed_transaction
        )

        self.assertEqual(result["status"], "rejected")

        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            50000,
        )

        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            10000,
        )

    # --------------------------------------------------
    # 9. DIRECT TRANSFER WITHOUT VERIFIED SIGNATURE
    # --------------------------------------------------

    def test_database_rejects_unverified_transfer(self):
        result = database.process_wallet_transfer(
            transaction_id="test-unverified-transfer",
            sender_id="CUSTOMER001",
            receiver_id="MERCHANT001",
            amount_paise=100,
            sender_device_id=self.sender_id,
            receiver_device_id=self.receiver_id,
            signature="test-signature",
            digest="test-digest",
            signature_verified=False,
        )

        self.assertEqual(result["status"], "rejected")

        self.assertEqual(
            database.get_wallet_balance("CUSTOMER001"),
            50000,
        )

        self.assertEqual(
            database.get_wallet_balance("MERCHANT001"),
            10000,
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)