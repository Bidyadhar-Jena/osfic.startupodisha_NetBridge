import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from authenticator.identity import generate_identity
from offline.offline_protocol import (
    create_payment_request,
    verify_payment_request,
    create_customer_authorization,
    verify_customer_authorization,
)
from offline.offline_ledger import initialize_ledger, list_offline_payments
from offline.offline_spending_control import (
    record_authorization_with_spending_limits,
    get_customer_offline_spending,
)


class OfflineSpendingControlsTests(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.database_path = (
            Path(self.temp_directory.name) / "test_spending.db"
        )

        initialize_ledger(self.database_path)

        self.merchant = generate_identity()
        self.customer = generate_identity()

    def tearDown(self):
        self.temp_directory.cleanup()

    def create_verified_payment(self, amount_rupees):
        signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id="MERCHANT001",
            amount_rupees=str(amount_rupees),
        )

        verified_request = verify_payment_request(
            signed_request=signed_request,
            trusted_merchant_public_key=self.merchant["public_key"],
        )

        signed_authorization = create_customer_authorization(
            customer_identity=self.customer,
            customer_user_id="CUSTOMER001",
            verified_request=verified_request,
        )

        verified_authorization = verify_customer_authorization(
            signed_authorization=signed_authorization,
            verified_request=verified_request,
            trusted_customer_public_key=self.customer["public_key"],
        )

        return verified_authorization, signed_authorization

    def record_payment(self, amount_rupees):
        verified, signed = self.create_verified_payment(amount_rupees)

        return record_authorization_with_spending_limits(
            verification_result=verified,
            signed_authorization=signed,
            database_path=self.database_path,
        )

    def test_payment_within_limits_is_accepted(self):
        result = self.record_payment("25.50")

        self.assertEqual(result["status"], "accepted_locally")
        self.assertEqual(result["amount_paise"], 2550)
        self.assertEqual(result["ledger_status"], "pending_reconciliation")

    def test_payment_above_single_payment_limit_is_rejected(self):
        # ₹5,000.01 exceeds the configured per-payment limit.
        with self.assertRaises(ValueError):
            self.create_and_record_payment("5000.01")

    def create_and_record_payment(self, amount_rupees):
        return self.record_payment(amount_rupees)

    def test_cumulative_spending_limit_is_enforced(self):
        self.record_payment("4000")
        self.record_payment("4000")

        # ₹4,000 + ₹4,000 + ₹2,001 = ₹10,001.
        with self.assertRaises(ValueError):
            self.record_payment("2001")

        spending = get_customer_offline_spending(
            customer_user_id="CUSTOMER001",
            database_path=self.database_path,
        )

        self.assertEqual(spending["spent_paise"], 800000)
        self.assertEqual(spending["remaining_paise"], 200000)

    def test_duplicate_authorization_is_rejected(self):
        verified, signed = self.create_verified_payment("25.50")

        record_authorization_with_spending_limits(
            verification_result=verified,
            signed_authorization=signed,
            database_path=self.database_path,
        )

        with self.assertRaises(ValueError):
            record_authorization_with_spending_limits(
                verification_result=verified,
                signed_authorization=signed,
                database_path=self.database_path,
            )

        records = list_offline_payments(
            status="pending_reconciliation",
            database_path=self.database_path,
        )

        self.assertEqual(len(records), 1)

    def test_expired_authorization_is_rejected_at_ledger_write(self):
        verified, signed = self.create_verified_payment("25.50")
        expiry = signed["authorization"]["expires_at"]

        with patch("offline.offline.offline_spending_control.time.time", return_value=expiry):
            with self.assertRaisesRegex(ValueError, "authorization has expired"):
                record_authorization_with_spending_limits(
                    verification_result=verified,
                    signed_authorization=signed,
                    database_path=self.database_path,
                )

        records = list_offline_payments(database_path=self.database_path)
        self.assertEqual(records, [])

    def test_spending_persists_across_connections(self):
        self.record_payment("100")

        spending = get_customer_offline_spending(
            customer_user_id="CUSTOMER001",
            database_path=self.database_path,
        )

        self.assertEqual(spending["spent_paise"], 10000)
        self.assertEqual(spending["remaining_paise"], 990000)


if __name__ == "__main__":
    unittest.main(verbosity=2)
