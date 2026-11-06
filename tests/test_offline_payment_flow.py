# test_offline_payment_flow.py

import tempfile
import unittest
from pathlib import Path

from authenticator.identity import generate_identity

from offline.offline_protocol import (
    create_payment_request,
    verify_payment_request,
    create_customer_authorization,
    verify_customer_authorization,
)

from offline.offline_qr import (
    create_qr_payload,
    parse_qr_payload,
)

from offline.offline_ledger import initialize_ledger, list_offline_payments

from offline.offline_spending_control import (
    record_authorization_with_spending_limits,
    get_customer_offline_spending,
)


class OfflinePaymentFlowTests(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()

        self.database_path = (
            Path(self.temp_directory.name) / "payment_flow.db"
        )

        initialize_ledger(self.database_path)

        self.merchant = generate_identity()
        self.customer = generate_identity()

        self.merchant_id = "MERCHANT001"
        self.customer_id = "CUSTOMER001"

    def tearDown(self):
        self.temp_directory.cleanup()

    def create_merchant_qr(self, amount_rupees):
        """Merchant creates a signed payment request QR."""

        signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id=self.merchant_id,
            amount_rupees=str(amount_rupees),
        )

        qr_text = create_qr_payload(
            payload_type="payment_request",
            signed_data=signed_request,
        )

        return qr_text

    def customer_scan_and_authorize(self, merchant_qr_text):
        """Customer scans, verifies, and authorizes the request."""

        scanned_payload = parse_qr_payload(merchant_qr_text)

        self.assertEqual(
            scanned_payload["type"],
            "payment_request",
        )

        signed_request = scanned_payload["data"]

        verified_request = verify_payment_request(
            signed_request=signed_request,
            trusted_merchant_public_key=self.merchant["public_key"],
        )

        signed_authorization = create_customer_authorization(
            customer_identity=self.customer,
            customer_user_id=self.customer_id,
            verified_request=verified_request,
        )

        customer_qr_text = create_qr_payload(
            payload_type="payment_authorization",
            signed_data=signed_authorization,
        )

        return customer_qr_text

    def merchant_scan_and_record(self, customer_qr_text):
        """Merchant verifies the customer's authorization and records it."""

        scanned_payload = parse_qr_payload(customer_qr_text)

        self.assertEqual(
            scanned_payload["type"],
            "payment_authorization",
        )

        signed_authorization = scanned_payload["data"]

        # Reconstruct and verify the original merchant request.
        request_digest = signed_authorization["authorization"][
            "request_digest"
        ]

        # This test retains the original signed request for verification.
        signed_request = self.current_signed_request

        verified_request = verify_payment_request(
            signed_request=signed_request,
            trusted_merchant_public_key=self.merchant["public_key"],
        )

        if verified_request["request_digest"] != request_digest:
            raise ValueError("Authorization references another request.")

        verified_authorization = verify_customer_authorization(
            signed_authorization=signed_authorization,
            verified_request=verified_request,
            trusted_customer_public_key=self.customer["public_key"],
        )

        return record_authorization_with_spending_limits(
            verification_result=verified_authorization,
            signed_authorization=signed_authorization,
            database_path=self.database_path,
        )

    def execute_payment(self, amount_rupees):
        """Execute the complete simulated offline QR flow."""

        self.current_signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id=self.merchant_id,
            amount_rupees=str(amount_rupees),
        )

        merchant_qr_text = create_qr_payload(
            payload_type="payment_request",
            signed_data=self.current_signed_request,
        )

        customer_qr_text = self.customer_scan_and_authorize(
            merchant_qr_text
        )

        return self.merchant_scan_and_record(customer_qr_text)

    def test_complete_offline_payment_flow(self):
        result = self.execute_payment("25.50")

        self.assertEqual(result["status"], "accepted_locally")
        self.assertEqual(result["amount_paise"], 2550)
        self.assertEqual(
            result["ledger_status"],
            "pending_reconciliation",
        )

        records = list_offline_payments(
            database_path=self.database_path,
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["amount_paise"], 2550)

    def test_customer_spending_is_updated(self):
        self.execute_payment("100")

        spending = get_customer_offline_spending(
            customer_user_id=self.customer_id,
            database_path=self.database_path,
        )

        self.assertEqual(spending["spent_paise"], 10000)
        self.assertEqual(spending["remaining_paise"], 990000)

    def test_cumulative_limit_rejects_excess_payment(self):
        self.execute_payment("4000")
        self.execute_payment("4000")

        with self.assertRaises(ValueError):
            self.execute_payment("2001")

        records = list_offline_payments(
            database_path=self.database_path,
        )

        self.assertEqual(len(records), 2)

    def test_tampered_customer_authorization_is_rejected(self):
        self.current_signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id=self.merchant_id,
            amount_rupees="25.50",
        )

        verified_request = verify_payment_request(
            signed_request=self.current_signed_request,
            trusted_merchant_public_key=self.merchant["public_key"],
        )

        signed_authorization = create_customer_authorization(
            customer_identity=self.customer,
            customer_user_id=self.customer_id,
            verified_request=verified_request,
        )

        # Change the amount after the customer has signed.
        signed_authorization["authorization"]["amount_paise"] = 100

        customer_qr_text = create_qr_payload(
            payload_type="payment_authorization",
            signed_data=signed_authorization,
        )

        with self.assertRaises(ValueError):
            self.merchant_scan_and_record(customer_qr_text)

        records = list_offline_payments(
            database_path=self.database_path,
        )

        self.assertEqual(len(records), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)