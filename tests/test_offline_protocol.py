# test_offline_protocol.py

import copy
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
from offline.offline_ledger import (
    initialize_ledger,
    record_verified_authorization,
    list_offline_payments,
)


class OfflineProtocolTests(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.ledger_path = (
            Path(self.temp_directory.name) / "test_offline_ledger.db"
        )

        self.merchant = generate_identity()
        self.customer = generate_identity()

        initialize_ledger(self.ledger_path)

    def tearDown(self):
        self.temp_directory.cleanup()

    def create_verified_payment(self):
        signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id="MERCHANT001",
            amount_rupees="25.50",
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

    def test_valid_offline_payment_is_recorded(self):
        verified, signed = self.create_verified_payment()

        result = record_verified_authorization(
            verification_result=verified,
            signed_authorization=signed,
            database_path=self.ledger_path,
        )

        self.assertEqual(result["status"], "accepted_locally")
        self.assertEqual(result["amount_paise"], 2550)
        self.assertEqual(
            result["ledger_status"],
            "pending_reconciliation",
        )

        records = list_offline_payments(
            database_path=self.ledger_path,
        )

        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["amount_paise"], 2550)

    def test_modified_merchant_request_is_rejected(self):
        signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id="MERCHANT001",
            amount_rupees="25.50",
        )

        tampered_request = copy.deepcopy(signed_request)
        tampered_request["request"]["amount_paise"] = 100

        with self.assertRaises(ValueError):
            verify_payment_request(
                signed_request=tampered_request,
                trusted_merchant_public_key=self.merchant["public_key"],
            )

    def test_authorization_for_wrong_amount_is_rejected(self):
        signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id="MERCHANT001",
            amount_rupees="25.50",
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

        tampered_authorization = copy.deepcopy(signed_authorization)
        tampered_authorization["authorization"]["amount_paise"] = 100

        with self.assertRaises(ValueError):
            verify_customer_authorization(
                signed_authorization=tampered_authorization,
                verified_request=verified_request,
                trusted_customer_public_key=self.customer["public_key"],
            )

    def test_authorization_cannot_outlive_merchant_request(self):
        signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id="MERCHANT001",
            amount_rupees="25.50",
            ttl_seconds=60,
        )
        verified_request = verify_payment_request(
            signed_request=signed_request,
            trusted_merchant_public_key=self.merchant["public_key"],
        )
        signed_authorization = create_customer_authorization(
            customer_identity=self.customer,
            customer_user_id="CUSTOMER001",
            verified_request=verified_request,
            ttl_seconds=900,
        )

        self.assertLessEqual(
            signed_authorization["authorization"]["expires_at"],
            verified_request["request"]["expires_at"],
        )

    def test_authorization_rejected_after_merchant_request_expires(self):
        signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id="MERCHANT001",
            amount_rupees="25.50",
            ttl_seconds=60,
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

        with self.assertRaisesRegex(ValueError, "merchant payment request has expired"):
            verify_customer_authorization(
                signed_authorization=signed_authorization,
                verified_request=verified_request,
                trusted_customer_public_key=self.customer["public_key"],
                now=verified_request["request"]["expires_at"],
            )

    def test_expired_authorization_is_rejected_when_recorded(self):
        verified, signed = self.create_verified_payment()
        expiry = signed["authorization"]["expires_at"]

        with patch("offline.offline_ledger.time.time", return_value=expiry):
            with self.assertRaisesRegex(ValueError, "authorization has expired"):
                record_verified_authorization(
                    verification_result=verified,
                    signed_authorization=signed,
                    database_path=self.ledger_path,
                )

        self.assertEqual(
            list_offline_payments(database_path=self.ledger_path),
            [],
        )

    def test_duplicate_authorization_is_rejected(self):
        verified, signed = self.create_verified_payment()

        record_verified_authorization(
            verification_result=verified,
            signed_authorization=signed,
            database_path=self.ledger_path,
        )

        with self.assertRaises(ValueError):
            record_verified_authorization(
                verification_result=verified,
                signed_authorization=signed,
                database_path=self.ledger_path,
            )

        records = list_offline_payments(
            database_path=self.ledger_path,
        )

        self.assertEqual(len(records), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)