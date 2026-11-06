import unittest
import time

from offline.offline_receipt import create_payment_receipt, validate_payment_receipt


class OfflineReceiptTests(unittest.TestCase):
    def setUp(self):
        now = int(time.time())
        self.request = {
            "request_id": "req-001", "nonce": "nonce-001",
            "merchant_user_id": "MERCHANT001", "merchant_device_id": "merchant-device",
            "amount_paise": 2550, "currency": "INR",
            "created_at": now, "expires_at": now + 300,
        }
        self.now = now + 1
        self.receipt = create_payment_receipt(self.request, "CUSTOMER001", now=self.now)

    def test_create_and_validate_receipt(self):
        result = validate_payment_receipt(self.receipt, self.request, now=self.now + 1)
        self.assertTrue(result["valid"])
        self.assertEqual(result["amount_paise"], 2550)

    def test_amount_tampering_is_rejected(self):
        altered = dict(self.receipt, amount_paise=5000)
        with self.assertRaises(ValueError):
            validate_payment_receipt(altered, self.request, now=self.now + 1)

    def test_wrong_request_is_rejected(self):
        other = dict(self.request, request_id="req-002")
        with self.assertRaises(ValueError):
            validate_payment_receipt(self.receipt, other, now=self.now + 1)

    def test_expired_receipt_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_payment_receipt(self.receipt, self.request, now=self.receipt["expires_at"])

    def test_unapproved_receipt_is_rejected(self):
        altered = dict(self.receipt, approved=False)
        with self.assertRaises(ValueError):
            validate_payment_receipt(altered, self.request, now=self.now + 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
