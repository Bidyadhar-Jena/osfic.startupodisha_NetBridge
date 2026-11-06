import unittest

import app as netbridge_app
from database import get_wallet_balance


class TestLegacyPaymentDisabled(unittest.TestCase):

    def setUp(self):
        netbridge_app.app.config["TESTING"] = True
        self.client = netbridge_app.app.test_client()

    def test_legacy_payment_returns_gone(self):
        response = self.client.post(
            "/api/pay",
            json={
                "sender_id": "CUSTOMER001",
                "receiver_id": "MERCHANT001",
                "pin": "1234",
                "amount": "10.00"
            }
        )

        self.assertEqual(response.status_code, 410)

        data = response.get_json()

        self.assertEqual(data["status"], "error")
        self.assertEqual(
            data["code"],
            "LEGACY_PAYMENT_DISABLED"
        )
        self.assertFalse(data["real_payments_enabled"])

    def test_legacy_payment_does_not_change_balances(self):
        sender_before = get_wallet_balance("CUSTOMER001")
        receiver_before = get_wallet_balance("MERCHANT001")

        response = self.client.post(
            "/api/pay",
            json={
                "sender_id": "CUSTOMER001",
                "receiver_id": "MERCHANT001",
                "pin": "1234",
                "amount": "10.00"
            }
        )

        sender_after = get_wallet_balance("CUSTOMER001")
        receiver_after = get_wallet_balance("MERCHANT001")

        self.assertEqual(response.status_code, 410)
        self.assertEqual(sender_before, sender_after)
        self.assertEqual(receiver_before, receiver_after)


if __name__ == "__main__":
    unittest.main(verbosity=2)