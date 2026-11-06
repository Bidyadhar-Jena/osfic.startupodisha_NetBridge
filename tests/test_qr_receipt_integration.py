import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app as netbridge_app
import database
from offline.offline_qr import create_qr_payload, parse_qr_payload
from offline.offline_receipt import create_payment_receipt


class TwoQrReceiptIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = str(Path(self.temp_dir.name) / "netbridge-test.db")
        self.db_patch = patch.object(database, "DATABASE", self.db_path)
        self.db_patch.start()
        database.initialize_database()
        self.client = netbridge_app.app.test_client()

        with patch.object(
            netbridge_app,
            "get_or_create_identity",
            return_value={"device_id": "MERCHANT-DEMO-DEVICE", "public_key": "unused"},
        ):
            response = self.client.post(
                "/api/offline/merchant/request",
                json={"merchant_id": "MERCHANT001", "pin": "5678", "amount": "25.50"},
            )
        self.assertEqual(response.status_code, 200, response.get_json())
        self.merchant_qr = response.get_json()["qr_data"]
        self.request = parse_qr_payload(self.merchant_qr)["data"]["request"]
        self.receipt = create_payment_receipt(self.request, "CUSTOMER001")
        self.customer_qr = create_qr_payload("payment_receipt", {"receipt": self.receipt})
        self.balances_before = (
            database.get_wallet_balance("CUSTOMER001"),
            database.get_wallet_balance("MERCHANT001"),
        )

    def tearDown(self):
        self.db_patch.stop()
        self.temp_dir.cleanup()

    def _accept(self, customer_qr=None):
        return self.client.post(
            "/api/offline/merchant/accept",
            json={
                "merchant_id": "MERCHANT001",
                "pin": "5678",
                "merchant_qr": self.merchant_qr,
                "customer_qr": customer_qr or self.customer_qr,
            },
        )

    def test_two_qr_receipt_is_recorded_once_without_wallet_transfer(self):
        response = self._accept()
        self.assertEqual(response.status_code, 200, response.get_json())
        body = response.get_json()
        self.assertEqual(body["payment_status"], "accepted_for_simulation_review")
        self.assertEqual(body["settlement_status"], "pending_reconciliation")

        history = self.client.get("/api/wallets/MERCHANT001/transactions").get_json()["transactions"]
        saved = [item for item in history if item.get("transaction_id") == self.receipt["receipt_id"]]
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["status"], "accepted_for_simulation_review")
        self.assertEqual(saved[0]["settlement_status"], "pending_reconciliation")
        self.assertEqual(
            (database.get_wallet_balance("CUSTOMER001"), database.get_wallet_balance("MERCHANT001")),
            self.balances_before,
        )

        replay = self._accept()
        self.assertEqual(replay.status_code, 409)

    def test_mismatched_receipt_is_rejected_without_consuming_request(self):
        tampered = dict(self.receipt)
        tampered["amount_paise"] += 1
        tampered_qr = create_qr_payload("payment_receipt", {"receipt": tampered})
        rejected = self._accept(tampered_qr)
        self.assertEqual(rejected.status_code, 400)

        accepted = self._accept()
        self.assertEqual(accepted.status_code, 200, accepted.get_json())


if __name__ == "__main__":
    unittest.main(verbosity=2)
