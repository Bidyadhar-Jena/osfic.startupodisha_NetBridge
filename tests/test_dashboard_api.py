import unittest
from unittest.mock import patch

import app as netbridge_app


class TestDashboardAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        netbridge_app.app.config["TESTING"] = True

    def setUp(self):
        self.client = netbridge_app.app.test_client()

    # 1. Dashboard loads successfully
    def test_dashboard_homepage(self):
        response = self.client.get("/")

        self.assertEqual(response.status_code, 200)

    def test_customer_page_loads_offline_store_before_main_script(self):
        response = self.client.get("/", base_url="http://10.0.0.2:5001")

        self.assertEqual(response.status_code, 200)
        offline_store = response.data.index(b"offline_store.js")
        customer_script = response.data.index(b"script.js")
        self.assertLess(offline_store, customer_script)
        self.assertIn(b"/static/offline_receipt_code.js?v=2", response.data)
        self.assertIn(b"/static/script.js?v=16", response.data)
        self.assertIn(b"customerReceiptCode", response.data)
        self.assertNotIn(b"customerReceiptQr", response.data)

    def test_merchant_page_uses_manual_code_without_receipt_scanner(self):
        response = self.client.get("/merchant")

        self.assertEqual(response.status_code, 200)
        self.assertIn(b"manualReceiptCode", response.data)
        self.assertIn(b"offline_receipt_code.js?v=2", response.data)
        self.assertNotIn(b"startMerchantCameraButton", response.data)
        self.assertNotIn(b"merchantReceiptUpload", response.data)

    def test_offline_credential_requires_correct_otp(self):
        with patch.object(netbridge_app, "verify_wallet_pin", return_value=True), \
             patch.object(netbridge_app, "verify_totp_for_reconnect", return_value=False) as verify_otp, \
             patch.object(netbridge_app, "get_totp_secret") as get_secret:
            response = self.client.post(
                "/api/authenticator/offline-credential",
                json={"user_id": "CUSTOMER001", "pin": "1234", "otp": "123456"},
            )

        self.assertEqual(response.status_code, 401)
        verify_otp.assert_called_once_with("CUSTOMER001", "123456")
        get_secret.assert_not_called()

    def test_offline_credential_returns_secret_after_pin_and_otp(self):
        with patch.object(netbridge_app, "verify_wallet_pin", return_value=True), \
             patch.object(netbridge_app, "verify_totp_for_reconnect", return_value=True), \
             patch.object(netbridge_app, "get_totp_secret", return_value="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"):
            response = self.client.post(
                "/api/authenticator/offline-credential",
                json={"user_id": "CUSTOMER001", "pin": "1234", "otp": "123456"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["offline_secret"], "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP")

    # 2. Health endpoint reports simulation mode
    def test_health_endpoint(self):
        response = self.client.get("/api/health")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["application"], "NetBridge")
        self.assertEqual(data["status"], "running")
        self.assertEqual(data["mode"], "simulation_only")
        self.assertFalse(data["real_payments_enabled"])

    # 3. Wallet list returns a valid response
    def test_wallet_list(self):
        response = self.client.get("/api/wallets")

        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.get_json(), list)

    # 4. Existing demo wallet can be retrieved
    def test_existing_wallet(self):
        response = self.client.get("/api/wallets/CUSTOMER001")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["user_id"], "CUSTOMER001")
        self.assertIn("balance_paise", data)
        self.assertIn("balance_rupees", data)

    # 5. Missing wallet returns 404
    def test_missing_wallet(self):
        response = self.client.get("/api/wallets/UNKNOWN_USER")

        self.assertEqual(response.status_code, 404)

        data = response.get_json()

        self.assertEqual(data["status"], "error")

    # 6. Missing wallet balance returns 404
    def test_missing_wallet_balance(self):
        response = self.client.get(
            "/api/wallets/UNKNOWN_USER/balance"
        )

        self.assertEqual(response.status_code, 404)

    # 7. Wallet transaction history rejects unknown wallet
    def test_missing_wallet_transaction_history(self):
        response = self.client.get(
            "/api/wallets/UNKNOWN_USER/transactions"
        )

        self.assertEqual(response.status_code, 404)

    # 8. Identity endpoint returns public identity
    def test_identity_endpoint(self):
        fake_identity = {
            "device_id": "TEST_DEVICE_123",
            "public_key": "TEST_PUBLIC_KEY"
        }

        with patch.object(
            netbridge_app,
            "get_or_create_identity",
            return_value=fake_identity
        ):
            response = self.client.get("/api/auth/identity")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["status"], "success")
        self.assertEqual(data["device_id"], "TEST_DEVICE_123")
        self.assertEqual(data["public_key"], "TEST_PUBLIC_KEY")

        self.assertNotIn("private_key", data)
        self.assertNotIn("private_seed", data)

    # 9. Authentication challenge rejects missing JSON
    def test_challenge_rejects_missing_json(self):
        response = self.client.post(
            "/api/auth/challenge",
            data="not-json",
            content_type="text/plain"
        )

        self.assertEqual(response.status_code, 400)

        data = response.get_json()

        self.assertEqual(data["status"], "error")

    # 10. Authentication challenge rejects missing device ID
    def test_challenge_rejects_missing_device_id(self):
        response = self.client.post(
            "/api/auth/challenge",
            json={}
        )

        self.assertEqual(response.status_code, 400)

    # 11. Untrusted devices cannot request a challenge
    def test_untrusted_device_cannot_request_challenge(self):
        with patch.object(
            netbridge_app,
            "is_device_trusted",
            return_value=False
        ):
            response = self.client.post(
                "/api/auth/challenge",
                json={"device_id": "UNTRUSTED_DEVICE"}
            )

        self.assertEqual(response.status_code, 403)

        data = response.get_json()

        self.assertEqual(data["status"], "error")

    # 12. Device registration rejects a missing JSON body
    def test_registration_rejects_missing_json(self):
        response = self.client.post(
            "/api/devices/register-local",
            data="invalid",
            content_type="text/plain"
        )

        self.assertEqual(response.status_code, 400)

    # 13. Device registration rejects a missing wallet ID
    def test_registration_rejects_missing_wallet_id(self):
        response = self.client.post(
            "/api/devices/register-local",
            json={"pin": "1234"}
        )

        self.assertEqual(response.status_code, 400)

    # 14. Device registration rejects an invalid PIN
    def test_registration_rejects_invalid_pin(self):
        response = self.client.post(
            "/api/devices/register-local",
            json={
                "owner_user_id": "CUSTOMER001",
                "pin": "12"
            }
        )

        self.assertEqual(response.status_code, 400)

    # 15. Trusted device listing returns the expected structure
    def test_trusted_device_list(self):
        with patch.object(
            netbridge_app,
            "list_trusted_devices",
            return_value=[
                {
                    "device_id": "DEVICE_TEST_1",
                    "owner_user_id": "CUSTOMER001",
                    "device_name": "Test Device",
                    "status": "trusted",
                    "created_at": "2026-01-01",
                    "updated_at": "2026-01-01",
                    "private_key": "SHOULD_NOT_BE_EXPOSED"
                }
            ]
        ):
            response = self.client.get("/api/devices/trusted")

        self.assertEqual(response.status_code, 200)

        data = response.get_json()

        self.assertEqual(data["status"], "success")
        self.assertEqual(data["count"], 1)

        device = data["devices"][0]

        self.assertEqual(device["device_id"], "DEVICE_TEST_1")
        self.assertEqual(device["status"], "trusted")
        self.assertNotIn("private_key", device)

    # 16. Revoking a nonexistent device returns 404
    def test_revoke_missing_device(self):
        with patch.object(
            netbridge_app,
            "get_trusted_device",
            return_value=None
        ):
            response = self.client.post(
                "/api/devices/DEVICE_DOES_NOT_EXIST/revoke"
            )

        self.assertEqual(response.status_code, 404)

    # The legacy single-scan endpoint is retired; payment uses a merchant QR and a typed confirmation code.
    def test_one_scan_customer_authorization_is_disabled(self):
        response = self.client.post(
            "/api/offline/customer/authorize",
            json={"customer_id": "CUSTOMER001", "pin": "1234"},
        )

        self.assertEqual(response.status_code, 410)
        self.assertIn("customer's manual confirmation code", response.get_json()["error"])

    # 20. Unknown API route returns 404
    def test_unknown_api_route(self):
        response = self.client.get("/api/this-route-does-not-exist")

        self.assertEqual(response.status_code, 404)


if __name__ == "__main__":
    unittest.main(verbosity=2)
