import unittest
from unittest.mock import patch
import app as netbridge


class TestAuthenticatorEnrollment(unittest.TestCase):

    def setUp(self):
        netbridge.app.config["TESTING"] = True
        self.client = netbridge.app.test_client()

    def test_enrollment_endpoint_exists(self):
        response = self.client.post(
            "/api/authenticator/enroll",
            json={}
        )

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.get_json()["status"], "error")

    def test_enrollment_returns_square_qr_module_grid(self):
        with patch.object(netbridge, "verify_wallet_pin", return_value=True), \
             patch.object(netbridge, "is_totp_enabled", return_value=False), \
             patch.object(netbridge, "begin_totp_enrollment", return_value="JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"):
            response = self.client.post(
                "/api/authenticator/enroll",
                json={"user_id": "CUSTOMER001", "pin": "1234"},
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        matrix = response.get_json()["qr_matrix"]
        self.assertGreater(len(matrix), 0)
        self.assertEqual(len(matrix), len(matrix[0]))
        self.assertTrue(all(len(row) == len(matrix) and set(row) <= {"0", "1"} for row in matrix))


if __name__ == "__main__":
    unittest.main()
