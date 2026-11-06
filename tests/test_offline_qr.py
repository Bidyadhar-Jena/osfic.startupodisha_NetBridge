# test_offline_qr.py

import json
import tempfile
import unittest
from pathlib import Path

from authenticator.identity import generate_identity
from offline.offline_protocol import create_payment_request
from offline.offline_qr import (
    create_qr_payload,
    parse_qr_payload,
    create_qr_image,
    PROTOCOL_VERSION,
    SIMULATION_MODE,
)


class OfflineQRTests(unittest.TestCase):

    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.output_path = (
            Path(self.temp_directory.name) / "payment_request.png"
        )

        self.merchant = generate_identity()

        self.signed_request = create_payment_request(
            merchant_identity=self.merchant,
            merchant_user_id="MERCHANT001",
            amount_rupees="25.50",
        )

    def tearDown(self):
        self.temp_directory.cleanup()

    def test_payment_request_payload_round_trip(self):
        encoded = create_qr_payload(
            payload_type="payment_request",
            signed_data=self.signed_request,
        )

        parsed = parse_qr_payload(encoded)

        self.assertEqual(parsed["protocol"], PROTOCOL_VERSION)
        self.assertEqual(parsed["mode"], SIMULATION_MODE)
        self.assertEqual(parsed["type"], "payment_request")
        self.assertEqual(parsed["data"], self.signed_request)

    def test_payment_receipt_payload_round_trip(self):
        receipt = {
            "receipt": {
                "receipt_id": "RECEIPT-DEMO-001",
                "request_id": "REQUEST-DEMO-001",
                "customer_user_id": "CUSTOMER001",
                "merchant_user_id": "MERCHANT001",
                "amount_paise": 2550,
                "currency": "INR",
                "approved": True,
            }
        }

        encoded = create_qr_payload(
            payload_type="payment_receipt",
            signed_data=receipt,
        )
        parsed = parse_qr_payload(encoded)

        self.assertEqual(parsed["type"], "payment_receipt")
        self.assertEqual(parsed["data"], receipt)

    def test_payment_receipt_requires_receipt_object(self):
        payload = {
            "protocol": PROTOCOL_VERSION,
            "mode": SIMULATION_MODE,
            "type": "payment_receipt",
            "data": {},
        }

        with self.assertRaises(ValueError):
            parse_qr_payload(json.dumps(payload))

    def test_qr_image_is_created(self):
        image_path = create_qr_image(
            payload_type="payment_request",
            signed_data=self.signed_request,
            output_path=self.output_path,
        )

        self.assertTrue(Path(image_path).exists())
        self.assertGreater(Path(image_path).stat().st_size, 0)

    def test_invalid_json_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_qr_payload("this is not valid JSON")

    def test_unknown_protocol_is_rejected(self):
        payload = {
            "protocol": "unknown-version",
            "mode": SIMULATION_MODE,
            "type": "payment_request",
            "data": self.signed_request,
        }

        with self.assertRaises(ValueError):
            parse_qr_payload(json.dumps(payload))

    def test_unknown_payload_type_is_rejected(self):
        payload = {
            "protocol": PROTOCOL_VERSION,
            "mode": SIMULATION_MODE,
            "type": "unknown_type",
            "data": {},
        }

        with self.assertRaises(ValueError):
            parse_qr_payload(json.dumps(payload))

    def test_oversized_payload_is_rejected(self):
        oversized_text = "x" * 20_001

        with self.assertRaises(ValueError):
            parse_qr_payload(oversized_text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
