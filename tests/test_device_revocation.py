import unittest
import tempfile
import os
import database


class TestDeviceRevocation(unittest.TestCase):

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(
            suffix=".db", delete=False
        )
        self.temp_db.close()

        self.original_db = database.DATABASE
        database.DATABASE = self.temp_db.name
        database.initialize_database()

    def tearDown(self):
        database.DATABASE = self.original_db

        if os.path.exists(self.temp_db.name):
            os.remove(self.temp_db.name)

    def test_revoke_missing_device(self):
        result = database.revoke_trusted_device(
            "nonexistent-device"
        )

        self.assertNotEqual(
            result.get("status"), "success"
        )

    def test_revoke_untrusted_device(self):
        result = database.revoke_trusted_device(
            "unregistered-device"
        )

        self.assertNotEqual(
            result.get("status"), "success"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)