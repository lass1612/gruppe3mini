import tempfile
import unittest
from pathlib import Path

from database import Database
from scanner import validate_cidr


class CoreTests(unittest.TestCase):
    def test_cidr_validation(self):
        self.assertEqual(validate_cidr("192.168.2.17/24"), "192.168.2.0/24")
        with self.assertRaises(ValueError):
            validate_cidr("10.0.0.0/8")

    def test_parameterized_database_crud(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = Database(Path(tmp) / "test.db")
            # A SQL-looking name must be stored as ordinary text, not executed.
            db.upsert_reservation(
                {
                    "ip": "192.168.2.10",
                    "name": "Printer'); DROP TABLE reservations; --",
                    "mac": "AA:BB:CC:DD:EE:FF",
                    "owner": "Test",
                    "note": "SQL injection test",
                }
            )
            rows = db.list_reservations()
            self.assertEqual(len(rows), 1)
            self.assertIn("DROP TABLE", rows[0]["name"])
            self.assertTrue(db.delete_reservation("192.168.2.10"))
            self.assertEqual(db.list_reservations(), [])


if __name__ == "__main__":
    unittest.main()
