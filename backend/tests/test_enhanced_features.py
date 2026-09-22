import os
import sys
import unittest

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from app import extract_bulk_messages, extract_text_from_bytes


class EnhancedFeaturesTests(unittest.TestCase):
    def test_extract_bulk_messages_from_text(self):
        payload = "Hello there\nUrgent account update needed\n"
        result = extract_bulk_messages(payload, "text/plain")
        self.assertEqual(result, ["Hello there", "Urgent account update needed"])

    def test_extract_bulk_messages_from_csv(self):
        payload = "message\nHello world\nClick here now"
        result = extract_bulk_messages(payload, "text/csv")
        self.assertEqual(result, ["Hello world", "Click here now"])

    def test_extract_text_from_text_bytes(self):
        payload = b"Urgent account update needed\nClick now"
        text, error = extract_text_from_bytes(payload, "notes.txt")
        self.assertEqual(text, "Urgent account update needed\nClick now")
        self.assertIsNone(error)

    def test_extract_text_from_csv_bytes(self):
        payload = b"message\nHello there\nClaim your prize"
        text, error = extract_text_from_bytes(payload, "messages.csv")
        self.assertEqual(text, "Hello there\nClaim your prize")
        self.assertIsNone(error)


if __name__ == "__main__":
    unittest.main()
