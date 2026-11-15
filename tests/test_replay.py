"""
Replay Protection Test Suite.
Validates defenses against duplicate message replays and expired timestamps.
"""

import unittest
import os
import sys
import uuid
from datetime import datetime, timezone, timedelta

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sender.sender_crypto import SenderCryptoService
from receiver.receiver_crypto import ReceiverCryptoService
from database import ReceiverDatabase


class TestReplayProtection(unittest.TestCase):

    def setUp(self):
        self.temp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), f"temp_replay_{uuid.uuid4().hex[:8]}"))
        os.makedirs(self.temp_dir, exist_ok=True)
        self.db_path = os.path.join(self.temp_dir, "test_receiver.db")

        self.db = ReceiverDatabase(self.db_path)
        self.sender = SenderCryptoService(
            keys_dir=os.path.join(self.temp_dir, "sender_keys"),
            sender_id="alice@laptop1.sec"
        )
        self.receiver = ReceiverCryptoService(
            keys_dir=os.path.join(self.temp_dir, "receiver_keys"),
            receiver_id="bob@laptop2.sec"
        )
        self.rec_pub = self.receiver.get_public_identity()["public_key_pem"]

    def test_replay_attack_rejected(self):
        """Test that re-sending the same message_id is caught and rejected."""
        envelope, _ = self.sender.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=self.rec_pub,
            subject="One-Time Authentication Token",
            message_body="Token: 849204"
        )

        # First arrival: legitimate
        is_replayed_1 = self.db.is_message_replayed(envelope.message_id)
        self.assertFalse(is_replayed_1)

        result_1 = self.receiver.process_incoming_envelope(envelope, is_replayed=is_replayed_1)
        self.assertTrue(result_1["success"])

        # Cache in replay database
        self.db.register_replay_cache(envelope.message_id, envelope.sender_id, envelope.timestamp)

        # Second arrival: replay attack!
        is_replayed_2 = self.db.is_message_replayed(envelope.message_id)
        self.assertTrue(is_replayed_2)

        result_2 = self.receiver.process_incoming_envelope(envelope, is_replayed=is_replayed_2)
        self.assertFalse(result_2["success"])
        self.assertEqual(result_2["verification_status"], "REPLAY_DETECTED")
        self.assertIn("REPLAY ATTACK DETECTED", result_2["error_message"])

    def test_expired_timestamp_rejected(self):
        """Test that a message with an expired timestamp (e.g. 1 hour old) is rejected."""
        envelope, _ = self.sender.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=self.rec_pub,
            subject="Delayed Transmission",
            message_body="Test expired timestamp."
        )

        # Backdate timestamp to 1 hour ago
        old_time = datetime.now(timezone.utc) - timedelta(hours=1)
        envelope.timestamp = old_time.isoformat()

        result = self.receiver.process_incoming_envelope(envelope, is_replayed=False)
        self.assertFalse(result["success"])
        self.assertEqual(result["verification_status"], "TIMESTAMP_EXPIRED")


if __name__ == "__main__":
    unittest.main()
