"""
End-to-End Network & Integration Test Suite.
Tests full HTTP communication, JSON wire protocol serialization,
API endpoints, and database state transitions.
"""

import unittest
import os
import sys
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sender.sender_app import create_sender_app
from receiver.receiver_app import create_receiver_app


class TestNetworkEndToEnd(unittest.TestCase):

    def setUp(self):
        self.temp_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "temp_e2e"))
        os.makedirs(self.temp_dir, exist_ok=True)

        self.sender_db = os.path.join(self.temp_dir, "sender.db")
        self.receiver_db = os.path.join(self.temp_dir, "receiver.db")
        self.sender_keys = os.path.join(self.temp_dir, "sender_keys")
        self.receiver_keys = os.path.join(self.temp_dir, "receiver_keys")

        self.receiver_app = create_receiver_app(
            db_path=self.receiver_db,
            keys_dir=self.receiver_keys,
            receiver_id="bob@laptop2.sec"
        )
        self.sender_app = create_sender_app(
            db_path=self.sender_db,
            keys_dir=self.sender_keys,
            sender_id="alice@laptop1.sec"
        )

        self.receiver_client = self.receiver_app.test_client()
        self.sender_client = self.sender_app.test_client()

    def test_receiver_identity_endpoint(self):
        """Test Receiver /api/identity endpoint returns valid public key and fingerprint."""
        resp = self.receiver_client.get("/api/identity")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["receiver_id"], "bob@laptop2.sec")
        self.assertTrue(data["fingerprint"].startswith("SHA256:"))
        self.assertIn("BEGIN PUBLIC KEY", data["public_key_pem"])

    def test_end_to_end_transmission_and_verification(self):
        """
        Tests complete E2E flow:
        1. Fetch Receiver's public key.
        2. Sender prepares encrypted and signed wire envelope.
        3. Transmit payload to Receiver's /api/messages/receive endpoint.
        4. Verify Receiver processes, verifies signature, decrypts, and records in database.
        5. Verify decrypted message is accessible via /api/inbox.
        """
        # Step 1: Fetch receiver public key
        rec_id_resp = self.receiver_client.get("/api/identity")
        rec_data = rec_id_resp.get_json()

        # Step 2: Use Sender's crypto service to prepare envelope
        from sender.sender_crypto import SenderCryptoService
        sender_crypto = SenderCryptoService(keys_dir=self.sender_keys, sender_id="alice@laptop1.sec")

        envelope, telemetry = sender_crypto.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=rec_data["public_key_pem"],
            subject="Project Deployment Plan",
            message_body="All security protocols pass. Ready for dual-laptop deployment."
        )

        # Step 3: Send wire JSON payload to Receiver
        payload = envelope.to_dict()
        resp = self.receiver_client.post(
            "/api/messages/receive",
            data=json.dumps(payload),
            content_type="application/json"
        )

        self.assertEqual(resp.status_code, 200)
        res_json = resp.get_json()
        self.assertTrue(res_json["received"])
        self.assertEqual(res_json["verification_status"], "AUTHENTICATED")

        # Step 4: Verify message in inbox
        inbox_resp = self.receiver_client.get("/api/inbox")
        inbox_data = inbox_resp.get_json()
        self.assertGreaterEqual(inbox_data["count"], 1)

        msg = inbox_data["messages"][0]
        self.assertEqual(msg["message_id"], envelope.message_id)
        self.assertEqual(msg["verification_status"], "AUTHENTICATED")

        # Step 5: Check detail view for decrypted body
        detail_resp = self.receiver_client.get(f"/api/inbox/{envelope.message_id}")
        detail_data = detail_resp.get_json()
        self.assertEqual(detail_data["message"]["decrypted_body"], "All security protocols pass. Ready for dual-laptop deployment.")
        self.assertEqual(detail_data["message"]["integrity_status"], "PASSED")
        self.assertEqual(detail_data["message"]["signature_status"], "PASSED")


if __name__ == "__main__":
    unittest.main()
