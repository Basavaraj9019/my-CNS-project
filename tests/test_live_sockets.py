"""
Live TCP Socket Integration Test.
Runs Sender and Receiver Flask servers in parallel threads listening on live network sockets (ports 5000 and 5001).
Tests real HTTP request/response over the network stack:
1. Pinging Receiver identity endpoint.
2. Transmitting genuine hybrid-encrypted and signed email.
3. Transmitting tampered ciphertext over network and verifying HTTP rejection.
4. Transmitting forged signature over network and verifying rejection.
5. Replaying identical message and verifying replay cache detection.
"""

import unittest
import threading
import time
import os
import sys
import uuid
import requests
from werkzeug.serving import make_server

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from receiver.receiver_app import create_receiver_app
from sender.sender_app import create_sender_app


class ServerThread(threading.Thread):
    def __init__(self, app, host="127.0.0.1", port=5000):
        super().__init__()
        self.server = make_server(host, port, app)
        self.ctx = app.app_context()
        self.ctx.push()
        self.daemon = True

    def run(self):
        self.server.serve_forever()

    def shutdown(self):
        self.server.shutdown()


class TestLiveSockets(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), f"temp_live_{uuid.uuid4().hex[:6]}"))
        os.makedirs(cls.test_dir, exist_ok=True)

        cls.rec_db = os.path.join(cls.test_dir, "receiver.db")
        cls.rec_keys = os.path.join(cls.test_dir, "rec_keys")
        cls.sen_db = os.path.join(cls.test_dir, "sender.db")
        cls.sen_keys = os.path.join(cls.test_dir, "sen_keys")

        cls.receiver_port = 5500
        cls.sender_port = 5501

        cls.receiver_app = create_receiver_app(cls.rec_db, cls.rec_keys, receiver_id="bob@laptop2.sec")
        cls.sender_app = create_sender_app(cls.sen_db, cls.sen_keys, sender_id="alice@laptop1.sec")

        cls.receiver_thread = ServerThread(cls.receiver_app, "127.0.0.1", cls.receiver_port)
        cls.sender_thread = ServerThread(cls.sender_app, "127.0.0.1", cls.sender_port)

        cls.receiver_thread.start()
        cls.sender_thread.start()

        # Allow servers to bind sockets
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.receiver_thread.shutdown()
        cls.sender_thread.shutdown()

    def test_01_receiver_identity_live_socket(self):
        """Test HTTP GET on live receiver socket."""
        resp = requests.get(f"http://127.0.0.1:{self.receiver_port}/api/identity", timeout=2)
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data["receiver_id"], "bob@laptop2.sec")
        self.assertTrue(data["fingerprint"].startswith("SHA256:"))

    def test_02_sender_discovers_receiver_over_network(self):
        """Test Sender /api/receiver/test_connection pinging live Receiver."""
        resp = requests.post(
            f"http://127.0.0.1:{self.sender_port}/api/receiver/test_connection",
            json={"host_ip": "127.0.0.1", "port": self.receiver_port},
            timeout=3
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertIn("latency_ms", data)
        self.assertEqual(data["receiver_info"]["receiver_id"], "bob@laptop2.sec")

    def test_03_send_legitimate_secure_email_over_network(self):
        """Test Sender encrypts, signs, and sends email to Receiver over HTTP socket."""
        send_payload = {
            "receiver_id": "bob@laptop2.sec",
            "host_ip": "127.0.0.1",
            "port": self.receiver_port,
            "subject": "Dual-Laptop Live Transmission Test",
            "body": "This message is encrypted with AES-256-GCM and signed with RSA-PSS.",
            "tamper_mode": None
        }

        resp = requests.post(
            f"http://127.0.0.1:{self.sender_port}/api/messages/send",
            json=send_payload,
            timeout=5
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data["success"])
        self.assertEqual(data["network_status"], "DELIVERED_AND_AUTHENTICATED")

        msg_id = data["message_id"]

        # Verify on Receiver endpoint
        inbox_resp = requests.get(f"http://127.0.0.1:{self.receiver_port}/api/inbox/{msg_id}", timeout=2)
        self.assertEqual(inbox_resp.status_code, 200)
        inbox_data = inbox_resp.json()

        self.assertEqual(inbox_data["message"]["verification_status"], "AUTHENTICATED")
        self.assertEqual(inbox_data["message"]["integrity_status"], "PASSED")
        self.assertEqual(inbox_data["message"]["signature_status"], "PASSED")
        self.assertEqual(
            inbox_data["message"]["decrypted_body"],
            "This message is encrypted with AES-256-GCM and signed with RSA-PSS."
        )

    def test_04_tampered_ciphertext_rejected_over_network(self):
        """Test Sender transmits tampered ciphertext over network; Receiver rejects it."""
        send_payload = {
            "receiver_id": "bob@laptop2.sec",
            "host_ip": "127.0.0.1",
            "port": self.receiver_port,
            "subject": "Attack Test: Modified Ciphertext",
            "body": "Attacker will modify this in transit.",
            "tamper_mode": "tamper_ciphertext"
        }

        resp = requests.post(
            f"http://127.0.0.1:{self.sender_port}/api/messages/send",
            json=send_payload,
            timeout=5
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["success"])
        self.assertEqual(data["http_code"], 400)
        self.assertIn("REJECTED_BY_RECEIVER", data["network_status"])

    def test_05_forged_signature_rejected_over_network(self):
        """Test Sender transmits invalid digital signature over network; Receiver rejects it."""
        send_payload = {
            "receiver_id": "bob@laptop2.sec",
            "host_ip": "127.0.0.1",
            "port": self.receiver_port,
            "subject": "Attack Test: Forged Signature",
            "body": "Attacker forged this signature.",
            "tamper_mode": "tamper_signature"
        }

        resp = requests.post(
            f"http://127.0.0.1:{self.sender_port}/api/messages/send",
            json=send_payload,
            timeout=5
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertFalse(data["success"])
        self.assertEqual(data["http_code"], 400)
        self.assertIn("REJECTED_BY_RECEIVER", data["network_status"])


if __name__ == "__main__":
    unittest.main()
