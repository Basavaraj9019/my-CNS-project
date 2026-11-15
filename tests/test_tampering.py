"""
Security Attack & Tamper Detection Test Suite.
Validates defenses against:
1. Ciphertext manipulation (AES-GCM tag mismatch).
2. Forged/modified digital signatures (RSA-PSS verification failure).
3. Header modification in transit (AAD verification failure).
4. Public-key substitution / Sender impersonation.
5. Unauthorized decryption attempts.
"""

import unittest
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto import (
    generate_rsa_keypair,
    export_public_key_pem,
    compute_public_key_fingerprint,
    compute_sha256_hex
)
from shared import SecureMessageEnvelope
from sender.sender_crypto import SenderCryptoService
from receiver.receiver_crypto import ReceiverCryptoService


class TestSecurityAndTamperAttacks(unittest.TestCase):

    def setUp(self):
        self.temp_sender_keys = os.path.abspath(os.path.join(os.path.dirname(__file__), "temp_sender_keys"))
        self.temp_receiver_keys = os.path.abspath(os.path.join(os.path.dirname(__file__), "temp_receiver_keys"))
        os.makedirs(self.temp_sender_keys, exist_ok=True)
        os.makedirs(self.temp_receiver_keys, exist_ok=True)

        self.sender_crypto = SenderCryptoService(
            keys_dir=self.temp_sender_keys,
            sender_id="alice@laptop1.sec"
        )
        self.receiver_crypto = ReceiverCryptoService(
            keys_dir=self.temp_receiver_keys,
            receiver_id="bob@laptop2.sec"
        )

        self.receiver_identity = self.receiver_crypto.get_public_identity()
        self.trusted_sender_record = {
            "sender_id": self.sender_crypto.sender_id,
            "public_key_pem": export_public_key_pem(self.sender_crypto.public_key).decode('utf-8'),
            "fingerprint": self.sender_crypto.fingerprint
        }

    def test_normal_legitimate_flow(self):
        """Test legitimate message passes all 7 cryptographic checks."""
        envelope, telemetry = self.sender_crypto.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=self.receiver_identity["public_key_pem"],
            subject="Classified Budget Report",
            message_body="Net profit for Q4 reached $14.2M."
        )

        result = self.receiver_crypto.process_incoming_envelope(
            envelope=envelope,
            is_replayed=False,
            trusted_sender_record=self.trusted_sender_record
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["verification_status"], "AUTHENTICATED")
        self.assertEqual(result["integrity_status"], "PASSED")
        self.assertEqual(result["signature_status"], "PASSED")
        self.assertEqual(result["non_repudiation_status"], "PASSED")
        self.assertEqual(result["sender_trusted_status"], "TRUSTED_AND_VERIFIED")
        self.assertEqual(result["decrypted_body"], "Net profit for Q4 reached $14.2M.")

    def test_attack_ciphertext_tampering(self):
        """Test active eavesdropper modifying ciphertext in transit."""
        envelope, _ = self.sender_crypto.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=self.receiver_identity["public_key_pem"],
            subject="Wire Transfer",
            message_body="Transfer $1000 to Account A"
        )

        # Adversary flips 1 bit in ciphertext
        ct = bytearray(envelope.ciphertext)
        ct[0] ^= 0x01
        envelope.ciphertext = bytes(ct)

        result = self.receiver_crypto.process_incoming_envelope(
            envelope=envelope,
            is_replayed=False,
            trusted_sender_record=self.trusted_sender_record
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["verification_status"], "INTEGRITY_COMPROMISED")
        self.assertEqual(result["integrity_status"], "TAMPERED")
        self.assertIsNone(result["decrypted_body"])
        self.assertIn("AES-GCM", result["error_message"])

    def test_attack_signature_forgery(self):
        """Test active attacker forging or corrupting the RSA-PSS digital signature."""
        envelope, _ = self.sender_crypto.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=self.receiver_identity["public_key_pem"],
            subject="Executive Order",
            message_body="Authorize project deployment."
        )

        # Corrupt signature bytes
        sig = bytearray(envelope.digital_signature)
        sig[10] ^= 0xAA
        envelope.digital_signature = bytes(sig)

        result = self.receiver_crypto.process_incoming_envelope(
            envelope=envelope,
            is_replayed=False,
            trusted_sender_record=self.trusted_sender_record
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["verification_status"], "INVALID_SIGNATURE")
        self.assertEqual(result["signature_status"], "INVALID")
        self.assertEqual(result["non_repudiation_status"], "FAILED")
        self.assertIsNone(result["decrypted_body"])

    def test_attack_header_metadata_tampering(self):
        """Test attacker modifying Subject or metadata bound into AES-GCM Associated Data (AAD)."""
        envelope, _ = self.sender_crypto.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=self.receiver_identity["public_key_pem"],
            subject="Genuine Subject",
            message_body="Safe contents."
        )

        # In-transit attacker modifies subject line in cleartext header
        envelope.subject = "Tampered Subject By Adversary"

        result = self.receiver_crypto.process_incoming_envelope(
            envelope=envelope,
            is_replayed=False,
            trusted_sender_record=self.trusted_sender_record
        )

        # Should fail AES-GCM AAD verification!
        self.assertFalse(result["success"])
        self.assertEqual(result["verification_status"], "INTEGRITY_COMPROMISED")

    def test_attack_public_key_substitution(self):
        """Test attacker substituting sender public key with their own key (MITM impersonation)."""
        envelope, _ = self.sender_crypto.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=self.receiver_identity["public_key_pem"],
            subject="CEO Instruction",
            message_body="Wire bonus immediately."
        )

        # Rogue attacker generates keypair and replaces sender key and re-signs
        rogue_priv, rogue_pub = generate_rsa_keypair(2048)
        from crypto import sign_data
        rogue_sig = sign_data("Wire bonus immediately.".encode('utf-8'), rogue_priv)
        rogue_pub_pem = export_public_key_pem(rogue_pub).decode('utf-8')
        rogue_fp = compute_public_key_fingerprint(rogue_pub)

        envelope.sender_public_key_pem = rogue_pub_pem
        envelope.sender_fingerprint = rogue_fp
        envelope.digital_signature = rogue_sig

        result = self.receiver_crypto.process_incoming_envelope(
            envelope=envelope,
            is_replayed=False,
            trusted_sender_record=self.trusted_sender_record
        )

        # Receiver notices fingerprint does not match trusted sender address book!
        self.assertFalse(result["success"])
        self.assertEqual(result["verification_status"], "UNTRUSTED_KEY_SUBSTITUTION")
        self.assertEqual(result["sender_trusted_status"], "KEY_CHANGED_WARNING")

    def test_attack_unauthorized_recipient_decryption(self):
        """Test eavesdropper receiver trying to decrypt envelope destined for someone else."""
        envelope, _ = self.sender_crypto.prepare_secure_envelope(
            receiver_id="bob@laptop2.sec",
            receiver_public_key_pem=self.receiver_identity["public_key_pem"],
            subject="Private Note",
            message_body="Secret data."
        )

        # Eavesdropper with their own keypair
        eavesdropper = ReceiverCryptoService(
            keys_dir=os.path.join(self.temp_receiver_keys, "eavesdropper"),
            receiver_id="eve@attacker.sec"
        )

        result = eavesdropper.process_incoming_envelope(
            envelope=envelope,
            is_replayed=False,
            trusted_sender_record=self.trusted_sender_record
        )

        self.assertFalse(result["success"])
        self.assertEqual(result["verification_status"], "KEY_DECRYPTION_FAILED")
        self.assertIsNone(result["decrypted_body"])


if __name__ == "__main__":
    unittest.main()
