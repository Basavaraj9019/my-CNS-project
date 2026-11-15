"""
Unit Tests for Cryptographic Modules.
Tests RSA key management, AES-256-GCM authenticated encryption,
RSA-OAEP session key transport, RSA-PSS digital signatures,
and tamper detection.
"""

import unittest
import os
import sys

# Ensure project root is in python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto import (
    generate_rsa_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
    compute_public_key_fingerprint,
    generate_aes_key,
    generate_nonce,
    compute_sha256_hex,
    encrypt_aes_gcm,
    decrypt_aes_gcm,
    encrypt_session_key_rsa,
    decrypt_session_key_rsa,
    sign_data,
    verify_signature,
    hybrid_encrypt,
    hybrid_decrypt,
    IntegrityCompromisedError,
    KeyDecryptionError
)


class TestCryptoModules(unittest.TestCase):

    def setUp(self):
        # Generate sender and receiver test keypairs
        self.sender_priv, self.sender_pub = generate_rsa_keypair(key_size=2048)
        self.receiver_priv, self.receiver_pub = generate_rsa_keypair(key_size=2048)
        self.test_message = "CONFIDENTIAL: Financial Report & Encryption Test 2026".encode('utf-8')

    def test_key_serialization_and_fingerprints(self):
        """Test RSA PEM export, import, and SHA-256 fingerprint generation."""
        priv_pem = export_private_key_pem(self.sender_priv)
        pub_pem = export_public_key_pem(self.sender_pub)

        loaded_priv = load_private_key_pem(priv_pem)
        loaded_pub = load_public_key_pem(pub_pem)

        fp1 = compute_public_key_fingerprint(self.sender_pub)
        fp2 = compute_public_key_fingerprint(loaded_pub)

        self.assertEqual(fp1, fp2)
        self.assertTrue(fp1.startswith("SHA256:"))
        self.assertEqual(len(fp1.split(":")), 33)  # 'SHA256' + 32 byte pairs

    def test_aes_gcm_encryption_and_decryption(self):
        """Test AES-256-GCM symmetric encryption and authenticated decryption."""
        key = generate_aes_key()
        nonce = generate_nonce()
        aad = b"header_metadata_test"

        ciphertext, used_nonce, tag = encrypt_aes_gcm(self.test_message, key, nonce=nonce, associated_data=aad)
        decrypted = decrypt_aes_gcm(ciphertext, key, used_nonce, tag, associated_data=aad)

        self.assertEqual(self.test_message, decrypted)
        self.assertEqual(len(key), 32)
        self.assertEqual(len(used_nonce), 12)
        self.assertEqual(len(tag), 16)

    def test_aes_gcm_tamper_detection(self):
        """Test that altering a single bit in AES-GCM ciphertext fails authentication."""
        key = generate_aes_key()
        nonce = generate_nonce()
        ciphertext, used_nonce, tag = encrypt_aes_gcm(self.test_message, key, nonce=nonce)

        # Tamper with first byte of ciphertext
        tampered_ct = bytes([ciphertext[0] ^ 0xFF]) + ciphertext[1:]

        with self.assertRaises(IntegrityCompromisedError):
            decrypt_aes_gcm(tampered_ct, key, used_nonce, tag)

    def test_rsa_oaep_session_key_transport(self):
        """Test RSA-OAEP session key encryption and decryption."""
        session_key = generate_aes_key()
        encrypted_key = encrypt_session_key_rsa(session_key, self.receiver_pub)
        decrypted_key = decrypt_session_key_rsa(encrypted_key, self.receiver_priv)

        self.assertEqual(session_key, decrypted_key)

    def test_unauthorized_rsa_decryption_failure(self):
        """Test that unauthorized private key fails to decrypt session key."""
        session_key = generate_aes_key()
        encrypted_key = encrypt_session_key_rsa(session_key, self.receiver_pub)

        # Attacker keypair
        attacker_priv, _ = generate_rsa_keypair(key_size=2048)

        with self.assertRaises(KeyDecryptionError):
            decrypt_session_key_rsa(encrypted_key, attacker_priv)

    def test_rsa_pss_digital_signature_verification(self):
        """Test RSA-PSS digital signature generation and verification."""
        signature = sign_data(self.test_message, self.sender_priv)
        is_valid, msg = verify_signature(self.test_message, signature, self.sender_pub)

        self.assertTrue(is_valid)
        self.assertIn("VALID", msg)

    def test_digital_signature_tamper_detection(self):
        """Test that signature fails if data is altered or signature is forged."""
        signature = sign_data(self.test_message, self.sender_priv)

        # Alter message
        altered_message = self.test_message + b" [ALTERED]"
        is_valid, msg = verify_signature(altered_message, signature, self.sender_pub)
        self.assertFalse(is_valid)
        self.assertIn("INVALID", msg)

        # Wrong public key (impersonation attempt)
        is_valid_wrong_key, _ = verify_signature(self.test_message, signature, self.receiver_pub)
        self.assertFalse(is_valid_wrong_key)

    def test_end_to_end_hybrid_cryptography(self):
        """Test complete hybrid encryption and decryption pipeline."""
        aad = b"alice@laptop1 -> bob@laptop2"

        # Sender signs plaintext
        signature = sign_data(self.test_message, self.sender_priv)

        # Sender hybrid encrypts
        enc_result = hybrid_encrypt(self.test_message, self.receiver_pub, associated_data=aad)

        # Receiver hybrid decrypts
        dec_result = hybrid_decrypt(
            enc_result["encrypted_session_key"],
            enc_result["ciphertext"],
            enc_result["nonce"],
            enc_result["auth_tag"],
            self.receiver_priv,
            associated_data=aad
        )

        # Receiver verifies decrypted plaintext matches
        self.assertEqual(dec_result["plaintext"], self.test_message)

        # Receiver verifies signature
        is_valid, _ = verify_signature(dec_result["plaintext"], signature, self.sender_pub)
        self.assertTrue(is_valid)

        # Receiver verifies SHA-256 hash
        hash_check = compute_sha256_hex(dec_result["plaintext"])
        self.assertEqual(hash_check, enc_result["sha256_hash_hex"])


if __name__ == "__main__":
    unittest.main()
