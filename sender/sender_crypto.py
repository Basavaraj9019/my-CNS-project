"""
Sender Cryptography Service.
Handles Sender RSA keypair management, message SHA-256 hashing,
RSA-PSS digital signing, AES-256-GCM payload encryption, and RSA-OAEP session key encapsulation.
"""

import os
import sys
from typing import Dict, Any, Optional, Tuple

# Ensure project root is accessible
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto import (
    load_or_create_keypair,
    export_public_key_pem,
    load_public_key_pem,
    compute_public_key_fingerprint,
    compute_sha256_hex,
    sign_data,
    hybrid_encrypt
)
from shared import SecureMessageEnvelope, compute_aad


class SenderCryptoService:
    """
    Manages sender cryptographic lifecycle:
    - RSA-2048/3072 key storage (private key strictly local).
    - Hybrid encryption and digital signature generation.
    """

    def __init__(self, keys_dir: str, sender_id: str = "alice@laptop1.sec", key_size: int = 2048):
        self.keys_dir = keys_dir
        self.sender_id = sender_id
        self.key_size = key_size
        self.private_key, self.public_key, self.fingerprint = load_or_create_keypair(
            directory=keys_dir,
            prefix="sender",
            key_size=key_size
        )

    def get_public_identity(self) -> Dict[str, Any]:
        """Returns non-sensitive public identity credentials for distribution."""
        return {
            "sender_id": self.sender_id,
            "public_key_pem": export_public_key_pem(self.public_key).decode('utf-8'),
            "fingerprint": self.fingerprint,
            "key_size": self.key_size,
            "algorithm": f"RSA-{self.key_size} (OAEP/PSS)"
        }

    def prepare_secure_envelope(
        self,
        receiver_id: str,
        receiver_public_key_pem: str,
        subject: str,
        message_body: str,
        tamper_mode: Optional[str] = None
    ) -> Tuple[SecureMessageEnvelope, Dict[str, Any]]:
        """
        Creates and packages a secure email envelope using hybrid cryptography and digital signatures:
        1. Encodes body to UTF-8.
        2. Computes SHA-256 digest of plaintext body.
        3. Signs plaintext body using Sender's RSA private key (RSA-PSS with SHA-256).
        4. Loads receiver's RSA public key.
        5. Generates ephemeral 256-bit AES key and 96-bit nonce.
        6. Encrypts body using AES-256-GCM with Associated Authenticated Data (AAD).
        7. Encapsulates AES key with RSA-OAEP using receiver's public key.
        8. Assembles wire envelope.
        9. Optional: applies intentional tampering if requested by Security Testing Lab.

        Returns:
            (envelope: SecureMessageEnvelope, telemetry: Dict[str, Any])
        """
        body_bytes = message_body.encode('utf-8')
        sha256_hash_hex = compute_sha256_hex(body_bytes)

        # Step 1: RSA-PSS Digital Signature of Plaintext
        digital_signature = sign_data(body_bytes, self.private_key)

        # Step 2: Load receiver's public key
        receiver_pub_key = load_public_key_pem(receiver_public_key_pem.encode('utf-8'))

        # Prepare envelope metadata
        envelope = SecureMessageEnvelope(
            sender_id=self.sender_id,
            receiver_id=receiver_id,
            subject=subject,
            encrypted_session_key=b"",  # Placeholder
            nonce=b"",
            ciphertext=b"",
            auth_tag=b"",
            digital_signature=digital_signature,
            sha256_hash_hex=sha256_hash_hex,
            sender_public_key_pem=export_public_key_pem(self.public_key).decode('utf-8'),
            sender_fingerprint=self.fingerprint
        )

        # Step 3: Compute Associated Authenticated Data (AAD)
        aad = envelope.get_aad()

        # Step 4: Hybrid Encryption (AES-256-GCM + RSA-OAEP)
        enc_result = hybrid_encrypt(
            plaintext=body_bytes,
            receiver_public_key=receiver_pub_key,
            associated_data=aad
        )

        envelope.encrypted_session_key = enc_result["encrypted_session_key"]
        envelope.nonce = enc_result["nonce"]
        envelope.ciphertext = enc_result["ciphertext"]
        envelope.auth_tag = enc_result["auth_tag"]

        # Cryptographic process telemetry for UI visualization
        telemetry = {
            "plaintext_length": len(body_bytes),
            "sha256_hash": sha256_hash_hex,
            "session_key_hex": enc_result["session_key"].hex(),
            "encrypted_session_key_len": len(enc_result["encrypted_session_key"]),
            "nonce_hex": enc_result["nonce"].hex(),
            "ciphertext_len": len(enc_result["ciphertext"]),
            "auth_tag_hex": enc_result["auth_tag"].hex(),
            "signature_len": len(digital_signature),
            "sender_fingerprint": self.fingerprint,
            "tamper_mode_applied": tamper_mode or "NONE"
        }

        # Step 5: Handle intentional security test tampering if requested
        if tamper_mode == "tamper_ciphertext":
            ct = envelope.ciphertext
            # Invert first byte
            envelope.ciphertext = bytes([ct[0] ^ 0x01]) + ct[1:]
        elif tamper_mode == "tamper_signature":
            sig = envelope.digital_signature
            # Invert first byte
            envelope.digital_signature = bytes([sig[0] ^ 0xFF]) + sig[1:]
        elif tamper_mode == "tamper_subject":
            envelope.subject = envelope.subject + " [MITM MODIFIED]"
        elif tamper_mode == "tamper_sender_key":
            # Spoof sender by swapping with a rogue key
            from crypto import generate_rsa_keypair
            _, rogue_pub = generate_rsa_keypair(2048)
            envelope.sender_public_key_pem = export_public_key_pem(rogue_pub).decode('utf-8')

        return envelope, telemetry
