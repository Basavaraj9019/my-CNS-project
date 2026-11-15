"""
Receiver Cryptography Service.
Handles Receiver RSA keypair management, message decryption, replay validation,
AEAD integrity verification, RSA-PSS signature verification, and trust evaluation.
"""

import os
import sys
from typing import Dict, Any, Tuple, Optional

# Ensure project root is accessible
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from crypto import (
    load_or_create_keypair,
    export_public_key_pem,
    load_public_key_pem,
    compute_public_key_fingerprint,
    compute_sha256_hex,
    decrypt_session_key_rsa,
    decrypt_aes_gcm,
    verify_signature,
    IntegrityCompromisedError,
    KeyDecryptionError
)
from shared import SecureMessageEnvelope


class ReceiverCryptoService:
    """
    Manages receiver cryptographic lifecycle:
    - RSA-2048/3072 key storage (private key strictly local).
    - Step-by-step hybrid verification and decryption pipeline.
    """

    def __init__(self, keys_dir: str, receiver_id: str = "bob@laptop2.sec", key_size: int = 2048):
        self.keys_dir = keys_dir
        self.receiver_id = receiver_id
        self.key_size = key_size
        self.private_key, self.public_key, self.fingerprint = load_or_create_keypair(
            directory=keys_dir,
            prefix="receiver",
            key_size=key_size
        )

    def get_public_identity(self) -> Dict[str, Any]:
        """Returns non-sensitive public identity credentials for distribution."""
        return {
            "receiver_id": self.receiver_id,
            "public_key_pem": export_public_key_pem(self.public_key).decode('utf-8'),
            "fingerprint": self.fingerprint,
            "key_size": self.key_size,
            "algorithm": f"RSA-{self.key_size} (OAEP/PSS)"
        }

    def process_incoming_envelope(
        self,
        envelope: SecureMessageEnvelope,
        is_replayed: bool,
        trusted_sender_record: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes the comprehensive cryptographic verification and decryption pipeline:
        1. Replay Protection: checks duplicate ID and timestamp window.
        2. Receiver Identity match check.
        3. Session Key Decryption: RSA-OAEP with Receiver's private key.
        4. Ciphertext Decryption & Authenticated Data check: AES-256-GCM.
        5. Plaintext Hash Check: SHA-256 comparison.
        6. Digital Signature Verification: RSA-PSS using sender's public key.
        7. Trust & Identity Fingerprint Check: compares with trusted sender directory.

        Returns detailed audit log for UI security dashboard.
        """
        audit_log = []
        result = {
            "success": False,
            "message_id": envelope.message_id,
            "sender_id": envelope.sender_id,
            "receiver_id": envelope.receiver_id,
            "subject": envelope.subject,
            "timestamp": envelope.timestamp,
            "decrypted_body": None,
            "sha256_hash": envelope.sha256_hash_hex,
            "verification_status": "FAILED",
            "integrity_status": "UNVERIFIED",
            "signature_status": "UNVERIFIED",
            "non_repudiation_status": "UNVERIFIED",
            "sender_trusted_status": "UNVERIFIED",
            "error_message": None,
            "audit_log": audit_log
        }

        # Step 1: Replay Attack Defense Check
        if is_replayed:
            err = f"REPLAY ATTACK DETECTED: Message ID {envelope.message_id} was already received and processed."
            audit_log.append({"step": "Replay Defense", "status": "FAILED", "details": err})
            result["verification_status"] = "REPLAY_DETECTED"
            result["error_message"] = err
            return result

        is_fresh, freshness_msg = envelope.validate_timestamp_freshness()
        if not is_fresh:
            audit_log.append({"step": "Timestamp Freshness", "status": "FAILED", "details": freshness_msg})
            result["verification_status"] = "TIMESTAMP_EXPIRED"
            result["error_message"] = freshness_msg
            return result
        audit_log.append({"step": "Timestamp Freshness", "status": "PASSED", "details": freshness_msg})

        # Step 2: Receiver Identity Check
        if envelope.receiver_id.lower().strip() != self.receiver_id.lower().strip():
            audit_log.append({
                "step": "Receiver ID Check",
                "status": "WARNING",
                "details": f"Target receiver '{envelope.receiver_id}' differs from local ID '{self.receiver_id}'."
            })
        else:
            audit_log.append({
                "step": "Receiver ID Check",
                "status": "PASSED",
                "details": f"Target receiver matches local identity: {self.receiver_id}"
            })

        # Step 3: Decrypt AES Session Key (RSA-OAEP)
        try:
            session_key = decrypt_session_key_rsa(envelope.encrypted_session_key, self.private_key)
            audit_log.append({
                "step": "Session Key Decryption (RSA-OAEP)",
                "status": "PASSED",
                "details": f"Successfully decrypted 256-bit AES session key using Receiver's private RSA key."
            })
        except KeyDecryptionError as e:
            err = f"Session key decryption failed (Unauthorized recipient or corrupted key): {str(e)}"
            audit_log.append({"step": "Session Key Decryption", "status": "FAILED", "details": err})
            result["verification_status"] = "KEY_DECRYPTION_FAILED"
            result["error_message"] = err
            return result

        # Step 4: Decrypt Ciphertext and Verify Authenticated Tag (AES-256-GCM)
        aad = envelope.get_aad()
        try:
            plaintext_bytes = decrypt_aes_gcm(
                ciphertext=envelope.ciphertext,
                key=session_key,
                nonce=envelope.nonce,
                auth_tag=envelope.auth_tag,
                associated_data=aad
            )
            result["integrity_status"] = "PASSED"
            audit_log.append({
                "step": "AES-256-GCM AEAD Decryption & Tag Verification",
                "status": "PASSED",
                "details": "Ciphertext decrypted successfully. 128-bit authentication tag verified: message and header integrity intact."
            })
        except IntegrityCompromisedError as e:
            err = f"INTEGRITY VIOLATION: {str(e)}"
            result["integrity_status"] = "TAMPERED"
            result["verification_status"] = "INTEGRITY_COMPROMISED"
            result["error_message"] = err
            audit_log.append({"step": "AES-256-GCM Tag Verification", "status": "FAILED", "details": err})
            return result

        # Step 5: Verify SHA-256 Hash Digest
        computed_hash = compute_sha256_hex(plaintext_bytes)
        if computed_hash.lower() != envelope.sha256_hash_hex.lower():
            err = f"HASH MISMATCH: Computed SHA-256 ({computed_hash}) does not match wire hash ({envelope.sha256_hash_hex})."
            result["integrity_status"] = "HASH_MISMATCH"
            result["verification_status"] = "INTEGRITY_COMPROMISED"
            result["error_message"] = err
            audit_log.append({"step": "SHA-256 Digest Verification", "status": "FAILED", "details": err})
            return result
        audit_log.append({
            "step": "SHA-256 Digest Verification",
            "status": "PASSED",
            "details": f"Computed hash {computed_hash[:16]}... matches wire digest."
        })

        # Step 6: Verify Digital Signature (RSA-PSS)
        try:
            sender_pub = load_public_key_pem(envelope.sender_public_key_pem.encode('utf-8'))
            sig_valid, sig_msg = verify_signature(plaintext_bytes, envelope.digital_signature, sender_pub)
            if not sig_valid:
                result["signature_status"] = "INVALID"
                result["non_repudiation_status"] = "FAILED"
                result["verification_status"] = "INVALID_SIGNATURE"
                result["error_message"] = sig_msg
                audit_log.append({"step": "RSA-PSS Digital Signature", "status": "FAILED", "details": sig_msg})
                return result

            result["signature_status"] = "PASSED"
            result["non_repudiation_status"] = "PASSED"
            audit_log.append({
                "step": "RSA-PSS Digital Signature",
                "status": "PASSED",
                "details": f"Digital signature verified successfully with sender's public key. Non-repudiation and sender authenticity confirmed."
            })
        except Exception as e:
            err = f"Sender public key or signature format error: {str(e)}"
            result["signature_status"] = "ERROR"
            result["verification_status"] = "SIGNATURE_ERROR"
            result["error_message"] = err
            audit_log.append({"step": "RSA-PSS Digital Signature", "status": "ERROR", "details": err})
            return result

        # Step 7: Sender Identity & Fingerprint Trust Evaluation
        claimed_fp = envelope.sender_fingerprint
        actual_fp = compute_public_key_fingerprint(sender_pub)

        if claimed_fp != actual_fp:
            err = f"FINGERPRINT SPOOFING DETECTED: Claimed fingerprint '{claimed_fp}' does not match actual key fingerprint '{actual_fp}'!"
            result["sender_trusted_status"] = "SPOOFED"
            result["verification_status"] = "SENDER_SPOOFED"
            result["error_message"] = err
            audit_log.append({"step": "Sender Fingerprint Trust", "status": "FAILED", "details": err})
            return result

        if trusted_sender_record:
            if trusted_sender_record.get("fingerprint") == actual_fp:
                result["sender_trusted_status"] = "TRUSTED_AND_VERIFIED"
                audit_log.append({
                    "step": "Sender Fingerprint Trust",
                    "status": "PASSED",
                    "details": f"Sender is verified in trusted address book ({actual_fp})."
                })
            else:
                err = f"KEY SUBSTITUTION WARNING: Sender '{envelope.sender_id}' public key changed from previously trusted key ({trusted_sender_record.get('fingerprint')} vs {actual_fp})!"
                result["sender_trusted_status"] = "KEY_CHANGED_WARNING"
                result["verification_status"] = "UNTRUSTED_KEY_SUBSTITUTION"
                result["error_message"] = err
                audit_log.append({"step": "Sender Fingerprint Trust", "status": "FAILED", "details": err})
                return result
        else:
            result["sender_trusted_status"] = "UNVERIFIED_FIRST_CONTACT"
            audit_log.append({
                "step": "Sender Fingerprint Trust",
                "status": "INFO",
                "details": f"First contact from sender. Key fingerprint is {actual_fp}. Out-of-band verification recommended."
            })

        # All cryptographic verification gates passed!
        result["success"] = True
        result["verification_status"] = "AUTHENTICATED"
        result["decrypted_body"] = plaintext_bytes.decode('utf-8', errors='replace')
        return result
