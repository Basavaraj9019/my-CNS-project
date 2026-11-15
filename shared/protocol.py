"""
Secure Wire Protocol and Envelope Specification.
Defines JSON serialization, base64 encoding/decryption helpers,
Associated Authenticated Data (AAD) generation, and packet validation.
"""

import base64
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, Tuple


PROTOCOL_VERSION = "1.0"
MAX_TIMESTAMP_DRIFT_SECONDS = 300  # 5-minute window for replay defense


def compute_aad(
    message_id: str,
    sender_id: str,
    receiver_id: str,
    timestamp: str,
    subject: str
) -> bytes:
    """
    Computes deterministic Associated Authenticated Data (AAD) bytes.
    Binding message headers into AES-GCM ensures any alteration of the subject,
    sender, receiver, timestamp, or message ID triggers an AEAD tag mismatch.
    """
    canonical_header = f"v1|{message_id}|{sender_id}|{receiver_id}|{timestamp}|{subject}"
    return canonical_header.encode('utf-8')


def b64encode_str(data: bytes) -> str:
    """Encodes bytes to standard ASCII Base64 string."""
    return base64.b64encode(data).decode('ascii')


def b64decode_bytes(encoded: str) -> bytes:
    """Decodes standard ASCII Base64 string to bytes."""
    return base64.b64decode(encoded.encode('ascii'))


class SecureMessageEnvelope:
    """
    Encapsulates all cryptographic artifacts and metadata for transmission
    between Sender (Laptop 1) and Receiver (Laptop 2).
    """

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        subject: str,
        encrypted_session_key: bytes,
        nonce: bytes,
        ciphertext: bytes,
        auth_tag: bytes,
        digital_signature: bytes,
        sha256_hash_hex: str,
        sender_public_key_pem: str,
        sender_fingerprint: str,
        message_id: Optional[str] = None,
        timestamp: Optional[str] = None,
        version: str = PROTOCOL_VERSION
    ):
        self.version = version
        self.message_id = message_id or str(uuid.uuid4())
        self.timestamp = timestamp or datetime.now(timezone.utc).isoformat()
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.subject = subject
        self.encrypted_session_key = encrypted_session_key
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.auth_tag = auth_tag
        self.digital_signature = digital_signature
        self.sha256_hash_hex = sha256_hash_hex
        self.sender_public_key_pem = sender_public_key_pem
        self.sender_fingerprint = sender_fingerprint

    def get_aad(self) -> bytes:
        """Returns Associated Authenticated Data for this envelope."""
        return compute_aad(
            self.message_id,
            self.sender_id,
            self.receiver_id,
            self.timestamp,
            self.subject
        )

    def to_dict(self) -> Dict[str, Any]:
        """Converts envelope to JSON-serializable dictionary with Base64 fields."""
        return {
            "version": self.version,
            "message_id": self.message_id,
            "timestamp": self.timestamp,
            "sender_id": self.sender_id,
            "receiver_id": self.receiver_id,
            "subject": self.subject,
            "encrypted_session_key": b64encode_str(self.encrypted_session_key),
            "nonce": b64encode_str(self.nonce),
            "ciphertext": b64encode_str(self.ciphertext),
            "auth_tag": b64encode_str(self.auth_tag),
            "digital_signature": b64encode_str(self.digital_signature),
            "sha256_hash": self.sha256_hash_hex,
            "sender_public_key_pem": self.sender_public_key_pem,
            "sender_fingerprint": self.sender_fingerprint
        }

    def to_json(self) -> str:
        """Serializes envelope to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SecureMessageEnvelope":
        """Reconstructs SecureMessageEnvelope from dictionary, decoding Base64 fields."""
        required_fields = [
            "message_id", "timestamp", "sender_id", "receiver_id",
            "subject", "encrypted_session_key", "nonce", "ciphertext",
            "auth_tag", "digital_signature", "sha256_hash",
            "sender_public_key_pem", "sender_fingerprint"
        ]
        for field in required_fields:
            if field not in data:
                raise ValueError(f"Missing required envelope field: {field}")

        return cls(
            sender_id=data["sender_id"],
            receiver_id=data["receiver_id"],
            subject=data["subject"],
            encrypted_session_key=b64decode_bytes(data["encrypted_session_key"]),
            nonce=b64decode_bytes(data["nonce"]),
            ciphertext=b64decode_bytes(data["ciphertext"]),
            auth_tag=b64decode_bytes(data["auth_tag"]),
            digital_signature=b64decode_bytes(data["digital_signature"]),
            sha256_hash_hex=data["sha256_hash"],
            sender_public_key_pem=data["sender_public_key_pem"],
            sender_fingerprint=data["sender_fingerprint"],
            message_id=data["message_id"],
            timestamp=data["timestamp"],
            version=data.get("version", PROTOCOL_VERSION)
        )

    @classmethod
    def from_json(cls, json_str: str) -> "SecureMessageEnvelope":
        """Parses JSON string into SecureMessageEnvelope."""
        data = json.loads(json_str)
        return cls.from_dict(data)

    def validate_timestamp_freshness(self, max_drift_seconds: int = MAX_TIMESTAMP_DRIFT_SECONDS) -> Tuple[bool, str]:
        """
        Validates timestamp freshness to thwart replay attacks.
        Checks if timestamp is within UTC +/- max_drift_seconds.
        """
        try:
            msg_dt = datetime.fromisoformat(self.timestamp)
            if msg_dt.tzinfo is None:
                msg_dt = msg_dt.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)

            delta = abs((now - msg_dt).total_seconds())
            if delta > max_drift_seconds:
                return False, f"Message expired or timestamp drift exceeds limit ({delta:.1f}s > {max_drift_seconds}s)."
            return True, f"Timestamp is fresh (drift: {delta:.1f}s)."
        except Exception as e:
            return False, f"Invalid timestamp format: {str(e)}"
