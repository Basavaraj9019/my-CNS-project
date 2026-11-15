"""
Decryption Module for Hybrid Cryptography System.
Implements:
1. RSA-OAEP session key decryption using receiver's private key.
2. AES-256-GCM authenticated symmetric decryption with integrity/tag verification.
3. Cryptographic exception handling for tamper detection.
"""

from typing import Optional, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag, InvalidSignature


class DecryptionError(Exception):
    """Base exception for hybrid decryption failures."""
    pass


class IntegrityCompromisedError(DecryptionError):
    """Raised when AES-GCM authentication tag verification fails (ciphertext modified)."""
    pass


class KeyDecryptionError(DecryptionError):
    """Raised when RSA-OAEP session key decryption fails (wrong private key or corrupted key)."""
    pass


def decrypt_session_key_rsa(
    encrypted_session_key: bytes,
    receiver_private_key: rsa.RSAPrivateKey
) -> bytes:
    """
    Decrypts the AES session key using the receiver's private RSA key with OAEP padding.
    """
    try:
        session_key = receiver_private_key.decrypt(
            encrypted_session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        if len(session_key) != 32:
            raise KeyDecryptionError(f"Decrypted key length is {len(session_key)} bytes, expected 32 bytes.")
        return session_key
    except Exception as e:
        raise KeyDecryptionError(f"RSA-OAEP session key decryption failed: {str(e)}") from e


def decrypt_aes_gcm(
    ciphertext: bytes,
    key: bytes,
    nonce: bytes,
    auth_tag: bytes,
    associated_data: Optional[bytes] = None
) -> bytes:
    """
    Decrypts ciphertext using AES-256-GCM.
    Automatically validates the 16-byte authentication tag against ciphertext, nonce, and associated_data.
    If any byte has been tampered with, raises IntegrityCompromisedError.
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be exactly 32 bytes. Got {len(key)} bytes.")
    if len(nonce) != 12:
        raise ValueError(f"AES-GCM nonce must be exactly 12 bytes. Got {len(nonce)} bytes.")
    if len(auth_tag) != 16:
        raise ValueError(f"AES-GCM authentication tag must be exactly 16 bytes. Got {len(auth_tag)} bytes.")

    aesgcm = AESGCM(key)
    ct_with_tag = ciphertext + auth_tag

    try:
        plaintext = aesgcm.decrypt(nonce, ct_with_tag, associated_data)
        return plaintext
    except InvalidTag as e:
        raise IntegrityCompromisedError(
            "AES-GCM authentication tag check failed! Ciphertext, nonce, or header data has been tampered with."
        ) from e


def hybrid_decrypt(
    encrypted_session_key: bytes,
    ciphertext: bytes,
    nonce: bytes,
    auth_tag: bytes,
    receiver_private_key: rsa.RSAPrivateKey,
    associated_data: Optional[bytes] = None
) -> Dict[str, bytes]:
    """
    Executes complete hybrid decryption:
    1. Decrypts AES session key using receiver's private RSA key.
    2. Decrypts ciphertext using AES-256-GCM and verifies authentication tag.

    Returns dictionary containing:
        - session_key
        - plaintext
    """
    session_key = decrypt_session_key_rsa(encrypted_session_key, receiver_private_key)
    plaintext = decrypt_aes_gcm(ciphertext, session_key, nonce, auth_tag, associated_data)

    return {
        "session_key": session_key,
        "plaintext": plaintext
    }
