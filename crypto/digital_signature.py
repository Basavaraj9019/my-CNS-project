"""
Digital Signature Module for Hybrid Cryptography System.
Implements:
1. RSA-PSS digital signature generation using sender's private key.
2. RSA-PSS signature verification using sender's public key.
3. Cryptographic authentication and non-repudiation guarantees.
4. Secure parameterization using SHA-256 and PSS.MAX_LENGTH salt.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature


def sign_data(data: bytes, sender_private_key: rsa.RSAPrivateKey) -> bytes:
    """
    Generates a cryptographically secure digital signature using RSA-PSS
    with SHA-256 hashing and maximum salt length.
    Ensures message authenticity and non-repudiation.
    """
    signature = sender_private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature


def verify_signature(
    data: bytes,
    signature: bytes,
    sender_public_key: rsa.RSAPublicKey
) -> Tuple[bool, str]:
    """
    Verifies an RSA-PSS digital signature against the provided data and sender public key.

    Returns:
        (is_valid: bool, status_message: str)
    """
    try:
        sender_public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True, "Digital signature is VALID. Authenticity and non-repudiation confirmed."
    except InvalidSignature:
        return False, "Digital signature is INVALID! Signature does not match sender public key or message was modified."
    except Exception as e:
        return False, f"Signature verification error: {str(e)}"
