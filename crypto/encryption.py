"""
Encryption Module for Hybrid Cryptography System.
Implements:
1. AES-256-GCM authenticated symmetric encryption.
2. RSA-OAEP asymmetric key encapsulation using SHA-256 and MGF1.
3. Cryptographically secure random key & nonce generation.
4. SHA-256 digest calculation for message integrity verification.
"""

import os
import hashlib
from typing import Tuple, Optional, Dict
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes


def generate_aes_key() -> bytes:
    """
    Generates a cryptographically strong 256-bit (32-byte) AES session key
    using operating system CSPRNG (os.urandom).
    """
    return os.urandom(32)


def generate_nonce() -> bytes:
    """
    Generates a standard 96-bit (12-byte) initialization vector / nonce for AES-GCM.
    A fresh nonce must be used for every encryption with a given key.
    """
    return os.urandom(12)


def compute_sha256_hex(data: bytes) -> str:
    """
    Computes standard SHA-256 hexadecimal hash digest of input bytes.
    """
    return hashlib.sha256(data).hexdigest()


def compute_sha256_bytes(data: bytes) -> bytes:
    """
    Computes standard SHA-256 raw bytes hash digest of input bytes.
    """
    return hashlib.sha256(data).digest()


def encrypt_aes_gcm(
    plaintext: bytes,
    key: bytes,
    nonce: Optional[bytes] = None,
    associated_data: Optional[bytes] = None
) -> Tuple[bytes, bytes, bytes]:
    """
    Encrypts plaintext using AES-256 in Galois/Counter Mode (GCM).
    AES-GCM provides both confidentiality and cryptographic integrity.

    Returns:
        (ciphertext: bytes, nonce: bytes, tag: bytes)
    """
    if len(key) != 32:
        raise ValueError(f"AES-256 key must be exactly 32 bytes (256 bits). Got {len(key)} bytes.")

    if nonce is None:
        nonce = generate_nonce()
    elif len(nonce) != 12:
        raise ValueError(f"AES-GCM nonce must be 12 bytes (96 bits). Got {len(nonce)} bytes.")

    aesgcm = AESGCM(key)
    # cryptography's AESGCM.encrypt appends the 16-byte tag to the ciphertext
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, associated_data)
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]

    return ciphertext, nonce, tag


def encrypt_session_key_rsa(
    session_key: bytes,
    receiver_public_key: rsa.RSAPublicKey
) -> bytes:
    """
    Encrypts the 256-bit AES session key using the receiver's RSA public key with
    Optimal Asymmetric Encryption Padding (OAEP) parameterized with SHA-256.
    """
    encrypted_key = receiver_public_key.encrypt(
        session_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key


def hybrid_encrypt(
    plaintext: bytes,
    receiver_public_key: rsa.RSAPublicKey,
    associated_data: Optional[bytes] = None
) -> Dict[str, bytes]:
    """
    Full hybrid encryption flow:
    1. Generates one-time 256-bit AES session key and 96-bit nonce.
    2. Encrypts plaintext via AES-256-GCM with associated data -> ciphertext + auth_tag.
    3. Encrypts session key via RSA-OAEP with receiver public key.
    4. Computes SHA-256 hash of plaintext.

    Returns dictionary containing all cryptographic outputs:
        - session_key (ephemeral, should be zeroized after use)
        - encrypted_session_key
        - ciphertext
        - nonce
        - auth_tag
        - sha256_hash_hex
    """
    session_key = generate_aes_key()
    ciphertext, nonce, auth_tag = encrypt_aes_gcm(plaintext, session_key, associated_data=associated_data)
    encrypted_session_key = encrypt_session_key_rsa(session_key, receiver_public_key)
    sha256_hash_hex = compute_sha256_hex(plaintext)

    return {
        "session_key": session_key,
        "encrypted_session_key": encrypted_session_key,
        "ciphertext": ciphertext,
        "nonce": nonce,
        "auth_tag": auth_tag,
        "sha256_hash_hex": sha256_hash_hex
    }
