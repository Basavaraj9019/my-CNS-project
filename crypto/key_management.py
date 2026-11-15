"""
Key Management Module for Hybrid Cryptography System.
Handles RSA-2048/3072 key generation, PEM serialization, secure local file storage,
and cryptographic public key fingerprinting (SHA-256).
"""

import os
import hashlib
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """
    Generates a cryptographically strong RSA private/public keypair.
    Key size must be at least 2048 bits (supports 2048 or 3072 bits).
    """
    if key_size not in (2048, 3072, 4096):
        raise ValueError(f"Unsupported RSA key size: {key_size}. Must be 2048, 3072, or 4096 bits.")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def export_private_key_pem(private_key: rsa.RSAPrivateKey, passphrase: Optional[str] = None) -> bytes:
    """
    Exports an RSA private key to standard PKCS#8 PEM format.
    Optionally encrypts the private key with AES-256 if passphrase is provided.
    """
    if passphrase:
        encryption_algo = serialization.BestAvailableEncryption(passphrase.encode('utf-8'))
    else:
        encryption_algo = serialization.NoEncryption()

    pem_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algo
    )
    return pem_bytes


def export_public_key_pem(public_key: rsa.RSAPublicKey) -> bytes:
    """
    Exports an RSA public key to standard SubjectPublicKeyInfo (SPKI) PEM format.
    """
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def load_private_key_pem(pem_bytes: bytes, passphrase: Optional[str] = None) -> rsa.RSAPrivateKey:
    """
    Loads an RSA private key from PEM bytes.
    """
    password = passphrase.encode('utf-8') if passphrase else None
    private_key = serialization.load_pem_private_key(
        pem_bytes,
        password=password,
        backend=default_backend()
    )
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise TypeError("Loaded key is not an RSA private key.")
    return private_key


def load_public_key_pem(pem_bytes: bytes) -> rsa.RSAPublicKey:
    """
    Loads an RSA public key from PEM bytes.
    """
    public_key = serialization.load_pem_public_key(
        pem_bytes,
        backend=default_backend()
    )
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise TypeError("Loaded key is not an RSA public key.")
    return public_key


def compute_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """
    Computes a cryptographic SHA-256 fingerprint of the public key's DER representation.
    Returns format: 'SHA256:xx:xx:xx:...' for human-verifiable out-of-band trust.
    Prevents public-key substitution / man-in-the-middle attacks.
    """
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der_bytes).hexdigest()
    # Format as pairs separated by colons
    formatted = ":".join(digest[i:i+2] for i in range(0, len(digest), 2))
    return f"SHA256:{formatted}"


def save_keypair_to_disk(
    private_key: rsa.RSAPrivateKey,
    public_key: rsa.RSAPublicKey,
    directory: str,
    prefix: str = "identity",
    passphrase: Optional[str] = None
) -> Tuple[str, str]:
    """
    Saves private and public keys to the specified directory.
    Enforces strict local file storage. Private key is never shared.
    """
    os.makedirs(directory, exist_ok=True)
    priv_path = os.path.join(directory, f"{prefix}_private.pem")
    pub_path = os.path.join(directory, f"{prefix}_public.pem")

    priv_pem = export_private_key_pem(private_key, passphrase)
    pub_pem = export_public_key_pem(public_key)

    with open(priv_path, "wb") as f:
        f.write(priv_pem)

    # In POSIX environments we would chmod 600, in Windows we write to private user directory
    with open(pub_path, "wb") as f:
        f.write(pub_pem)

    return priv_path, pub_path


def load_or_create_keypair(
    directory: str,
    prefix: str = "identity",
    key_size: int = 2048,
    passphrase: Optional[str] = None
) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey, str]:
    """
    Loads existing keypair if found in directory; otherwise generates a new keypair,
    saves it to disk, and returns (private_key, public_key, fingerprint).
    """
    os.makedirs(directory, exist_ok=True)
    priv_path = os.path.join(directory, f"{prefix}_private.pem")
    pub_path = os.path.join(directory, f"{prefix}_public.pem")

    if os.path.exists(priv_path) and os.path.exists(pub_path):
        with open(priv_path, "rb") as f:
            priv_key = load_private_key_pem(f.read(), passphrase)
        with open(pub_path, "rb") as f:
            pub_key = load_public_key_pem(f.read())
    else:
        priv_key, pub_key = generate_rsa_keypair(key_size=key_size)
        save_keypair_to_disk(priv_key, pub_key, directory, prefix, passphrase)

    fingerprint = compute_public_key_fingerprint(pub_key)
    return priv_key, pub_key, fingerprint
