"""
Crypto package root.
Exports key management, encryption, decryption, and digital signature capabilities.
"""

from .key_management import (
    generate_rsa_keypair,
    export_private_key_pem,
    export_public_key_pem,
    load_private_key_pem,
    load_public_key_pem,
    compute_public_key_fingerprint,
    save_keypair_to_disk,
    load_or_create_keypair
)
from .encryption import (
    generate_aes_key,
    generate_nonce,
    compute_sha256_hex,
    compute_sha256_bytes,
    encrypt_aes_gcm,
    encrypt_session_key_rsa,
    hybrid_encrypt
)
from .decryption import (
    decrypt_session_key_rsa,
    decrypt_aes_gcm,
    hybrid_decrypt,
    DecryptionError,
    IntegrityCompromisedError,
    KeyDecryptionError
)
from .digital_signature import (
    sign_data,
    verify_signature
)

__all__ = [
    "generate_rsa_keypair",
    "export_private_key_pem",
    "export_public_key_pem",
    "load_private_key_pem",
    "load_public_key_pem",
    "compute_public_key_fingerprint",
    "save_keypair_to_disk",
    "load_or_create_keypair",
    "generate_aes_key",
    "generate_nonce",
    "compute_sha256_hex",
    "compute_sha256_bytes",
    "encrypt_aes_gcm",
    "encrypt_session_key_rsa",
    "hybrid_encrypt",
    "decrypt_session_key_rsa",
    "decrypt_aes_gcm",
    "hybrid_decrypt",
    "DecryptionError",
    "IntegrityCompromisedError",
    "KeyDecryptionError",
    "sign_data",
    "verify_signature"
]
