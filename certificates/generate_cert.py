"""
TLS / HTTPS Certificate Generator.
Generates self-signed X.509 certificate and private key for securing the HTTP transport layer.
Provides Defense-in-Depth (Transport Layer Security + Application Layer Cryptography).
"""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


def generate_self_signed_cert(
    output_dir: str,
    common_name: str = "secure-email.local",
    days_valid: int = 365
) -> tuple[str, str]:
    """
    Generates a 2048-bit RSA private key and self-signed X.509 certificate.
    Saves 'cert.pem' and 'key.pem' in output_dir.
    """
    os.makedirs(output_dir, exist_ok=True)
    cert_path = os.path.join(output_dir, "cert.pem")
    key_path = os.path.join(output_dir, "key.pem")

    # Generate RSA private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Build certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CyberSec"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Secure Email System"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        now
    ).not_valid_after(
        now + datetime.timedelta(days=days_valid)
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True
    ).sign(private_key, hashes.SHA256(), default_backend())

    # Write key
    with open(key_path, "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # Write cert
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"[+] TLS Certificate created: {cert_path}")
    print(f"[+] TLS Private Key created: {key_path}")
    return cert_path, key_path


if __name__ == "__main__":
    cert_dir = os.path.dirname(os.path.abspath(__file__))
    generate_self_signed_cert(cert_dir)
