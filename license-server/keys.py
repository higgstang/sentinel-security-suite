"""RSA key generation and JWT signing for license keys."""

import os

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

KEY_DIR = os.path.dirname(os.path.abspath(__file__))
PRIVATE_KEY_PATH = os.path.join(KEY_DIR, "private_key.pem")
PUBLIC_KEY_PATH = os.path.join(KEY_DIR, "public_key.pem")


def generate_key_pair():
    """Generate a 2048-bit RSA key pair and save it to disk."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)

    return PRIVATE_KEY_PATH, PUBLIC_KEY_PATH


def load_private_key():
    if not os.path.exists(PRIVATE_KEY_PATH):
        generate_key_pair()
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return f.read()


def load_public_key():
    if not os.path.exists(PUBLIC_KEY_PATH):
        generate_key_pair()
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return f.read()


def ensure_keys():
    """Generate keys if missing."""
    if not os.path.exists(PRIVATE_KEY_PATH) or not os.path.exists(PUBLIC_KEY_PATH):
        generate_key_pair()
