"""Cryptographic utilities for SSH key encryption and validation."""

from __future__ import annotations

import asyncssh
from cryptography.fernet import Fernet, InvalidToken

from app.config import get_settings
from app.exceptions import EncryptionError


def _get_fernet() -> Fernet:
    """Get Fernet instance from SSH_KEY_ENCRYPTION_KEY setting.

    Raises:
        EncryptionError: If the encryption key is not configured.
    """
    key = get_settings().ssh_key_encryption_key
    if not key:
        raise EncryptionError("SSH_KEY_ENCRYPTION_KEY is not configured")
    return Fernet(key.encode() if isinstance(key, str) else key)


def encrypt_ssh_key(raw_pem: str) -> str:
    """Encrypt a PEM private key string using Fernet.

    Args:
        raw_pem: Raw PEM-encoded SSH private key.

    Returns:
        Base64-encoded Fernet ciphertext.

    Raises:
        EncryptionError: If the encryption key is not configured.
    """
    f = _get_fernet()
    return f.encrypt(raw_pem.encode("utf-8")).decode("utf-8")


def decrypt_ssh_key(encrypted: str) -> str:
    """Decrypt a Fernet-encrypted PEM key.

    Args:
        encrypted: Base64-encoded Fernet ciphertext.

    Returns:
        Raw PEM private key string.

    Raises:
        EncryptionError: If decryption fails (wrong key or corrupted data).
    """
    f = _get_fernet()
    try:
        return f.decrypt(encrypted.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise EncryptionError("Failed to decrypt SSH key — encryption key may have changed") from exc


def validate_ssh_private_key(pem_str: str) -> None:
    """Validate that a string is a parseable PEM SSH private key.

    Uses asyncssh key parsing to support RSA, Ed25519, and ECDSA key types.

    Args:
        pem_str: PEM-encoded key string to validate.

    Raises:
        ValueError: If the key is invalid, or if a public key is provided
            instead of a private key.
    """
    # Detect if user accidentally provided a public key
    stripped = pem_str.strip()
    if stripped.startswith("ssh-") or "PUBLIC KEY" in stripped:
        raise ValueError("A private key is required, not a public key")

    try:
        asyncssh.import_private_key(pem_str)
    except asyncssh.KeyImportError as exc:
        raise ValueError(f"Invalid SSH private key: {exc}") from exc
    except Exception as exc:
        raise ValueError(f"Invalid SSH private key: {exc}") from exc
