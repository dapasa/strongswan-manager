"""Tests for crypto utilities — encryption round-trip and SSH key validation."""
from __future__ import annotations

from unittest.mock import patch, MagicMock

import pytest
from cryptography.fernet import Fernet

from app.exceptions import EncryptionError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# Generate a real Fernet key for testing
_TEST_FERNET_KEY = Fernet.generate_key().decode()
_ALT_FERNET_KEY = Fernet.generate_key().decode()


def _mock_settings(key: str = _TEST_FERNET_KEY):
    """Return a mock settings object with a given encryption key."""
    settings = MagicMock()
    settings.ssh_key_encryption_key = key
    return settings


def _generate_rsa_private_key_pem() -> str:
    """Generate a valid RSA private key PEM string using cryptography."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()


def _generate_ed25519_private_key_pem() -> str:
    """Generate a valid Ed25519 private key PEM string using cryptography."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization

    key = ed25519.Ed25519PrivateKey.generate()
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()


def _generate_rsa_public_key_openssh() -> str:
    """Generate an OpenSSH public key string (starts with ssh-rsa)."""
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode()


# ---------------------------------------------------------------------------
# Encrypt / Decrypt round-trip
# ---------------------------------------------------------------------------


class TestEncryptDecryptRoundTrip:
    @patch("app.utils.crypto.get_settings")
    def test_encrypt_decrypt_round_trip(self, mock_get_settings):
        """Encrypt then decrypt returns the original plaintext (SRV-003)."""
        mock_get_settings.return_value = _mock_settings()
        from app.utils.crypto import decrypt_ssh_key, encrypt_ssh_key

        original = _generate_rsa_private_key_pem()
        encrypted = encrypt_ssh_key(original)

        # Encrypted text must differ from original
        assert encrypted != original

        decrypted = decrypt_ssh_key(encrypted)
        assert decrypted == original

    @patch("app.utils.crypto.get_settings")
    def test_decrypt_with_wrong_key_raises(self, mock_get_settings):
        """Decrypting with a different key raises EncryptionError (SRV-003)."""
        # Encrypt with key A
        mock_get_settings.return_value = _mock_settings(_TEST_FERNET_KEY)
        from app.utils.crypto import decrypt_ssh_key, encrypt_ssh_key

        encrypted = encrypt_ssh_key("some-ssh-key-data")

        # Try to decrypt with key B
        mock_get_settings.return_value = _mock_settings(_ALT_FERNET_KEY)
        with pytest.raises(EncryptionError, match="Failed to decrypt"):
            decrypt_ssh_key(encrypted)

    @patch("app.utils.crypto.get_settings")
    def test_encrypt_raises_when_key_not_configured(self, mock_get_settings):
        """Encrypt raises EncryptionError when encryption key is empty (SRV-006)."""
        mock_get_settings.return_value = _mock_settings("")
        from app.utils.crypto import encrypt_ssh_key

        with pytest.raises(EncryptionError, match="not configured"):
            encrypt_ssh_key("some-key")

    @patch("app.utils.crypto.get_settings")
    def test_decrypt_raises_when_key_not_configured(self, mock_get_settings):
        """Decrypt raises EncryptionError when encryption key is empty (SRV-006)."""
        mock_get_settings.return_value = _mock_settings("")
        from app.utils.crypto import decrypt_ssh_key

        with pytest.raises(EncryptionError, match="not configured"):
            decrypt_ssh_key("some-encrypted-data")


# ---------------------------------------------------------------------------
# SSH key validation
# ---------------------------------------------------------------------------


class TestValidateSSHPrivateKey:
    def test_valid_rsa_key_accepted(self):
        """Valid RSA PEM private key passes validation (SRV-004)."""
        from app.utils.crypto import validate_ssh_private_key

        pem = _generate_rsa_private_key_pem()
        # Should not raise
        validate_ssh_private_key(pem)

    def test_valid_ed25519_key_accepted(self):
        """Valid Ed25519 PEM private key passes validation (SRV-004)."""
        from app.utils.crypto import validate_ssh_private_key

        pem = _generate_ed25519_private_key_pem()
        validate_ssh_private_key(pem)

    def test_public_key_rejected(self):
        """Public key (ssh-rsa format) is rejected with specific message (SRV-004)."""
        from app.utils.crypto import validate_ssh_private_key

        pub_key = _generate_rsa_public_key_openssh()
        with pytest.raises(ValueError, match="private key is required, not a public key"):
            validate_ssh_private_key(pub_key)

    def test_pem_public_key_rejected(self):
        """PEM-encoded public key (with PUBLIC KEY header) is rejected (SRV-004)."""
        from app.utils.crypto import validate_ssh_private_key

        pem_pub = "-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"
        with pytest.raises(ValueError, match="private key is required, not a public key"):
            validate_ssh_private_key(pem_pub)

    def test_garbage_input_rejected(self):
        """Random garbage string is rejected as invalid key (SRV-004)."""
        from app.utils.crypto import validate_ssh_private_key

        with pytest.raises(ValueError, match="Invalid SSH private key"):
            validate_ssh_private_key("this-is-not-a-key-at-all")

    def test_empty_string_rejected(self):
        """Empty string is rejected (SRV-004)."""
        from app.utils.crypto import validate_ssh_private_key

        with pytest.raises(ValueError):
            validate_ssh_private_key("")
