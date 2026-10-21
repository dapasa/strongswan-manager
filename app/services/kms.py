"""KMS service — encrypt and decrypt PSK values using AWS KMS.

The PSK is encrypted with KMS Encrypt (direct encryption, PSK < 4 KB).
The ciphertext is stored base64-encoded in the tunnels table.

The plaintext PSK is only ever in memory during:
  - Tunnel create / update (from the API request body)
  - Config render + push to VPN nodes

It is never logged, never returned by the API, and never written to disk.
"""

from __future__ import annotations

import asyncio
import base64

from botocore.exceptions import ClientError

from app.config import get_settings
from app.exceptions import InfrastructureError
from app.logging_config import get_logger
from app.services.aws_session import get_client

logger = get_logger(__name__)


def _get_kms_client():  # noqa: ANN202
    """Return a boto3 KMS client (uses the shared session/assume-role logic)."""
    return get_client("kms")


async def encrypt_psk(psk: str) -> str:
    """Encrypt a PSK with KMS and return the base64-encoded ciphertext.

    Args:
        psk: Plaintext pre-shared key.

    Returns:
        Base64-encoded KMS ciphertext blob.

    Raises:
        InfrastructureError: On KMS API failure.
    """
    settings = get_settings()
    key_id = settings.kms_psk_key_id

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: _get_kms_client().encrypt(
                KeyId=key_id,
                Plaintext=psk.encode("utf-8"),
            ),
        )
        ciphertext = base64.b64encode(response["CiphertextBlob"]).decode("ascii")
        logger.info("kms_psk_encrypted")
        return ciphertext
    except ClientError as exc:
        raise InfrastructureError(
            service="KMS",
            message="Failed to encrypt PSK",
            detail=str(exc),
        ) from exc


async def decrypt_psk(ciphertext_b64: str) -> str:
    """Decrypt a KMS-encrypted PSK and return the plaintext.

    Args:
        ciphertext_b64: Base64-encoded KMS ciphertext blob (from encrypt_psk).

    Returns:
        Plaintext PSK string.

    Raises:
        InfrastructureError: On KMS API failure.
    """
    ciphertext = base64.b64decode(ciphertext_b64)

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: _get_kms_client().decrypt(
                CiphertextBlob=ciphertext,
            ),
        )
        psk = response["Plaintext"].decode("utf-8")
        logger.info("kms_psk_decrypted")
        return psk
    except ClientError as exc:
        raise InfrastructureError(
            service="KMS",
            message="Failed to decrypt PSK",
            detail=str(exc),
        ) from exc
