"""In-memory cache for AWS Secrets Manager secrets.

Used by the Tier 2 (Shortcut) access-request flow to read the Shortcut API
token from Secrets Manager, with a 1-hour TTL so rotation is picked up
without a restart.

Design:
  - Uses the DEFAULT boto3 credential chain (e.g. EC2 instance role).
    DO NOT assume a role here — the instance role has direct cross-account
    access to the secret.
  - The secret value is NEVER written to logs at any level.
  - On any read error, return None so callers fail closed.
"""

from __future__ import annotations

import time

import boto3
from botocore.exceptions import ClientError

from app.logging_config import get_logger

logger = get_logger(__name__)

_TTL_SECONDS = 3600  # 1 hour

# Cache: {arn: (plaintext_value, fetched_at_monotonic)}
_cache: dict[str, tuple[str, float]] = {}


def _region_from_arn(arn: str) -> str:
    """Extract the AWS region from an ARN.

    ARN format: arn:partition:service:region:account:resource
    """
    parts = arn.split(":")
    return parts[3] if len(parts) >= 4 else "us-east-1"


def get_secret(arn: str) -> str | None:
    """Return the plaintext value of an AWS Secrets Manager secret.

    Uses the default boto3 credential chain (instance role, environment
    credentials, etc.) — does NOT assume a role.

    The result is cached for _TTL_SECONDS so rotation is picked up within
    one hour without a restart.

    Returns None on any error.  The secret value is never logged.
    """
    now = time.monotonic()

    if arn in _cache:
        value, fetched_at = _cache[arn]
        if now - fetched_at < _TTL_SECONDS:
            return value
        del _cache[arn]  # TTL expired — re-fetch

    region = _region_from_arn(arn)
    logger.info("secrets_manager_fetch", arn=arn, region=region)
    try:
        # Default credential chain — no role assumption.
        client = boto3.client("secretsmanager", region_name=region)
        response = client.get_secret_value(SecretId=arn)
        value: str = response.get("SecretString") or ""
        if not value:
            # Binary secrets are not supported for a text token.
            logger.error("secrets_manager_binary_secret_not_supported", arn=arn)
            return None
        _cache[arn] = (value, now)
        logger.info("secrets_manager_fetch_ok", arn=arn)
        # value is intentionally NOT logged
        return value
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "unknown")
        logger.error("secrets_manager_fetch_failed", arn=arn, error_code=code)
        return None
    except Exception as exc:  # noqa: BLE001
        logger.error(
            "secrets_manager_fetch_error",
            arn=arn,
            error_type=type(exc).__name__,
        )
        return None


def resolve_shortcut_token(settings: object) -> str:
    """Return the Shortcut API token for the given settings.

    Resolution order:
    1. If SHORTCUT_TOKEN_SECRET_ARN is set, fetch from Secrets Manager
       (using the EC2 instance role, cached for 1 hour).
       If the fetch succeeds, return that value.
       If the fetch fails, fall through to the env-var fallback.
    2. SHORTCUT_API_TOKEN env var / setting value.

    Returns an empty string when neither source provides a token.
    The resolved token is never written to logs.
    """
    # Import inline to avoid circular imports at module load time.
    from app.config import Settings  # noqa: PLC0415

    s: Settings = settings  # type: ignore[assignment]

    if s.shortcut_token_secret_arn:
        token = get_secret(s.shortcut_token_secret_arn)
        if token is not None:
            return token
        # Fetch failed — warn and fall through to the env-var fallback.
        logger.warning(
            "secrets_manager_fallback_to_env",
            arn=s.shortcut_token_secret_arn,
        )

    env_token = s.shortcut_api_token.get_secret_value() if s.shortcut_api_token else ""
    return env_token
