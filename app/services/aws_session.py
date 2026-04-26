"""Shared AWS session management with optional cross-account role assumption.

When AWS_ASSUME_ROLE_ARN is configured, all AWS clients are created with
temporary credentials obtained via STS AssumeRole. Credentials are cached
and automatically refreshed 5 minutes before expiry.

When the env var is not set, boto3 uses the default credential chain.
"""

from __future__ import annotations

import time

import boto3

from app.config import get_settings
from app.logging_config import get_logger

logger = get_logger(__name__)

# Cached assumed-role credentials
_assumed_credentials: dict | None = None
_assumed_credentials_expiry: float = 0.0
_CREDENTIALS_REFRESH_BUFFER: int = 300  # refresh 5 min before expiry

# Cached clients keyed by service name; invalidated on credential refresh
_cached_clients: dict[str, object] = {}
_cached_clients_expiry: float = 0.0


def _get_assumed_role_session() -> boto3.Session | None:
    """Assume the cross-account role and return a session with temporary creds.

    Returns None if no role ARN is configured (use default credentials).
    Caches credentials until they are close to expiring.
    """
    global _assumed_credentials, _assumed_credentials_expiry  # noqa: PLW0603

    settings = get_settings()
    if not settings.aws_assume_role_arn:
        return None

    # Return cached credentials if still valid
    if _assumed_credentials and time.time() < _assumed_credentials_expiry:
        return boto3.Session(
            aws_access_key_id=_assumed_credentials["AccessKeyId"],
            aws_secret_access_key=_assumed_credentials["SecretAccessKey"],
            aws_session_token=_assumed_credentials["SessionToken"],
        )

    # Assume the role using master-account credentials
    logger.info("aws_assuming_role", role_arn=settings.aws_assume_role_arn)
    sts = boto3.client("sts", region_name=settings.aws_region)
    response = sts.assume_role(
        RoleArn=settings.aws_assume_role_arn,
        RoleSessionName="strongswan-manager",
        DurationSeconds=3600,
    )

    _assumed_credentials = response["Credentials"]
    expiration = _assumed_credentials["Expiration"]
    _assumed_credentials_expiry = expiration.timestamp() - _CREDENTIALS_REFRESH_BUFFER

    logger.info("aws_role_assumed", expires_at=expiration.isoformat())

    return boto3.Session(
        aws_access_key_id=_assumed_credentials["AccessKeyId"],
        aws_secret_access_key=_assumed_credentials["SecretAccessKey"],
        aws_session_token=_assumed_credentials["SessionToken"],
    )


def get_client(service_name: str):  # noqa: ANN202
    """Return a boto3 client, re-creating it when assumed credentials refresh.

    Safe for concurrent use from async code running in a single event loop.
    Uses simple in-memory caching: clients are held until credential rotation.
    """
    global _cached_clients_expiry  # noqa: PLW0603

    settings = get_settings()

    # No assume-role: straightforward caching with default creds
    if not settings.aws_assume_role_arn:
        if service_name not in _cached_clients:
            _cached_clients[service_name] = boto3.client(
                service_name, region_name=settings.aws_region
            )
        return _cached_clients[service_name]

    # With assume-role: ensure session is fresh (may refresh credentials)
    session = _get_assumed_role_session()

    # Invalidate cached clients when credentials were refreshed
    current_expiry = _assumed_credentials_expiry
    if current_expiry != _cached_clients_expiry or service_name not in _cached_clients:
        _cached_clients[service_name] = session.client(  # type: ignore[union-attr]
            service_name, region_name=settings.aws_region
        )
        _cached_clients_expiry = current_expiry

    return _cached_clients[service_name]
