"""Per-server AWS client factory with role assumption and TTL cache.

Design requirement (Daniel): aws_role_arn is an ARN, not a credential.
The manager assumes the target role using its own identity — no access key
or secret key fields exist anywhere in the data model.

Cache is keyed by (role_arn | None, service_name, region). Entries are
invalidated when the assumed-role credentials approach expiry (5-min buffer).

Invalidation when role_arn changes: call invalidate_server_clients(server)
before saving the updated server record so the next request rebuilds with
the new ARN.
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING, Any

import boto3
from botocore.exceptions import ClientError

from app.config import get_settings
from app.logging_config import get_logger

if TYPE_CHECKING:
    from app.db.models import Server

logger = get_logger(__name__)

# Cache: (role_arn | None, service_name, region) -> {"client": ..., "expiry": float}
# role_arn = None means "use the default boto3 credential chain (no assume-role)"
_client_cache: dict[tuple[str | None, str, str], dict[str, Any]] = {}

_CREDENTIAL_DURATION_SECONDS: int = 3600
_REFRESH_BUFFER_SECONDS: int = 300  # rebuild credentials 5 min before expiry
_SESSION_NAME: str = "strongswan-manager-server"


def _resolve_server_params(server: Server) -> tuple[str | None, str]:
    """Return (effective_role_arn, effective_region) for *server*.

    Falls back to global settings when server-level overrides are NULL.
    """
    settings = get_settings()
    role_arn: str | None = server.aws_role_arn if server.aws_role_arn else settings.aws_assume_role_arn
    region: str = server.aws_region_override if server.aws_region_override else settings.aws_region
    return role_arn, region


def _assume_role(role_arn: str, region: str) -> tuple[boto3.Session, float]:
    """Assume *role_arn* and return (session, expiry_timestamp).

    expiry_timestamp already has the 5-min refresh buffer subtracted so
    callers can compare directly against time.time().
    """
    sts = boto3.client("sts", region_name=region)
    logger.info("aws_client_assuming_role", role_arn=role_arn, region=region)
    response = sts.assume_role(
        RoleArn=role_arn,
        RoleSessionName=_SESSION_NAME,
        DurationSeconds=_CREDENTIAL_DURATION_SECONDS,
    )
    creds = response["Credentials"]
    session = boto3.Session(
        aws_access_key_id=creds["AccessKeyId"],
        aws_secret_access_key=creds["SecretAccessKey"],
        aws_session_token=creds["SessionToken"],
    )
    expiry_ts = creds["Expiration"].timestamp() - _REFRESH_BUFFER_SECONDS
    logger.info("aws_client_role_assumed", role_arn=role_arn, expiry_ts=expiry_ts)
    return session, expiry_ts


def get_client_for_server(server: Server, service_name: str) -> Any:
    """Return a boto3 client scoped to *server*'s role and region.

    Resolution order:
    - role:   server.aws_role_arn  → global aws_assume_role_arn  → no role (default chain)
    - region: server.aws_region_override → global aws_region

    Credentials are cached per (role_arn, service, region) with a TTL tied
    to the STS session expiry. If the server's aws_role_arn is updated you
    must call invalidate_server_clients(server) *before* saving, so the next
    call creates a fresh entry for the new ARN.

    Args:
        server:       Server ORM instance with optional aws_role_arn / aws_region_override.
        service_name: boto3 service identifier (e.g. "ssm", "ec2").

    Returns:
        A boto3 service client.
    """
    role_arn, region = _resolve_server_params(server)
    cache_key = (role_arn, service_name, region)
    now = time.time()

    entry = _client_cache.get(cache_key)
    if entry and now < entry["expiry"]:
        return entry["client"]

    if role_arn:
        session, expiry = _assume_role(role_arn, region)
        client = session.client(service_name, region_name=region)
    else:
        # No role assumption — use default credential chain
        client = boto3.client(service_name, region_name=region)
        expiry = now + _CREDENTIAL_DURATION_SECONDS - _REFRESH_BUFFER_SECONDS

    _client_cache[cache_key] = {"client": client, "expiry": expiry}
    logger.info(
        "aws_client_created",
        service=service_name,
        region=region,
        has_role=bool(role_arn),
    )
    return client


def invalidate_server_clients(server: Server) -> None:
    """Remove cached clients for *server*'s current role + region combination.

    Call this when server.aws_role_arn or server.aws_region_override is about
    to be updated. The next call to get_client_for_server will then assume the
    new role instead of returning a stale cached client for the old ARN.
    """
    role_arn, region = _resolve_server_params(server)
    keys_to_delete = [k for k in _client_cache if k[0] == role_arn and k[2] == region]
    for k in keys_to_delete:
        del _client_cache[k]
    logger.info(
        "aws_client_cache_invalidated",
        role_arn=role_arn,
        region=region,
        entries_removed=len(keys_to_delete),
    )
