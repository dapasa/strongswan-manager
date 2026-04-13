from __future__ import annotations

import time
from typing import Any

import httpx
from jose import JWTError, jwt

from app.config import get_settings
from app.exceptions import AuthenticationError
from app.logging_config import get_logger

logger = get_logger(__name__)

# Module-level JWKS cache
_openid_config: dict[str, Any] | None = None
_jwks: dict[str, Any] | None = None
_jwks_fetched_at: float = 0.0
_JWKS_TTL_SECONDS: int = 3600  # 1 hour


async def fetch_openid_config() -> dict[str, Any]:
    """Fetch and cache the OpenID Connect discovery document.

    GET {SSO_ISSUER_URL}/.well-known/openid-configuration
    Result is cached for the lifetime of the process (issuer config rarely changes).
    """
    global _openid_config  # noqa: PLW0603

    if _openid_config is not None:
        return _openid_config

    settings = get_settings()
    discovery_url = f"{settings.oidc_issuer_url.rstrip('/')}/.well-known/openid-configuration"

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(discovery_url)
            response.raise_for_status()
            _openid_config = response.json()
    except httpx.HTTPError as exc:
        logger.error("Failed to fetch OpenID configuration", url=discovery_url, error=str(exc))
        raise AuthenticationError(
            "Unable to fetch OpenID configuration",
            detail=str(exc),
        ) from exc

    logger.info("Fetched OpenID configuration", issuer=settings.oidc_issuer_url)
    return _openid_config


async def fetch_jwks() -> dict[str, Any]:
    """Fetch JWKS from the provider's jwks_uri with a 1-hour TTL cache.

    Falls back to cached JWKS if the fetch fails and a cached copy exists.
    """
    global _jwks, _jwks_fetched_at  # noqa: PLW0603

    now = time.monotonic()

    # Return cached JWKS if still fresh
    if _jwks is not None and (now - _jwks_fetched_at) < _JWKS_TTL_SECONDS:
        return _jwks

    try:
        openid_config = await fetch_openid_config()
        jwks_uri = openid_config["jwks_uri"]

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(jwks_uri)
            response.raise_for_status()
            _jwks = response.json()
            _jwks_fetched_at = now
    except (httpx.HTTPError, KeyError) as exc:
        # Fallback to cached JWKS if available
        if _jwks is not None:
            logger.warning(
                "Failed to refresh JWKS, using cached keys",
                error=str(exc),
            )
            return _jwks
        logger.error("Failed to fetch JWKS and no cached keys available", error=str(exc))
        raise AuthenticationError(
            "Unable to fetch JWKS",
            detail=str(exc),
        ) from exc

    logger.info("Fetched JWKS successfully")
    return _jwks


async def validate_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT against the OIDC provider.

    Validates:
    - RS256 signature against JWKS
    - Audience matches OIDC_AUDIENCE
    - Issuer matches OIDC_ISSUER_URL
    - Token is not expired

    Returns the decoded claims on success.
    Raises AuthenticationError on any validation failure.
    """
    settings = get_settings()
    jwks = await fetch_jwks()

    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            jwks,
            algorithms=["RS256"],
            audience=settings.oidc_audience,
            issuer=settings.oidc_issuer_url,
        )
    except JWTError as exc:
        logger.warning("JWT validation failed", error=str(exc))
        raise AuthenticationError("Invalid or expired token", detail=str(exc)) from exc

    # Ensure required claims are present
    if "sub" not in payload:
        raise AuthenticationError("Token missing required 'sub' claim")

    return payload


def clear_jwks_cache() -> None:
    """Clear the cached JWKS and OpenID config. Useful for testing and key rotation."""
    global _openid_config, _jwks, _jwks_fetched_at  # noqa: PLW0603
    _openid_config = None
    _jwks = None
    _jwks_fetched_at = 0.0
