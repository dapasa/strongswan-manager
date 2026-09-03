"""Local authentication — password hashing, JWT issuance and validation.

Used when AUTH_MODE=local (default). Issues HS256 JWTs signed with
JWT_SECRET_KEY. OIDC validation is preserved in app.auth.oidc for when
the project migrates back to an external provider.

Password hashing uses argon2id via argon2-cffi (already a transitive
dependency via another package). argon2id is the recommended algorithm
per OWASP 2023 and is salted by design.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from jose import JWTError, jwt

from app.config import get_settings
from app.exceptions import AuthenticationError
from app.logging_config import get_logger

logger = get_logger(__name__)

# argon2-cffi PasswordHasher with OWASP-recommended parameters.
# time_cost=3, memory_cost=65536 (64 MiB), parallelism=4
_ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


# ---------------------------------------------------------------------------
# Password helpers
# ---------------------------------------------------------------------------


def hash_password(plain_password: str) -> str:
    """Return an argon2id hash of *plain_password*.

    The returned string is self-contained (includes algorithm, params, and salt).
    """
    return _ph.hash(plain_password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Return True when *plain_password* matches *hashed_password*.

    Returns False (never raises) on any mismatch or hash format error.
    """
    try:
        return _ph.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------

_ALGORITHM = "HS256"


def create_access_token(*, user_id: int, sub: str, role: str) -> str:
    """Issue a signed JWT for the given user.

    Claims:
      - ``sub``: user identifier string (e.g. ``"local:user@example.com"``)
      - ``uid``: integer primary key (for fast DB lookup)
      - ``role``: current role at issuance time
      - ``exp``: expiry (``JWT_EXPIRE_MINUTES`` from now, default 480 min)
    """
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload: dict[str, Any] = {
        "sub": sub,
        "uid": user_id,
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=_ALGORITHM)


def decode_access_token(token: str) -> dict[str, Any]:
    """Decode and validate a local JWT.

    Returns the decoded payload on success.
    Raises :exc:`~app.exceptions.AuthenticationError` on any failure.
    """
    settings = get_settings()
    try:
        payload: dict[str, Any] = jwt.decode(token, settings.jwt_secret_key, algorithms=[_ALGORITHM])
    except JWTError as exc:
        logger.warning("Local JWT validation failed", error=str(exc))
        raise AuthenticationError("Invalid or expired token", detail=str(exc)) from exc

    if "sub" not in payload:
        raise AuthenticationError("Token missing required 'sub' claim")

    return payload
