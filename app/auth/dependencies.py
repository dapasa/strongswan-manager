from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import User, UserPermission
from app.db.session import get_db
from app.exceptions import AuthenticationError, AuthorizationError
from app.logging_config import get_logger

# ---------------------------------------------------------------------------
# Session revocation — second-precision rule
#
# Comparison: int(iat) >= int(tokens_valid_after.timestamp())
# Both are truncated to whole seconds (epoch). A token issued in the same
# second as the revocation is considered valid; at most a 1-second window
# exists for a stale token to slip through. This prevents accidental
# rejection of a fresh token obtained immediately after self-revocation.
# ---------------------------------------------------------------------------

logger = get_logger(__name__)

# OAuth2 scheme extracts Bearer token from Authorization header.
# tokenUrl is the local login endpoint; overridden by OIDC in oidc mode.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

# Role hierarchy: admin > operator > viewer
_ROLE_HIERARCHY: dict[str, int] = {
    "viewer": 0,
    "operator": 1,
    "admin": 2,
}


async def _resolve_user_local(token: str, db: AsyncSession) -> tuple[User, dict[str, Any]]:
    """Validate a local HS256 JWT and resolve to a User model instance.

    Returns the user and the decoded token payload (for iat extraction).
    """
    from app.auth.local import decode_access_token

    payload = decode_access_token(token)

    # Use primary-key uid claim for fast lookup; fall back to sub
    user_id: int | None = payload.get("uid")
    sub: str = payload["sub"]

    if user_id is not None:
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
    else:
        result = await db.execute(select(User).where(User.sub == sub))
        user = result.scalar_one_or_none()

    if user is None:
        raise AuthenticationError("User not found — token may reference a deleted account")

    return user, payload


async def _resolve_user_oidc(token: str, db: AsyncSession) -> tuple[User, dict[str, Any]]:
    """Validate an OIDC JWT and resolve (or auto-create) a User model instance.

    Returns the user and the decoded token claims (for iat extraction).

    Note on OIDC revocation: the app validates IdP-issued tokens directly (RS256).
    Setting tokens_valid_after applies the same iat check to IdP tokens. The user
    will be blocked until the IdP token expires and they re-authenticate — the app
    cannot force the IdP to revoke the token early.
    """
    from app.auth.oidc import validate_token

    claims = await validate_token(token)

    sub: str = claims["sub"]
    email: str = claims.get("email", "")
    display_name: str | None = claims.get("name") or claims.get("display_name")

    result = await db.execute(select(User).where(User.sub == sub))
    user = result.scalar_one_or_none()

    if user is None:
        user = User(
            sub=sub,
            email=email,
            display_name=display_name,
            role="viewer",
            is_active=True,
        )
        db.add(user)
        await db.flush()
        logger.info("Auto-created user on first OIDC login", sub=sub, email=email)

    # Sync metadata from IdP on every login
    user.email = email
    if display_name is not None:
        user.display_name = display_name
    user.last_login_at = func.now()
    await db.flush()

    return user, claims


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate Bearer token and resolve to a User model instance.

    Dispatches to the local or OIDC path depending on ``AUTH_MODE``:

    * ``local`` (default) — validates a locally-issued HS256 JWT and looks
      up the user by primary key.
    * ``oidc`` — validates an RS256 JWT from the configured external IdP and
      auto-creates users on first login.

    Raises :exc:`~app.exceptions.AuthenticationError` if the token is invalid.
    Raises :exc:`~app.exceptions.AuthorizationError` if the account is inactive.
    """
    settings = get_settings()

    if settings.auth_mode == "local":
        user, token_payload = await _resolve_user_local(token, db)
    else:
        user, token_payload = await _resolve_user_oidc(token, db)

    if not user.is_active:
        raise AuthorizationError("User account is deactivated")

    # Session revocation check — compare iat (epoch seconds) to tokens_valid_after.
    if user.tokens_valid_after is not None:
        iat: int | None = token_payload.get("iat")
        if iat is None:
            raise AuthenticationError("Token missing 'iat' claim; session may have been revoked")
        # Both sides truncated to whole seconds — see module-level rule comment.
        if int(iat) < int(user.tokens_valid_after.timestamp()):
            raise AuthenticationError("Session has been revoked; please log in again")

    return user


def require_role(required_role: str) -> Callable[..., Any]:
    """Return a FastAPI dependency that enforces a minimum role level.

    Role hierarchy: admin > operator > viewer.
    Admin has full access. Operator can manage resources. Viewer is read-only.

    Usage::

        @router.post("/tunnels", dependencies=[Depends(require_role("admin"))])
        async def create_tunnel(...): ...
    """
    required_level = _ROLE_HIERARCHY.get(required_role, 0)

    async def _check_role(current_user: User = Depends(get_current_user)) -> User:
        user_level = _ROLE_HIERARCHY.get(current_user.role, 0)
        if user_level < required_level:
            logger.warning(
                "Insufficient permissions",
                user_id=current_user.id,
                user_role=current_user.role,
                required_role=required_role,
            )
            raise AuthorizationError(
                f"Role '{required_role}' required, current role is '{current_user.role}'"
            )
        return current_user

    return _check_role


async def require_operator(current_user: User = Depends(get_current_user)) -> User:
    """Convenience dependency: require operator or admin role.

    Allows both operators and admins through. Viewers are rejected.

    Usage::

        @router.post("/tunnels", dependencies=[Depends(require_operator)])
        async def create_tunnel(...): ...
    """
    if _ROLE_HIERARCHY.get(current_user.role, 0) < _ROLE_HIERARCHY["operator"]:
        raise AuthorizationError("Operator access required")
    return current_user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Convenience dependency: require admin role.

    Usage::

        @router.delete("/tunnels/{id}", dependencies=[Depends(require_admin)])
        async def delete_tunnel(...): ...
    """
    if current_user.role != "admin":
        raise AuthorizationError("Admin access required")
    return current_user


async def require_viewer(current_user: User = Depends(get_current_user)) -> User:
    """Convenience dependency: require any authenticated active user.

    Semantically named alternative to ``get_current_user`` for read endpoints.
    Since ``get_current_user`` already validates the token and checks ``is_active``,
    this is functionally identical but makes the intent explicit in router code.
    """
    return current_user


# ---------------------------------------------------------------------------
# Tier 1 — per-action permission enforcement
# ---------------------------------------------------------------------------

async def _has_tier1_permission(
    user: User,
    perm_key: str,
    db: AsyncSession,
) -> bool:
    """Return True if the user holds the given Tier 1 permission.

    Rules:
    - admin: always True (implicit grant, no DB query).
    - viewer: always False (viewer is read-only).
    - operator: query user_permissions table.
    """
    if user.role == "admin":
        return True
    if _ROLE_HIERARCHY.get(user.role, 0) < _ROLE_HIERARCHY["operator"]:
        return False
    result = await db.execute(
        select(UserPermission).where(
            UserPermission.user_id == user.id,
            UserPermission.permission_key == perm_key,
        )
    )
    return result.scalar_one_or_none() is not None


async def assert_permission(
    user: User,
    perm_key: str,
    db: AsyncSession,
) -> None:
    """Raise AuthorizationError if the user lacks the given Tier 1 permission.

    Usage in route handlers::

        await assert_permission(current_user, "tunnels.write", db)
    """
    if not await _has_tier1_permission(user, perm_key, db):
        logger.warning(
            "insufficient_tier1_permission",
            user_id=user.id,
            user_role=user.role,
            required_permission=perm_key,
        )
        raise AuthorizationError(f"Permission '{perm_key}' required")


def require_permission(perm_key: str) -> Callable[..., Any]:
    """Return a FastAPI dependency that enforces a Tier 1 permission.

    Admin always passes.  Operators must have the permission in user_permissions.
    Viewers always fail.

    Usage::

        @router.post("/tunnels", dependencies=[Depends(require_permission("tunnels.write"))])
        async def create_tunnel(...): ...

    Or to also receive the current_user::

        @router.post("/tunnels")
        async def create_tunnel(
            current_user: User = Depends(require_permission("tunnels.write")),
            ...
        ): ...
    """
    async def _check(
        db: AsyncSession = Depends(get_db),
        current_user: User = Depends(get_current_user),
    ) -> User:
        await assert_permission(current_user, perm_key, db)
        return current_user

    return _check
