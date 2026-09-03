from __future__ import annotations

from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import User
from app.db.session import get_db
from app.exceptions import AuthenticationError, AuthorizationError
from app.logging_config import get_logger

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


async def _resolve_user_local(token: str, db: AsyncSession) -> User:
    """Validate a local HS256 JWT and resolve to a User model instance."""
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

    return user


async def _resolve_user_oidc(token: str, db: AsyncSession) -> User:
    """Validate an OIDC JWT and resolve (or auto-create) a User model instance."""
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

    return user


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
        user = await _resolve_user_local(token, db)
    else:
        user = await _resolve_user_oidc(token, db)

    if not user.is_active:
        raise AuthorizationError("User account is deactivated")

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
