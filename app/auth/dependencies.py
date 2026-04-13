from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.oidc import validate_token
from app.db.models import User
from app.db.session import get_db
from app.exceptions import AuthenticationError, AuthorizationError
from app.logging_config import get_logger

logger = get_logger(__name__)

# OAuth2 scheme extracts Bearer token from Authorization header.
# tokenUrl is a placeholder — actual OIDC flow happens externally via the SPA.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Role hierarchy: admin > viewer
_ROLE_HIERARCHY: dict[str, int] = {
    "viewer": 0,
    "admin": 1,
}


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate Bearer token and resolve to a User model instance.

    - Extracts and validates the JWT via OIDC provider.
    - Looks up user by ``sub`` claim.
    - Auto-creates on first login with role='viewer', is_active=True.
    - Syncs email and display_name from token claims on every login.
    - Raises AuthenticationError if token is invalid.
    - Raises AuthorizationError if user account is deactivated.
    """
    claims = await validate_token(token)

    sub: str = claims["sub"]
    email: str = claims.get("email", "")
    display_name: str | None = claims.get("name") or claims.get("display_name")

    # Look up existing user by OIDC subject
    result = await db.execute(select(User).where(User.sub == sub))
    user = result.scalar_one_or_none()

    if user is None:
        # Auto-create on first login
        user = User(
            sub=sub,
            email=email,
            display_name=display_name,
            role="viewer",
            is_active=True,
        )
        db.add(user)
        await db.flush()
        logger.info("Auto-created user on first login", sub=sub, email=email)

    # Check active status before allowing access
    if not user.is_active:
        raise AuthorizationError("User account is deactivated")

    # Sync metadata from IdP and update last_login_at on every login
    user.email = email
    if display_name is not None:
        user.display_name = display_name
    user.last_login_at = func.now()
    await db.flush()

    return user


def require_role(required_role: str) -> Callable[..., Any]:
    """Return a FastAPI dependency that enforces a minimum role level.

    Role hierarchy: admin > viewer.
    Admin has access to everything. Viewer is restricted to read operations.

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
