"""Auth router — login endpoint and current user profile."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.auth.local import create_access_token, verify_password
from app.config import get_settings
from app.db.models import TIER1_PERMISSION_KEYS, User
from app.db.session import get_db
from app.exceptions import AuthenticationError
from app.logging_config import get_logger
from app.schemas.user import UserDetail, UserProfile
from app.services import audit, user_service
from app.services import permissions as perm_service

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class LoginRequest(BaseModel):
    username: str = Field(..., description="User email address")
    password: str = Field(..., min_length=1, description="User password")


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post(
    "/token",
    response_model=TokenResponse,
    summary="Obtain a local access token",
)
async def login(
    body: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> TokenResponse:
    """Authenticate with username (email) and password.

    Issues a signed JWT on success. The token must be sent as a
    ``Bearer`` header on all subsequent requests.

    Only available when ``AUTH_MODE=local`` (default). Returns 400 if the
    application is configured for OIDC mode.

    Failed attempts are not audited to avoid leaking whether an account
    exists. Successful logins write a ``login`` audit entry.
    """
    settings = get_settings()
    if settings.auth_mode != "local":
        raise AuthenticationError("Local login is disabled — use the configured OIDC provider")

    # Look up user by email (email is the login identity in local mode)
    result = await db.execute(select(User).where(User.email == body.username))
    user = result.scalar_one_or_none()

    if user is None or user.password_hash is None or not verify_password(body.password, user.password_hash):
        logger.warning("Failed login attempt", email=body.username)
        raise AuthenticationError("Invalid credentials")

    if not user.is_active:
        raise AuthenticationError("Account is deactivated")

    token = create_access_token(user_id=user.id, sub=user.sub, role=user.role)

    # Update last_login_at
    user.last_login_at = func.now()

    # Audit the successful login
    await audit.log_action(
        db,
        user_id=user.id,
        entity_type="user",
        entity_id=user.id,
        action="login",
        new_state={"email": user.email, "role": user.role},
        request=request,
    )

    await db.commit()

    logger.info("Successful login", user_id=user.id, email=user.email)
    return TokenResponse(access_token=token)


@router.get(
    "/me",
    response_model=UserProfile,
    summary="Get current user profile with effective permissions",
)
async def get_me(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserProfile:
    """Return the profile of the currently authenticated user.

    Includes ``tier1_permissions`` (Tier 1 grants) and ``active_tier2``
    (active Tier 2 grants, not expired) so the UI can hide/disable buttons.
    """
    # Tier 1
    if current_user.role == "admin":
        tier1 = list(TIER1_PERMISSION_KEYS)
    elif current_user.role == "operator":
        tier1 = await perm_service.get_user_permission_keys(db, current_user.id)
    else:
        tier1 = []

    # Tier 2
    active_tier2 = await perm_service.get_active_tier2_permission_keys(db, current_user.id)

    profile = UserProfile(
        **UserDetail.model_validate(current_user).model_dump(),
        tier1_permissions=tier1,
        active_tier2=active_tier2,
    )
    return profile


@router.post(
    "/logout-all",
    response_model=UserDetail,
    summary="Revoke all active sessions (self-service)",
)
async def logout_all(
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> UserDetail:
    """Invalidate all outstanding tokens for the current user.

    Sets tokens_valid_after = now(). The caller's current token is still
    accepted for this single request (get_current_user runs before the
    update). The client should discard the token and log out locally after
    this call.
    """
    user = await user_service.revoke_user_sessions(
        db,
        current_user.id,
        acting_user=current_user,
        request=request,
    )
    return UserDetail.model_validate(user)
