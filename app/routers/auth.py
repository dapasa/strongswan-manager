"""Auth router — login endpoint and current user profile."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.auth.local import create_access_token, verify_password
from app.config import get_settings
from app.db.models import User
from app.db.session import get_db
from app.exceptions import AuthenticationError
from app.logging_config import get_logger
from app.schemas.user import UserDetail
from app.services import audit

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
    from sqlalchemy import func
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
    response_model=UserDetail,
    summary="Get current user profile",
)
async def get_me(
    current_user: User = Depends(get_current_user),
) -> UserDetail:
    """Return the profile of the currently authenticated user."""
    return UserDetail.model_validate(current_user)
