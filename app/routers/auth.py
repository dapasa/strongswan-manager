"""Auth router — current user profile endpoint."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from app.auth import get_current_user
from app.db.models import User
from app.schemas.user import UserDetail

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])


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
