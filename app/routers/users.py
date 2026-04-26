"""Users router — admin-only user management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin
from app.db.models import User
from app.db.session import get_db
from app.logging_config import get_logger
from app.schemas.common import PaginatedResponse
from app.schemas.user import UserDetail, UserUpdate
from app.services import user_service

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/users", tags=["users"])


@router.get(
    "/",
    response_model=PaginatedResponse[UserDetail],
    summary="List all users",
)
async def list_users(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> PaginatedResponse[UserDetail]:
    """List all users with pagination. Admin only."""
    users, total = await user_service.list_users(
        db,
        page=page,
        page_size=page_size,
    )
    items = [UserDetail.model_validate(u) for u in users]
    offset = (page - 1) * page_size
    return PaginatedResponse[UserDetail](
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(offset + page_size) < total,
    )


@router.get(
    "/{user_id}",
    response_model=UserDetail,
    summary="Get user detail",
)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> UserDetail:
    """Get a single user by ID. Admin only."""
    user = await user_service.get_user(db, user_id)
    return UserDetail.model_validate(user)


@router.patch(
    "/{user_id}",
    response_model=UserDetail,
    summary="Update user role or active status",
)
async def update_user(
    user_id: int,
    data: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> UserDetail:
    """Update a user's role and/or is_active status. Admin only.

    Cannot modify your own role or deactivate your own account.
    """
    user = await user_service.update_user(
        db,
        user_id,
        data=data,
        current_user=current_user,
        request=request,
    )
    return UserDetail.model_validate(user)
