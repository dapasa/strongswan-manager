"""Users router — admin-only user management endpoints + Tier 1 permissions."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user, require_admin
from app.db.models import TIER1_PERMISSION_KEYS, User
from app.db.session import get_db
from app.logging_config import get_logger
from app.schemas.common import PaginatedResponse
from app.schemas.user import (
    UserDetail,
    UserPermissionsResponse,
    UserPermissionsUpdate,
    UserUpdate,
)
from app.services import permissions as perm_service
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
    summary="Update user role, active status, or Shortcut member ID",
)
async def update_user(
    user_id: int,
    data: UserUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> UserDetail:
    """Update a user's role, is_active status, and/or Shortcut member ID. Admin only.

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


@router.post(
    "/{user_id}/revoke-sessions",
    response_model=UserDetail,
    summary="Revoke all active sessions for a user",
)
async def revoke_user_sessions(
    user_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> UserDetail:
    """Invalidate all outstanding tokens for a user. Admin only.

    Sets tokens_valid_after = now(). The user is not deactivated — they
    can log in again immediately to obtain a fresh token.
    """
    user = await user_service.revoke_user_sessions(
        db,
        user_id,
        acting_user=current_user,
        request=request,
    )
    return UserDetail.model_validate(user)


# ---------------------------------------------------------------------------
# Tier 1 permission management (admin only)
# ---------------------------------------------------------------------------

@router.get(
    "/{user_id}/permissions",
    response_model=UserPermissionsResponse,
    summary="Get Tier 1 permissions for a user",
)
async def get_user_permissions(
    user_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> UserPermissionsResponse:
    """Return the full set of Tier 1 permissions explicitly granted to a user.

    Admin users implicitly hold every permission; this endpoint still returns
    the DB rows (which will be empty for admins, since they never need them).
    """
    user = await user_service.get_user(db, user_id)
    if user.role == "admin":
        # Admin has all permissions implicitly; return the full catalog
        return UserPermissionsResponse(
            user_id=user_id,
            permissions=list(TIER1_PERMISSION_KEYS),
        )
    keys = await perm_service.get_user_permission_keys(db, user_id)
    return UserPermissionsResponse(user_id=user_id, permissions=sorted(keys))


@router.put(
    "/{user_id}/permissions",
    response_model=UserPermissionsResponse,
    summary="Set Tier 1 permissions for a user",
)
async def set_user_permissions(
    user_id: int,
    data: UserPermissionsUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> UserPermissionsResponse:
    """Replace the full Tier 1 permission set for a user. Admin only.

    - Pass an empty list to revoke all permissions.
    - Unknown keys are silently ignored.
    - Admin users are skipped (they always have all permissions implicitly).
    """
    user = await user_service.get_user(db, user_id)
    if user.role == "admin":
        return UserPermissionsResponse(
            user_id=user_id,
            permissions=list(TIER1_PERMISSION_KEYS),
        )
    keys = await perm_service.set_user_permissions(db, user_id, data.permissions)
    await db.commit()
    return UserPermissionsResponse(user_id=user_id, permissions=sorted(keys))
