"""User management service — list and update users (admin only)."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import User
from app.exceptions import NotFoundError, ValidationError
from app.logging_config import get_logger
from app.services import audit

logger = get_logger(__name__)


def _user_to_dict(user: User) -> dict[str, Any]:
    """Serialize a User model to a dict suitable for audit JSONB storage."""
    return {
        "id": user.id,
        "email": user.email,
        "display_name": user.display_name,
        "role": user.role,
        "is_active": user.is_active,
        "last_login_at": user.last_login_at.isoformat() if user.last_login_at else None,
    }


async def list_users(
    session: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
) -> tuple[list[User], int]:
    """List all users with pagination.

    Args:
        session: Active database session.
        page: Page number (1-indexed).
        page_size: Number of items per page.

    Returns:
        Tuple of (list of User instances, total count).
    """
    # Count query
    count_stmt = select(func.count()).select_from(User)
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Paginated items query
    offset = (page - 1) * page_size
    items_stmt = (
        select(User)
        .order_by(User.email)
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(items_stmt)
    return list(result.scalars().all()), total


async def get_user(session: AsyncSession, user_id: int) -> User:
    """Get a single user by ID.

    Args:
        session: Active database session.
        user_id: Primary key of the user.

    Returns:
        The User instance.

    Raises:
        NotFoundError: If no user with the given ID exists.
    """
    result = await session.execute(
        select(User).where(User.id == user_id),
    )
    user = result.scalar_one_or_none()
    if user is None:
        raise NotFoundError("User", user_id)
    return user


async def update_user(
    session: AsyncSession,
    user_id: int,
    *,
    data: Any,
    current_user: User,
    request: Request | None = None,
) -> User:
    """Update a user's role and/or is_active status.

    Prevents self-demotion (admin changing own role to non-admin) and
    self-deactivation (admin setting own is_active to false).

    Args:
        session: Active database session.
        user_id: Primary key of the user to update.
        data: UserUpdate schema instance.
        current_user: The admin performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The updated User instance.

    Raises:
        NotFoundError: If the user does not exist.
        ValidationError: If the admin tries to self-demote or self-deactivate.
    """
    user = await get_user(session, user_id)
    previous_state = _user_to_dict(user)

    update_data = data.model_dump(exclude_unset=True)

    # Self-modification guards
    if current_user.id == user_id:
        if "role" in update_data and update_data["role"] != "admin":
            raise ValidationError("Cannot change your own role")
        if "is_active" in update_data and update_data["is_active"] is False:
            raise ValidationError("Cannot deactivate your own account")

    # Apply updates
    for field, value in update_data.items():
        setattr(user, field, value)

    # Audit log
    await audit.log_action(
        session,
        user_id=current_user.id,
        entity_type="user",
        entity_id=user.id,
        action="update",
        previous_state=previous_state,
        new_state=_user_to_dict(user),
        request=request,
    )

    await session.flush()
    return user
