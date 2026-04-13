"""Operations router — poll async operation status."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_viewer
from app.db.models import User
from app.db.session import get_db
from app.schemas.operations import AsyncOperationDetail
from app.services.route_service import get_operation

router = APIRouter(prefix="/api/v1/operations", tags=["operations"])


@router.get(
    "/{operation_id}",
    response_model=AsyncOperationDetail,
    summary="Poll async operation status",
)
async def get_operation_status(
    operation_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> AsyncOperationDetail:
    """Get the current status of an async operation by its UUID."""
    operation = await get_operation(db, operation_id)
    return AsyncOperationDetail.model_validate(operation)
