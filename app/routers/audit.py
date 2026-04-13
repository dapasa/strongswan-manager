"""Audit log router — paginated, filterable audit trail."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_viewer
from app.db.models import AuditLog, User
from app.db.session import get_db
from app.schemas.audit import AuditLogEntry
from app.schemas.common import PaginatedResponse

router = APIRouter(prefix="/api/v1/audit", tags=["audit"])


@router.get(
    "/",
    response_model=PaginatedResponse[AuditLogEntry],
    summary="List audit log entries",
)
async def list_audit_logs(
    date_from: datetime | None = Query(None, description="Filter logs after this timestamp"),
    date_to: datetime | None = Query(None, description="Filter logs before this timestamp"),
    user_id: int | None = Query(None, description="Filter by user ID"),
    entity_type: str | None = Query(None, description="Filter by entity type"),
    action: str | None = Query(None, description="Filter by action"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(50, ge=1, le=100, description="Items per page"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> PaginatedResponse[AuditLogEntry]:
    """List audit log entries with filtering and pagination."""
    # Build base query with filters
    base_stmt = select(AuditLog)
    count_stmt = select(func.count()).select_from(AuditLog)

    if date_from is not None:
        base_stmt = base_stmt.where(AuditLog.created_at >= date_from)
        count_stmt = count_stmt.where(AuditLog.created_at >= date_from)
    if date_to is not None:
        base_stmt = base_stmt.where(AuditLog.created_at <= date_to)
        count_stmt = count_stmt.where(AuditLog.created_at <= date_to)
    if user_id is not None:
        base_stmt = base_stmt.where(AuditLog.user_id == user_id)
        count_stmt = count_stmt.where(AuditLog.user_id == user_id)
    if entity_type is not None:
        base_stmt = base_stmt.where(AuditLog.entity_type == entity_type)
        count_stmt = count_stmt.where(AuditLog.entity_type == entity_type)
    if action is not None:
        base_stmt = base_stmt.where(AuditLog.action == action)
        count_stmt = count_stmt.where(AuditLog.action == action)

    # Total count
    total_result = await db.execute(count_stmt)
    total = total_result.scalar_one()

    # Paginated results ordered by most recent first
    offset = (page - 1) * page_size
    items_stmt = (
        base_stmt
        .order_by(AuditLog.created_at.desc())
        .offset(offset)
        .limit(page_size)
    )
    items_result = await db.execute(items_stmt)
    logs = items_result.scalars().all()

    return PaginatedResponse[AuditLogEntry](
        items=[AuditLogEntry.model_validate(log) for log in logs],
        total=total,
        page=page,
        page_size=page_size,
        has_next=(offset + page_size) < total,
    )
