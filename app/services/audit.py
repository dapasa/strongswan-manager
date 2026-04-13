"""Audit logging service — creates immutable audit trail entries."""

from __future__ import annotations

from typing import Any

from fastapi import Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AuditLog
from app.logging_config import get_logger

logger = get_logger(__name__)


async def log_action(
    session: AsyncSession,
    *,
    user_id: int | None,
    entity_type: str,
    entity_id: int | None,
    action: str,
    previous_state: dict[str, Any] | None = None,
    new_state: dict[str, Any] | None = None,
    request: Request | None = None,
) -> None:
    """Create an audit log entry for a CUD operation or login event.

    Does NOT commit the session — the caller is responsible for managing
    the transaction boundary so audit records are atomically committed
    with the operation they describe.

    Args:
        session: Active database session (caller manages commit).
        user_id: ID of the acting user, or None for system actions.
        entity_type: Type of entity affected (e.g., ``tunnel``, ``route``).
        entity_id: Primary key of the affected entity.
        action: One of ``create``, ``update``, ``delete``, ``retry``, ``login``.
        previous_state: JSONB snapshot of entity before the operation.
        new_state: JSONB snapshot of entity after the operation.
        request: FastAPI request object for extracting IP and user-agent.
    """
    ip_address: str | None = None
    user_agent: str | None = None

    if request is not None:
        ip_address = (
            request.headers.get("x-forwarded-for", "").split(",")[0].strip()
            or (request.client.host if request.client else None)
        )
        user_agent = request.headers.get("user-agent")

    entry = AuditLog(
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        previous_state=previous_state,
        new_state=new_state,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    session.add(entry)

    logger.info(
        "audit_log_created",
        user_id=user_id,
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
    )
