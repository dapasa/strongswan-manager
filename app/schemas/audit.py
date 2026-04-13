from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.user import UserBrief


class AuditLogEntry(BaseModel):
    """Single audit log record."""

    id: int
    user: UserBrief | None = None
    action: str = Field(description="Action: create, update, delete, retry, login")
    entity_type: str
    entity_id: int | None = None
    previous_state: dict | None = None
    new_state: dict | None = None
    ip_address: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AuditLogFilter(BaseModel):
    """Query parameters for filtering audit logs."""

    date_from: datetime | None = Field(None, description="Filter logs created after this timestamp")
    date_to: datetime | None = Field(None, description="Filter logs created before this timestamp")
    user_id: int | None = Field(None, description="Filter by user ID")
    entity_type: str | None = Field(None, description="Filter by entity type (e.g., 'tunnel', 'route')")
    action: str | None = Field(None, description="Filter by action (e.g., 'create', 'delete')")
