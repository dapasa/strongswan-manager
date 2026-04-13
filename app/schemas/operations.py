from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class AsyncOperationRef(BaseModel):
    """Returned in 202 responses pointing to a background operation."""

    operation_id: UUID
    status: str = Field(description="Initial status: 'pending'")
    poll_url: str = Field(description="URL to poll for operation status")


class AsyncOperationDetail(BaseModel):
    """Full async operation status for polling endpoint."""

    id: UUID
    entity_type: str = Field(description="Entity type (e.g., 'route')")
    entity_id: int
    operation: str = Field(description="Operation type: create, update, delete")
    status: str = Field(description="Status: pending, running, completed, failed")
    started_at: datetime | None = None
    completed_at: datetime | None = None
    result: dict | None = Field(None, description="Operation result on success")
    error_message: str | None = Field(None, description="Error details on failure")
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
