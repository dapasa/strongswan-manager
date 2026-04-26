from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Network

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer


class RouteCreate(BaseModel):
    """Schema for creating a new route on a tunnel."""

    cidr: IPv4Network = Field(..., description="CIDR range for the route (e.g., '10.0.0.0/24')")
    description: str | None = None


class RouteDetail(BaseModel):
    """Full route representation."""

    id: int
    tunnel_id: int
    cidr: Any
    description: str | None = None
    sync_status: str = Field(description="Sync state: synced, pending, cloning, planning, applying, pushing, failed, pending_delete")
    sync_error: str | None = None
    created_by: int | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("cidr")
    def serialize_cidr(self, v: Any) -> str:
        return str(v) if v is not None else None
