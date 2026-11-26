"""Pydantic schemas for Tier 2 access requests."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Tier2CatalogEntry(BaseModel):
    """Single entry in the Tier 2 permission catalog."""

    permission_key: str
    description: str
    max_duration_hours: int


class Tier2Catalog(BaseModel):
    """Full Tier 2 catalog response."""

    entries: list[Tier2CatalogEntry]
    enabled: bool = Field(description="False when SHORTCUT_API_TOKEN is not configured")


class AccessRequestCreate(BaseModel):
    """Body for POST /api/v1/access-requests/."""

    permission_key: str = Field(
        ...,
        description="Tier 2 permission key (e.g. 'capture.full')",
    )
    duration_hours: int = Field(
        ...,
        ge=1,
        description="Requested duration in hours (must be <= catalog maximum)",
    )
    justification: str = Field(
        ...,
        min_length=10,
        description="Reason for the elevated access request",
    )


class AccessRequestDetail(BaseModel):
    """Full access request representation."""

    id: int
    user_id: int
    permission_key: str
    duration_hours: int = Field(description="Requested duration in hours")
    justification: str
    shortcut_story_id: int | None = None
    shortcut_story_url: str | None = None
    status: str
    approved_by_member_id: str | None = None
    approved_at: datetime | None = None
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    reason: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @classmethod
    def from_orm_with_hours(cls, obj: Any) -> "AccessRequestDetail":
        """Build from ORM instance, converting duration_seconds to hours."""
        d = {
            "id": obj.id,
            "user_id": obj.user_id,
            "permission_key": obj.permission_key,
            "duration_hours": max(1, obj.duration_seconds // 3600),
            "justification": obj.justification,
            "shortcut_story_id": obj.shortcut_story_id,
            "shortcut_story_url": obj.shortcut_story_url,
            "status": obj.status,
            "approved_by_member_id": obj.approved_by_member_id,
            "approved_at": obj.approved_at,
            "expires_at": obj.expires_at,
            "revoked_at": obj.revoked_at,
            "reason": obj.reason,
            "created_at": obj.created_at,
        }
        return cls(**d)
