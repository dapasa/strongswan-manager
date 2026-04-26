from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class UserBrief(BaseModel):
    """Minimal user representation embedded in other responses."""

    id: int
    email: str
    display_name: str | None = None

    model_config = ConfigDict(from_attributes=True)


class UserDetail(BaseModel):
    """Full user representation for admin endpoints."""

    id: int
    email: str
    display_name: str | None = None
    role: str = Field(description="User role: 'admin', 'operator', or 'viewer'")
    is_active: bool
    last_login_at: datetime | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class UserCreate(BaseModel):
    """Internal schema for creating a user from OIDC claims. Not exposed via API."""

    sub: str = Field(..., min_length=1, description="OIDC subject claim")
    email: str = Field(..., min_length=1, description="Email from OIDC token")
    display_name: str | None = None


class UserUpdate(BaseModel):
    """Schema for updating user role/status (admin only)."""

    role: str | None = Field(None, pattern="^(admin|operator|viewer)$", description="User role")
    is_active: bool | None = None


class UserListResponse(BaseModel):
    """Paginated user list response for admin endpoints."""

    items: list[UserDetail]
    total: int = Field(description="Total number of users")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    has_next: bool = Field(description="Whether more pages are available")
