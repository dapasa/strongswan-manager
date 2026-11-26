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
    shortcut_member_id: str | None = None

    model_config = ConfigDict(from_attributes=True)


class UserProfile(UserDetail):
    """Extended user representation for /me — includes effective permissions.

    tier1_permissions: Tier 1 permission keys the user holds.
      - admin: all keys (populated server-side, no DB query needed).
      - operator: only the keys explicitly granted.
      - viewer: empty list.

    active_tier2: Tier 2 permission keys with an active, non-expired grant.
    """

    tier1_permissions: list[str] = Field(default_factory=list)
    active_tier2: list[str] = Field(default_factory=list)


class UserCreate(BaseModel):
    """Internal schema for creating a user from OIDC claims. Not exposed via API."""

    sub: str = Field(..., min_length=1, description="OIDC subject claim")
    email: str = Field(..., min_length=1, description="Email from OIDC token")
    display_name: str | None = None


class UserUpdate(BaseModel):
    """Schema for updating user role/status/shortcut_member_id (admin only)."""

    role: str | None = Field(None, pattern="^(admin|operator|viewer)$", description="User role")
    is_active: bool | None = None
    shortcut_member_id: str | None = None


class UserPermissionsUpdate(BaseModel):
    """Schema for setting the full Tier 1 permission set for a user (admin only)."""

    permissions: list[str] = Field(
        default_factory=list,
        description=(
            "Full list of Tier 1 permission keys to grant. Unknown keys are ignored. "
            "Pass an empty list to revoke all permissions."
        ),
    )


class UserPermissionsResponse(BaseModel):
    """Response for GET/PUT /users/{id}/permissions."""

    user_id: int
    permissions: list[str]


class UserListResponse(BaseModel):
    """Paginated user list response for admin endpoints."""

    items: list[UserDetail]
    total: int = Field(description="Total number of users")
    page: int = Field(description="Current page number")
    page_size: int = Field(description="Items per page")
    has_next: bool = Field(description="Whether more pages are available")
