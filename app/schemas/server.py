"""Pydantic schemas for Server CRUD operations."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ServerCreate(BaseModel):
    """Schema for creating a new server."""

    name: str = Field(..., min_length=1, max_length=255, description="Unique server name")
    hostname: str = Field(..., min_length=1, max_length=255, description="Server hostname or IP address")
    ssh_port: int = Field(default=22, ge=1, le=65535, description="SSH port number")
    ssh_user: str = Field(default="admin", min_length=1, max_length=255, description="SSH username")
    ssh_private_key: str = Field(..., min_length=1, description="PEM-encoded SSH private key")
    description: str | None = None


class ServerUpdate(BaseModel):
    """Schema for updating an existing server. All fields optional."""

    name: str | None = Field(None, min_length=1, max_length=255)
    hostname: str | None = Field(None, min_length=1, max_length=255)
    ssh_port: int | None = Field(None, ge=1, le=65535)
    ssh_user: str | None = Field(None, min_length=1, max_length=255)
    ssh_private_key: str | None = Field(None, min_length=1, description="New PEM key (only if changing)")
    description: str | None = None
    is_active: bool | None = None


class ServerSummary(BaseModel):
    """Server summary for list endpoints. Never exposes SSH key."""

    id: int
    name: str
    hostname: str
    ssh_port: int
    ssh_user: str
    is_active: bool
    last_check_at: datetime | None = None
    last_check_status: str | None = None
    description: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ServerDetail(ServerSummary):
    """Full server representation. Never exposes SSH key."""

    updated_at: datetime


class ServerTestResult(BaseModel):
    """Result of an SSH connection test (not persisted)."""

    server_id: int
    server_name: str
    success: bool
    message: str
    tested_at: datetime


class ServerStatusResult(ServerTestResult):
    """Result of an SSH status check (persisted to DB)."""

    status: str = Field(description="Persisted status: 'reachable' or 'unreachable'")
    checked_at: datetime
