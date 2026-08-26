"""Pydantic schemas for Server CRUD operations — SSH and SSM transport."""

from __future__ import annotations

import re
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


_EC2_INSTANCE_RE = re.compile(r'^i-[0-9a-f]{17}$')


def _validate_ec2_instance_id(v: str | None) -> str | None:
    if v is not None and not _EC2_INSTANCE_RE.match(v):
        raise ValueError(
            "ec2_instance_id must match 'i-' followed by exactly 17 hex characters "
            f"(e.g. 'i-0e8545d009894bb9d'). Got: {v!r}"
        )
    return v


class ServerCreate(BaseModel):
    """Schema for creating a new server (SSH or SSM transport)."""

    name: str = Field(..., min_length=1, max_length=255, description="Unique server name")
    connection_type: Literal["ssh", "ssm"] = Field(
        default="ssh", description="Transport type: 'ssh' or 'ssm'"
    )
    description: str | None = None

    # SSH fields
    hostname: str | None = Field(None, min_length=1, max_length=255, description="Hostname or IP (SSH only)")
    ssh_port: int | None = Field(default=22, ge=1, le=65535, description="SSH port (default 22)")
    ssh_user: str | None = Field(default="admin", min_length=1, max_length=255, description="SSH username")
    ssh_private_key: str | None = Field(None, min_length=1, description="PEM-encoded SSH private key")

    # SSM fields
    ec2_instance_id: str | None = Field(None, description="EC2 instance ID (i-xxxxxxxxxxxxxxxxx)")
    aws_role_arn: str | None = Field(None, description="IAM role ARN (NULL → use global)")
    aws_region_override: str | None = Field(None, description="AWS region override (NULL → use global)")

    @model_validator(mode="after")
    def _validate_transport_fields(self) -> "ServerCreate":
        if self.connection_type == "ssh":
            missing = [f for f, v in [
                ("hostname", self.hostname),
                ("ssh_private_key", self.ssh_private_key),
            ] if not v]
            if missing:
                raise ValueError(
                    f"SSH server requires: {', '.join(missing)}"
                )
        else:  # ssm
            if not self.ec2_instance_id:
                raise ValueError("SSM server requires ec2_instance_id")
            _validate_ec2_instance_id(self.ec2_instance_id)
        return self


class ServerUpdate(BaseModel):
    """Schema for updating an existing server. All fields optional.

    connection_type IS editable — switching transport requires providing
    all fields for the new type.
    """

    name: str | None = Field(None, min_length=1, max_length=255)
    connection_type: Literal["ssh", "ssm"] | None = None
    description: str | None = None
    is_active: bool | None = None

    # SSH fields
    hostname: str | None = Field(None, min_length=1, max_length=255)
    ssh_port: int | None = Field(None, ge=1, le=65535)
    ssh_user: str | None = Field(None, min_length=1, max_length=255)
    ssh_private_key: str | None = Field(None, min_length=1, description="New PEM key (only if changing)")

    # SSM fields
    ec2_instance_id: str | None = None
    aws_role_arn: str | None = None
    aws_region_override: str | None = None

    @model_validator(mode="after")
    def _validate_ec2_fmt(self) -> "ServerUpdate":
        _validate_ec2_instance_id(self.ec2_instance_id)
        return self


class ServerSummary(BaseModel):
    """Server summary for list endpoints. SSH key is NEVER exposed."""

    id: int
    name: str
    connection_type: str
    # SSH fields (present only for ssh servers)
    hostname: str | None = None
    ssh_port: int | None = None
    ssh_user: str | None = None
    # SSM fields (present only for ssm servers)
    ec2_instance_id: str | None = None
    aws_role_arn: str | None = None
    aws_region_override: str | None = None
    # Common
    is_active: bool
    last_check_at: datetime | None = None
    last_check_status: str | None = None
    description: str | None = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ServerDetail(ServerSummary):
    """Full server representation. SSH key is NEVER exposed."""

    updated_at: datetime


class ServerTestResult(BaseModel):
    """Result of a connection test (not persisted)."""

    server_id: int
    server_name: str
    success: bool
    message: str
    tested_at: datetime


class ServerStatusResult(ServerTestResult):
    """Result of a status check (persisted to DB)."""

    status: str = Field(description="Persisted status: 'reachable' or 'unreachable'")
    checked_at: datetime
