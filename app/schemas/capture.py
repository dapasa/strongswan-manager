"""Pydantic schemas for packet capture API."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field, field_validator


# Valid interfaces on the VPN nodes
VALID_INTERFACES = ("ens5", "ens6", "any")
VALID_PROTOCOLS = ("tcp", "udp", "icmp", "all")
HEADERS_SNAPLEN = 96
FULL_SNAPLEN = 0


class CaptureStart(BaseModel):
    """Request body to start a new packet capture."""

    server_id: int = Field(..., description="ID of the server (VPN node) to capture on")
    interface: str = Field(..., description="Network interface name")
    duration_seconds: int = Field(..., ge=10, description="Capture duration in seconds")
    mode: Literal["headers", "full"] = Field(default="headers")
    host_filter: str | None = Field(
        default=None,
        description="Host filter: IP address or CIDR (e.g. '10.0.0.1' or '10.0.0.0/24')",
    )
    port_filter: int | None = Field(
        default=None,
        ge=1,
        le=65535,
        description="Port filter (1-65535)",
    )
    protocol_filter: str = Field(default="all", description="Protocol filter")

    @field_validator("interface")
    @classmethod
    def validate_interface(cls, v: str) -> str:
        if v not in VALID_INTERFACES:
            raise ValueError(f"interface must be one of {VALID_INTERFACES}")
        return v

    @field_validator("protocol_filter")
    @classmethod
    def validate_protocol(cls, v: str) -> str:
        if v not in VALID_PROTOCOLS:
            raise ValueError(f"protocol_filter must be one of {VALID_PROTOCOLS}")
        return v

    @field_validator("host_filter")
    @classmethod
    def validate_host(cls, v: str | None) -> str | None:
        if v is None:
            return None
        import ipaddress
        try:
            # Accept both plain IPs and CIDRs
            ipaddress.ip_network(v, strict=False)
        except ValueError:
            raise ValueError(f"host_filter must be a valid IP address or CIDR: {v!r}")
        return v


class CaptureOut(BaseModel):
    """Response schema for a capture record."""

    id: int
    server_id: int
    user_id: int
    mode: str
    interface: str
    host_filter: str | None
    port_filter: int | None
    protocol_filter: str
    duration_seconds: int
    snaplen: int
    status: str
    size_bytes: int | None
    s3_object_key: str | None
    started_at: datetime | None
    completed_at: datetime | None
    error: str | None
    deleted_at: datetime | None
    created_at: datetime

    model_config = {"from_attributes": True}


class CaptureOutput(BaseModel):
    """Response schema for capture output (read result)."""

    capture_id: int
    lines: list[str]
    truncated: bool
    mode: str
    payload_shown: bool
