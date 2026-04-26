from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Network
from typing import Literal

from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator

class IPTablesRuleCreate(BaseModel):
    """Schema for creating a structured iptables rule."""

    chain: Literal["INPUT", "FORWARD", "OUTPUT"] = Field(..., description="Netfilter chain")
    protocol: Literal["tcp", "udp", "icmp", "all"] = Field(..., description="IP protocol")
    source_cidr: IPv4Network | None = Field(None, description="Source CIDR (-s)")
    dest_cidr: IPv4Network | None = Field(None, description="Destination CIDR (-d)")
    sport: int | None = Field(None, ge=1, le=65535, description="Source port (--sport)")
    dport: int | None = Field(None, ge=1, le=65535, description="Destination port (--dport)")
    action: Literal["ACCEPT", "DROP", "REJECT"] = Field(..., description="Target action (-j)")
    state_match: list[Literal["NEW", "ESTABLISHED", "RELATED", "INVALID"]] | None = Field(
        None,
        description="Connection tracking states (-m state --state)",
    )
    comment: str | None = Field(None, max_length=256, description="Rule comment (-m comment)")
    position: int | None = Field(None, ge=0, description="Position in chain (for -I)")

    @field_validator("comment")
    @classmethod
    def validate_comment(cls, v: str | None) -> str | None:
        """Reject shell metacharacters to prevent command injection."""
        if v is None:
            return v
        forbidden = set(";|&$`\n\r\\\"'")
        if any(c in forbidden for c in v):
            raise ValueError("Comment contains forbidden characters")
        return v

    @model_validator(mode="after")
    def validate_port_requires_protocol(self) -> IPTablesRuleCreate:
        """Ports are only valid with tcp or udp protocol."""
        if (self.sport is not None or self.dport is not None) and self.protocol not in ("tcp", "udp"):
            raise ValueError("sport/dport require protocol 'tcp' or 'udp'")
        return self


class IPTablesRuleUpdate(BaseModel):
    """Schema for updating an iptables rule. All fields optional."""

    chain: Literal["INPUT", "FORWARD", "OUTPUT"] | None = None
    protocol: Literal["tcp", "udp", "icmp", "all"] | None = None
    source_cidr: IPv4Network | None = None
    dest_cidr: IPv4Network | None = None
    sport: int | None = Field(None, ge=1, le=65535)
    dport: int | None = Field(None, ge=1, le=65535)
    action: Literal["ACCEPT", "DROP", "REJECT"] | None = None
    state_match: list[Literal["NEW", "ESTABLISHED", "RELATED", "INVALID"]] | None = None
    comment: str | None = Field(None, max_length=256)
    position: int | None = Field(None, ge=0)

    @field_validator("comment")
    @classmethod
    def validate_comment(cls, v: str | None) -> str | None:
        """Reject shell metacharacters to prevent command injection."""
        if v is None:
            return v
        forbidden = set(";|&$`\n\r\\\"'")
        if any(c in forbidden for c in v):
            raise ValueError("Comment contains forbidden characters")
        return v


class IPTablesRuleDetail(BaseModel):
    """Full iptables rule representation."""

    id: int
    tunnel_id: int
    chain: str
    protocol: str
    source_cidr: Any | None = None
    dest_cidr: Any | None = None
    sport: int | None = None
    dport: int | None = None
    action: str
    state_match: list[str] | None = None
    comment: str | None = None
    position: int | None = None
    sync_status: str = Field(description="Sync state: synced, pending, failed, pending_delete")
    sync_error: str | None = None
    command_preview: str | None = Field(None, description="Generated iptables command for preview")
    created_by: int | None = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)

    @field_serializer("source_cidr", "dest_cidr")
    def serialize_cidrs(self, v: Any) -> str | None:
        return str(v) if v is not None else None
