from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator, model_validator


class IPTablesRuleCreate(BaseModel):
    """Schema for creating a structured iptables rule.

    Two mutually exclusive families:

    filter (default)
        rule_table='filter', chain in INPUT/FORWARD/OUTPUT,
        action in ACCEPT/DROP/REJECT, to_source must be None.

    nat / SNAT
        rule_table='nat', chain='POSTROUTING', action='SNAT',
        dest_cidr required, to_source required (IPv4 address),
        state_match / sport / dport are not allowed.
    """

    rule_table: Literal["filter", "nat"] = Field("filter", description="iptables table (-t flag)")
    chain: Literal["INPUT", "FORWARD", "OUTPUT", "POSTROUTING"] = Field(..., description="Netfilter chain")
    protocol: Literal["tcp", "udp", "icmp", "all"] = Field(..., description="IP protocol")
    source_cidr: IPv4Network | None = Field(None, description="Source CIDR (-s)")
    dest_cidr: IPv4Network | None = Field(None, description="Destination CIDR (-d)")
    sport: int | None = Field(None, ge=1, le=65535, description="Source port (--sport)")
    dport: int | None = Field(None, ge=1, le=65535, description="Destination port (--dport)")
    action: Literal["ACCEPT", "DROP", "REJECT", "SNAT"] = Field(..., description="Target action (-j)")
    # SNAT target IP (--to-source). Required when rule_table='nat', forbidden otherwise.
    to_source: IPv4Address | None = Field(None, description="SNAT source IP (--to-source), nat rules only")
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
    def validate_rule_family(self) -> IPTablesRuleCreate:
        """Enforce filter/nat consistency rules."""
        if self.rule_table == "nat":
            # nat/SNAT requirements
            if self.chain != "POSTROUTING":
                raise ValueError("nat rules require chain='POSTROUTING'")
            if self.action != "SNAT":
                raise ValueError("nat rules require action='SNAT'")
            if self.dest_cidr is None:
                raise ValueError("SNAT rules require dest_cidr")
            if self.to_source is None:
                raise ValueError("SNAT rules require to_source (IPv4 address)")
            if self.state_match:
                raise ValueError("state_match is not allowed for SNAT rules")
            if self.sport is not None or self.dport is not None:
                raise ValueError("sport/dport are not allowed for SNAT rules")
        else:
            # filter requirements
            if self.chain not in ("INPUT", "FORWARD", "OUTPUT"):
                raise ValueError("filter rules require chain in INPUT/FORWARD/OUTPUT")
            if self.action not in ("ACCEPT", "DROP", "REJECT"):
                raise ValueError("filter rules require action in ACCEPT/DROP/REJECT")
            if self.to_source is not None:
                raise ValueError("to_source is only allowed for nat/SNAT rules")
            # Port-protocol consistency (existing rule)
            if (self.sport is not None or self.dport is not None) and self.protocol not in ("tcp", "udp"):
                raise ValueError("sport/dport require protocol 'tcp' or 'udp'")
        return self


class IPTablesRuleUpdate(BaseModel):
    """Schema for updating an iptables rule. All fields optional.

    When updating, the same family constraints apply: if rule_table or action
    changes you must supply a consistent set of fields.
    """

    rule_table: Literal["filter", "nat"] | None = None
    chain: Literal["INPUT", "FORWARD", "OUTPUT", "POSTROUTING"] | None = None
    protocol: Literal["tcp", "udp", "icmp", "all"] | None = None
    source_cidr: IPv4Network | None = None
    dest_cidr: IPv4Network | None = None
    sport: int | None = Field(None, ge=1, le=65535)
    dport: int | None = Field(None, ge=1, le=65535)
    action: Literal["ACCEPT", "DROP", "REJECT", "SNAT"] | None = None
    to_source: IPv4Address | None = None
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
    rule_table: str = Field("filter", description="iptables table (filter or nat)")
    chain: str
    protocol: str
    source_cidr: Any | None = None
    dest_cidr: Any | None = None
    sport: int | None = None
    dport: int | None = None
    action: str
    to_source: Any | None = Field(None, description="SNAT source IP (nat rules only)")
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

    @field_serializer("source_cidr", "dest_cidr", "to_source")
    def serialize_inet_fields(self, v: Any) -> str | None:
        return str(v) if v is not None else None
