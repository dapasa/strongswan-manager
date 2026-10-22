from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_serializer, field_validator

from app.schemas.iptables import IPTablesRuleDetail
from app.schemas.route import RouteDetail
from app.schemas.user import UserBrief


class TunnelCreate(BaseModel):
    """Schema for creating a new IPSec tunnel."""

    name: str = Field(..., min_length=1, max_length=255, description="Unique tunnel name")
    description: str | None = None
    peer_ip: IPv4Address = Field(..., description="Remote peer IP address")
    local_cidrs: list[IPv4Network] = Field(..., min_length=1, description="Local CIDR ranges")
    remote_cidrs: list[IPv4Network] = Field(..., min_length=1, description="Remote CIDR ranges")
    psk: str = Field(..., min_length=1, description="Pre-shared key for the tunnel (encrypted with KMS and stored in the DB; never returned by the API)")
    ike_version: Literal["1", "2"] = Field(default="2", description="IKE protocol version")
    ike_proposals: str | None = Field(None, description="Custom IKE proposals (e.g., 'aes256-sha256-modp2048')")
    esp_proposals: str | None = Field(None, description="Custom ESP proposals")
    dpd_action: Literal["none", "clear", "restart"] = Field(default="restart", description="DPD action on timeout")
    dpd_delay: int = Field(default=30, ge=1, description="DPD delay in seconds")
    dpd_timeout: int = Field(default=150, ge=1, description="DPD timeout in seconds")
    local_id: str | None = Field(None, description="Local IKE identity (e.g. node's EIP). Omit to let strongSwan use the source IP.")
    remote_id: str | None = Field(None, description="IKE identity the peer presents (IP, FQDN or email). Leave blank to use the Peer IP.")
    start_action: Literal["trap", "none", "start"] = Field(default="trap", description="How to initiate the child SA: trap=route-based (auto=route), none=passive (auto=add), start=initiate immediately")
    ike_lifetime: int = Field(default=86400, ge=60, description="IKE SA lifetime in seconds")

    @field_validator("remote_id")
    @classmethod
    def validate_remote_id(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        if " " in v:
            raise ValueError("remote_id must not contain spaces")
        if '"' in v or "'" in v:
            raise ValueError("remote_id must not contain quotes")
        return v


class TunnelUpdate(BaseModel):
    """Schema for updating an existing tunnel. All fields optional."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    peer_ip: IPv4Address | None = None
    local_cidrs: list[IPv4Network] | None = None
    remote_cidrs: list[IPv4Network] | None = None
    psk: str | None = Field(None, description="New PSK value (re-encrypts with KMS and re-pushes to VPN nodes if provided)")
    ike_version: Literal["1", "2"] | None = None
    ike_proposals: str | None = None
    esp_proposals: str | None = None
    dpd_action: Literal["none", "clear", "restart"] | None = None
    dpd_delay: int | None = Field(None, ge=1)
    dpd_timeout: int | None = Field(None, ge=1)
    status: Literal["active", "inactive"] | None = None
    local_id: str | None = None
    remote_id: str | None = None
    start_action: Literal["trap", "none", "start"] | None = None
    ike_lifetime: int | None = Field(None, ge=60, description="IKE SA lifetime in seconds")

    @field_validator("remote_id")
    @classmethod
    def validate_remote_id(cls, v: str | None) -> str | None:
        if v is None:
            return v
        v = v.strip()
        if not v:
            return None
        if " " in v:
            raise ValueError("remote_id must not contain spaces")
        if '"' in v or "'" in v:
            raise ValueError("remote_id must not contain quotes")
        return v


class TunnelSummary(BaseModel):
    """Tunnel summary for list endpoints."""

    id: int
    name: str
    peer_ip: str
    status: str
    sync_status: str
    sync_error: str | None = None
    route_count: int = Field(description="Number of active routes")
    iptables_rule_count: int = Field(description="Number of active iptables rules")
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class TunnelDetail(BaseModel):
    """Full tunnel representation with nested routes and rules."""

    id: int
    name: str
    description: str | None = None
    peer_ip: Any
    local_cidrs: list[Any]
    remote_cidrs: list[Any]
    ike_version: str
    ike_proposals: str | None = None
    esp_proposals: str | None = None
    dpd_action: str
    dpd_delay: int
    dpd_timeout: int
    local_id: str | None = None
    remote_id: str | None = None
    start_action: str = "trap"
    ike_lifetime: int
    status: str
    sync_status: str
    sync_error: str | None = None
    routes: list[RouteDetail]
    iptables_rules: list[IPTablesRuleDetail]
    creator: UserBrief | None = Field(None, alias="creator")
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    @field_serializer("peer_ip")
    def serialize_peer_ip(self, v: Any) -> str:
        return str(v) if v is not None else None

    @field_serializer("local_cidrs", "remote_cidrs")
    def serialize_cidrs(self, v: list[Any]) -> list[str]:
        return [str(c) for c in v] if v else []


class ServerStateResult(BaseModel):
    """Per-server state from a tunnel status check."""

    server_id: int
    server_name: str
    state: str
    success: bool
    error: str | None = None


class TunnelStatus(BaseModel):
    """Live tunnel status from strongSwan via SSH fan-out."""

    tunnel_id: int
    name: str
    state: Literal["UP", "DOWN", "UNKNOWN", "PARTIAL"] = Field(description="Aggregated tunnel state across all servers")
    details: str | None = Field(None, description="Raw status details from strongSwan")
    per_server: list[ServerStateResult] = Field(default_factory=list, description="Per-server state breakdown")
    checked_at: datetime


class TunnelCheckStatusResult(BaseModel):
    """Result of an on-demand tunnel status check via SSH fan-out."""

    tunnel_id: int
    name: str
    state: Literal["UP", "DOWN", "UNKNOWN", "PARTIAL"] = Field(description="Aggregated operational state from ipsec status")
    raw_output: str = Field(description="Raw output from ipsec status command (last successful server)")
    per_server: list[ServerStateResult] = Field(default_factory=list, description="Per-server state breakdown")
    checked_at: datetime
