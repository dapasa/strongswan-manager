from __future__ import annotations

from datetime import datetime
from ipaddress import IPv4Address, IPv4Network
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

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
    psk_secret_name: str = Field(..., min_length=1, description="AWS Secrets Manager secret name for PSK")
    ike_version: Literal["1", "2"] = Field(default="2", description="IKE protocol version")
    ike_proposals: str | None = Field(None, description="Custom IKE proposals (e.g., 'aes256-sha256-modp2048')")
    esp_proposals: str | None = Field(None, description="Custom ESP proposals")
    dpd_action: Literal["none", "clear", "restart"] = Field(default="restart", description="DPD action on timeout")
    dpd_delay: int = Field(default=30, ge=1, description="DPD delay in seconds")
    dpd_timeout: int = Field(default=150, ge=1, description="DPD timeout in seconds")


class TunnelUpdate(BaseModel):
    """Schema for updating an existing tunnel. All fields optional."""

    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    peer_ip: IPv4Address | None = None
    local_cidrs: list[IPv4Network] | None = None
    remote_cidrs: list[IPv4Network] | None = None
    psk_secret_name: str | None = None
    ike_version: Literal["1", "2"] | None = None
    ike_proposals: str | None = None
    esp_proposals: str | None = None
    dpd_action: Literal["none", "clear", "restart"] | None = None
    dpd_delay: int | None = Field(None, ge=1)
    dpd_timeout: int | None = Field(None, ge=1)
    status: Literal["active", "inactive"] | None = None


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
    peer_ip: str
    local_cidrs: list[str]
    remote_cidrs: list[str]
    psk_secret_name: str
    ike_version: str
    ike_proposals: str | None = None
    esp_proposals: str | None = None
    dpd_action: str
    dpd_delay: int
    dpd_timeout: int
    status: str
    sync_status: str
    sync_error: str | None = None
    routes: list[RouteDetail]
    iptables_rules: list[IPTablesRuleDetail]
    creator: UserBrief | None = Field(None, alias="creator")
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True, populate_by_name=True)


class TunnelStatus(BaseModel):
    """Live tunnel status from strongSwan via SSM."""

    tunnel_id: int
    name: str
    state: Literal["UP", "DOWN", "UNKNOWN"] = Field(description="Current tunnel state from ipsec statusall")
    details: str | None = Field(None, description="Raw status details from strongSwan")
    checked_at: datetime
