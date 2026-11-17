from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class PskStaleTunnel(BaseModel):
    """A tunnel whose PSK age exceeds the configured threshold."""

    id: int
    name: str
    psk_age_days: int


class DashboardSummary(BaseModel):
    """Aggregated dashboard metrics."""

    active_tunnels: int = Field(description="Count of tunnels with status='active'")
    active_routes: int = Field(description="Count of routes not soft-deleted")
    active_iptables_rules: int = Field(description="Count of iptables rules not soft-deleted")
    failed_syncs: int = Field(description="Count of entities with sync_status='failed'")
    pending_operations: int = Field(description="Count of async operations in pending/running state")
    last_change: datetime | None = Field(None, description="Timestamp of the most recent audit log entry")
    # --- operational health fields (backwards-compatible) ---
    sync_problems: int = Field(
        default=0,
        description="Tunnels with sync_status in (failed, partial, pending)",
    )
    psk_stale_count: int = Field(
        default=0,
        description="Count of tunnels whose PSK age exceeds the configured threshold",
    )
    psk_oldest_days: int | None = Field(
        default=None,
        description="Age in days of the oldest PSK across all non-deleted tunnels",
    )
    psk_stale_tunnels: list[PskStaleTunnel] = Field(
        default_factory=list,
        description="Tunnels with stale PSKs, sorted by age descending",
    )
