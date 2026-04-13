from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class DashboardSummary(BaseModel):
    """Aggregated dashboard metrics."""

    active_tunnels: int = Field(description="Count of tunnels with status='active'")
    active_routes: int = Field(description="Count of routes not soft-deleted")
    active_iptables_rules: int = Field(description="Count of iptables rules not soft-deleted")
    failed_syncs: int = Field(description="Count of entities with sync_status='failed'")
    pending_operations: int = Field(description="Count of async operations in pending/running state")
    last_change: datetime | None = Field(None, description="Timestamp of the most recent audit log entry")
