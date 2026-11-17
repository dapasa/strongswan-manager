from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class ReconcilerTunnelEntry(BaseModel):
    """A tunnel currently tracked by the in-memory reconciler state."""

    tunnel_id: int
    tunnel_name: str
    attempts: int


class ReconcilerStatus(BaseModel):
    """Read-only snapshot of the in-memory reconciler state."""

    enabled: bool = Field(description="Whether the reconciler background task is active")
    interval_seconds: int = Field(description="Seconds between reconciliation passes")
    max_attempts: int = Field(description="Max automated retries per tunnel per process lifetime")
    last_run_at: datetime | None = Field(
        default=None,
        description="Timestamp of the last completed reconciliation pass",
    )
    retrying: list[ReconcilerTunnelEntry] = Field(
        default_factory=list,
        description="Tunnels currently being retried (attempts < max_attempts)",
    )
    maxed: list[ReconcilerTunnelEntry] = Field(
        default_factory=list,
        description="Tunnels that hit max_attempts and are no longer being retried",
    )
