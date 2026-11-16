"""Drift detection schemas — per-tunnel config comparison results."""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel


class TunnelDriftResult(BaseModel):
    """Drift comparison result for one tunnel on one server."""

    tunnel_id: int
    tunnel_name: str
    status: Literal["in_sync", "drifted", "missing_on_node"]
    expected_hashes: dict[str, str]  # path -> sha256 of rendered DB content
    actual_hashes: dict[str, str]    # path -> sha256 read from node (empty when missing)


class ServerDriftReport(BaseModel):
    """Full drift report for a single server across all (or one filtered) tunnel(s)."""

    server_id: int
    server_name: str
    tunnels: list[TunnelDriftResult]
    orphan_files: list[str]  # paths in manager dirs that belong to no known tunnel
    checked_at: datetime
