"""Fan-out result types for multi-server SSH command execution."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ServerResult:
    """Result of executing commands on a single server."""

    server_id: int
    server_name: str
    success: bool
    output: str = ""
    error: str = ""


@dataclass
class FanOutResult:
    """Aggregate result from executing commands on multiple servers."""

    total: int
    succeeded: int
    failed: int
    servers: list[ServerResult] = field(default_factory=list)

    @property
    def is_partial(self) -> bool:
        return self.failed > 0 and self.succeeded > 0

    @property
    def is_total_failure(self) -> bool:
        return self.succeeded == 0

    @property
    def is_success(self) -> bool:
        return self.failed == 0

    def to_sync_details(self) -> dict:
        """Return a JSON-serializable dict for storing in sync_details JSONB column."""
        return {
            "total": self.total,
            "succeeded": self.succeeded,
            "failed": self.failed,
            "servers": [
                {
                    "server_id": r.server_id,
                    "server_name": r.server_name,
                    "success": r.success,
                    "error": r.error or None,
                }
                for r in self.servers
            ],
        }

    def to_sync_status(self) -> str:
        """Return the sync_status string based on result."""
        if self.is_success:
            return "synced"
        if self.is_partial:
            return "partial"
        return "failed"

    def to_sync_error(self) -> str | None:
        """Return a summary error string if any failures, else None."""
        if self.is_success:
            return None
        return f"{self.failed} of {self.total} servers failed to sync"
