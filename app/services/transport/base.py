"""Abstract transport interface for VPN node connectivity.

Defines the protocol that all transport backends (SSH, SSM, …) must implement.
Callers depend only on this module — never on a concrete implementation.
"""

from __future__ import annotations

import enum
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


class TransportErrorKind(enum.Enum):
    """Broad category of a transport failure."""

    NODE_UNREACHABLE = "node_unreachable"
    PERMISSION_DENIED = "permission_denied"
    COMMAND_FAILED = "command_failed"
    TIMEOUT = "timeout"
    UNKNOWN = "unknown"


class TransportError(Exception):
    """Raised by any NodeTransport implementation on failure.

    Attributes:
        message:   Human-readable description of the error.
        kind:      Broad failure category for programmatic handling.
        stderr:    Stderr captured from the remote command, if any.
        exit_code: Remote process exit code, if applicable.
    """

    def __init__(
        self,
        message: str,
        *,
        kind: TransportErrorKind = TransportErrorKind.UNKNOWN,
        stderr: str = "",
        exit_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.kind = kind
        self.stderr = stderr
        self.exit_code = exit_code


@dataclass
class CommandResult:
    """Output from a successful remote command execution."""

    stdout: str = ""
    stderr: str = ""
    exit_code: int = 0


class NodeTransport(ABC):
    """Protocol for executing commands and managing files on a VPN node.

    All methods raise TransportError on failure.  Implementations must never
    raise asyncssh.Error, OSError, or other backend-specific exceptions to
    callers — those are wrapped into TransportError before leaving the
    implementation.
    """

    @abstractmethod
    async def execute(
        self,
        commands: list[str],
        *,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run shell commands joined with ' && ' on the remote node.

        Args:
            commands: One or more shell commands to execute in sequence.
            timeout:  Per-call timeout in seconds.  None means no extra limit.

        Returns:
            CommandResult with stdout/stderr/exit_code on success (exit_code == 0).

        Raises:
            TransportError: On any failure (connection, auth, nonzero exit, …).
        """

    @abstractmethod
    async def write_file(
        self,
        path: str,
        content: str,
        *,
        mode: str = "644",
        make_dirs: bool = True,
    ) -> None:
        """Write *content* to *path* on the remote node.

        Uses elevated privileges (sudo) so the SSH user does not need direct
        write access to the target directory.

        Args:
            path:      Absolute remote path to write.
            content:   File content.
            mode:      chmod value applied after writing (e.g. "644", "640").
            make_dirs: If True, ensure the parent directory exists first.

        Raises:
            TransportError: On mkdir, write, or chmod failure.
        """

    @abstractmethod
    async def delete_file(self, path: str) -> None:
        """Remove *path* from the remote node (idempotent — missing file is OK).

        Args:
            path: Absolute remote path to remove.

        Raises:
            TransportError: If the remove command fails for a reason other than
                            file-not-found.
        """

    @abstractmethod
    async def rename_file(self, src: str, dst: str) -> None:
        """Rename/move *src* to *dst* on the remote node.

        Args:
            src: Current absolute remote path.
            dst: New absolute remote path.

        Raises:
            TransportError: On failure.
        """

    @abstractmethod
    async def check_reachable(self, *, timeout: int = 10) -> bool:
        """Verify that the node is reachable by opening and closing a connection.

        Returns:
            True when the node is reachable.

        Raises:
            TransportError: When the node cannot be reached or authentication fails.
            Exception:      Re-raises unexpected exceptions so callers can decide
                            how to present them (e.g. as "unexpectedly failed").
        """
