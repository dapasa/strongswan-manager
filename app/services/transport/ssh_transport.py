"""SSH transport implementation using asyncssh.

This module is the *only* place in the codebase that imports asyncssh.
All SSH-specific exceptions are caught here and re-raised as TransportError
so that callers never need to depend on asyncssh.
"""

from __future__ import annotations

import asyncio
import posixpath
from typing import TYPE_CHECKING, Any

import asyncssh

from app.logging_config import get_logger
from app.utils.crypto import decrypt_ssh_key

from .base import CommandResult, NodeTransport, TransportError, TransportErrorKind

if TYPE_CHECKING:
    from app.db.models import Server

logger = get_logger(__name__)

# Seconds to wait for the TCP/SSH handshake to complete.
_CONNECT_TIMEOUT = 10


class SshTransport(NodeTransport):
    """NodeTransport implementation that talks to VPN nodes over SSH.

    Uses asyncssh for the underlying connection.  The stored SSH private key is
    decrypted on every connection — keys are never cached in memory.

    Args:
        server: Server ORM instance.  ``hostname`` and
                ``ssh_private_key_encrypted`` must not be None; a
                TransportError is raised immediately if they are.
    """

    def __init__(self, server: Server) -> None:
        self._server = server
        self._validate()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        """Raise TransportError early if required SSH fields are missing."""
        srv = self._server
        if not srv.hostname:
            raise TransportError(
                f"Server {srv.name!r} has no hostname configured — cannot use SSH transport",
                kind=TransportErrorKind.UNKNOWN,
            )
        if not srv.ssh_private_key_encrypted:
            raise TransportError(
                f"Server {srv.name!r} has no SSH key configured — cannot use SSH transport",
                kind=TransportErrorKind.UNKNOWN,
            )

    async def _connect(self) -> Any:
        """Build and return an asyncssh connection (awaitable context manager).

        Decrypts the stored SSH key on every call.  The returned object must be
        used as ``async with await transport._connect() as conn:``.

        Raises:
            asyncssh.Error: On SSH-level failure.
            OSError: On network-level failure.
        """
        srv = self._server
        raw_key = decrypt_ssh_key(srv.ssh_private_key_encrypted)
        key = asyncssh.import_private_key(raw_key)
        return asyncssh.connect(
            srv.hostname,
            port=srv.ssh_port,
            username=srv.ssh_user,
            client_keys=[key],
            known_hosts=None,
            connect_timeout=_CONNECT_TIMEOUT,
        )

    @staticmethod
    def _map_asyncssh_error(exc: Exception) -> TransportError:
        """Map asyncssh / OS exceptions to the appropriate TransportError kind."""
        if isinstance(exc, asyncssh.DisconnectError):
            return TransportError(str(exc), kind=TransportErrorKind.NODE_UNREACHABLE)
        if isinstance(exc, asyncssh.PermissionDenied):
            return TransportError(str(exc), kind=TransportErrorKind.PERMISSION_DENIED)
        if isinstance(exc, asyncssh.Error):
            return TransportError(str(exc), kind=TransportErrorKind.UNKNOWN)
        if isinstance(exc, OSError):
            return TransportError(str(exc), kind=TransportErrorKind.NODE_UNREACHABLE)
        return TransportError(str(exc), kind=TransportErrorKind.UNKNOWN)

    # ------------------------------------------------------------------
    # NodeTransport implementation
    # ------------------------------------------------------------------

    async def execute(
        self,
        commands: list[str],
        *,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run commands joined with ' && ' over SSH.

        Raises:
            TransportError: On connection failure, auth error, or nonzero exit.
        """
        command = " && ".join(commands)
        try:
            async with await self._connect() as conn:
                result = await conn.run(command)

            if result.exit_status != 0:
                stderr = result.stderr or ""
                stdout = result.stdout or ""
                detail = (stderr or stdout).strip() or f"exit {result.exit_status}"
                raise TransportError(
                    f"Command exited with status {result.exit_status}: {detail}",
                    kind=TransportErrorKind.COMMAND_FAILED,
                    stderr=stderr,
                    exit_code=result.exit_status,
                )

            return CommandResult(
                stdout=result.stdout or "",
                stderr=result.stderr or "",
                exit_code=result.exit_status,
            )

        except TransportError:
            raise
        except (asyncssh.Error, OSError) as exc:
            raise self._map_asyncssh_error(exc) from exc

    async def write_file(
        self,
        path: str,
        content: str,
        *,
        mode: str = "644",
        make_dirs: bool = True,
    ) -> None:
        """Write *content* to *path* using sudo tee + chmod over SSH.

        Raises:
            TransportError: On mkdir, tee, or chmod failure.
        """
        dir_path = posixpath.dirname(path)
        try:
            async with await self._connect() as conn:
                if make_dirs and dir_path:
                    r = await conn.run(f"sudo mkdir -p {dir_path}")
                    if r.exit_status != 0:
                        detail = (r.stderr or r.stdout or "").strip() or f"exit {r.exit_status}"
                        raise TransportError(
                            f"mkdir {dir_path} failed: {detail}",
                            kind=TransportErrorKind.COMMAND_FAILED,
                            stderr=r.stderr or "",
                            exit_code=r.exit_status,
                        )

                r = await conn.run(f"sudo tee {path}", input=content)
                if r.exit_status != 0:
                    detail = (r.stderr or r.stdout or "").strip() or f"exit {r.exit_status}"
                    raise TransportError(
                        f"tee {path} failed: {detail}",
                        kind=TransportErrorKind.COMMAND_FAILED,
                        stderr=r.stderr or "",
                        exit_code=r.exit_status,
                    )

                r = await conn.run(f"sudo chmod {mode} {path}")
                if r.exit_status != 0:
                    detail = (r.stderr or r.stdout or "").strip() or f"exit {r.exit_status}"
                    raise TransportError(
                        f"chmod {path} failed: {detail}",
                        kind=TransportErrorKind.COMMAND_FAILED,
                        stderr=r.stderr or "",
                        exit_code=r.exit_status,
                    )

        except TransportError:
            raise
        except (asyncssh.Error, OSError) as exc:
            raise self._map_asyncssh_error(exc) from exc

    async def delete_file(self, path: str) -> None:
        """Remove *path* via ``sudo rm -f`` (idempotent).

        Raises:
            TransportError: If rm fails for a reason other than file-not-found.
        """
        try:
            async with await self._connect() as conn:
                r = await conn.run(f"sudo rm -f {path}")
                if r.exit_status != 0:
                    detail = (r.stderr or r.stdout or "").strip() or f"exit {r.exit_status}"
                    raise TransportError(
                        f"rm failed for {path}: {detail}",
                        kind=TransportErrorKind.COMMAND_FAILED,
                        stderr=r.stderr or "",
                        exit_code=r.exit_status,
                    )
        except TransportError:
            raise
        except (asyncssh.Error, OSError) as exc:
            raise self._map_asyncssh_error(exc) from exc

    async def rename_file(self, src: str, dst: str) -> None:
        """Move *src* to *dst* via ``sudo mv``.

        Raises:
            TransportError: On failure.
        """
        try:
            async with await self._connect() as conn:
                r = await conn.run(f"sudo mv {src} {dst}")
                if r.exit_status != 0:
                    detail = (r.stderr or r.stdout or "").strip() or f"exit {r.exit_status}"
                    raise TransportError(
                        f"mv {src} -> {dst} failed: {detail}",
                        kind=TransportErrorKind.COMMAND_FAILED,
                        stderr=r.stderr or "",
                        exit_code=r.exit_status,
                    )
        except TransportError:
            raise
        except (asyncssh.Error, OSError) as exc:
            raise self._map_asyncssh_error(exc) from exc

    async def check_reachable(self, *, timeout: int = 10) -> bool:
        """Open and immediately close an SSH connection to verify reachability.

        Returns:
            True when the connection succeeds.

        Raises:
            TransportError: When connection or auth fails.
            Exception:      Re-raises unexpected exceptions unchanged.
        """
        async def _try() -> None:
            async with await self._connect() as _:
                pass

        try:
            await asyncio.wait_for(_try(), timeout=timeout)
            return True
        except asyncio.TimeoutError:
            raise TransportError(
                "Connection timed out",
                kind=TransportErrorKind.TIMEOUT,
            ) from None
        except (asyncssh.Error, OSError) as exc:
            raise self._map_asyncssh_error(exc) from exc
        # Unexpected exceptions propagate unchanged so server_service can
        # return a safe "unexpectedly failed" message without leaking details.
