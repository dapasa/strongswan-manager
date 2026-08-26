"""Transport factory — selects the correct NodeTransport for a server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import NodeTransport
from .ssh_transport import SshTransport

if TYPE_CHECKING:
    from app.db.models import Server


def get_transport(server: Server) -> NodeTransport:
    """Return the appropriate NodeTransport for *server*.

    Args:
        server: Server ORM instance with connection_type set.

    Returns:
        A NodeTransport implementation ready to use.

    Raises:
        NotImplementedError: If connection_type is "ssm" (Phase 3, not yet implemented).
        TransportError:      If the server's SSH fields are missing (raised by SshTransport).
    """
    if server.connection_type == "ssm":
        raise NotImplementedError(
            f"SSM transport is not yet implemented (Phase 3) — "
            f"server {server.name!r} uses connection_type='ssm'"
        )

    # Default / "ssh"
    return SshTransport(server)
