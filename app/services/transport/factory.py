"""Transport factory — selects the correct NodeTransport for a server."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .base import NodeTransport
from .ssh_transport import SshTransport
from .ssm_transport import SsmTransport

if TYPE_CHECKING:
    from app.db.models import Server


def get_transport(server: Server) -> NodeTransport:
    """Return the appropriate NodeTransport for *server*.

    Args:
        server: Server ORM instance with connection_type set.

    Returns:
        A NodeTransport implementation ready to use.

    Raises:
        TransportError: If required transport fields are missing.
        ValueError:     If connection_type is not a recognised value.
    """
    if server.connection_type == "ssm":
        return SsmTransport(server)

    # Default / "ssh"
    return SshTransport(server)
