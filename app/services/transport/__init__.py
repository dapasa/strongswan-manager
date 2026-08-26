"""Transport abstraction layer for VPN node connectivity."""

from .base import CommandResult, NodeTransport, TransportError, TransportErrorKind
from .factory import get_transport

__all__ = [
    "CommandResult",
    "NodeTransport",
    "TransportError",
    "TransportErrorKind",
    "get_transport",
]
