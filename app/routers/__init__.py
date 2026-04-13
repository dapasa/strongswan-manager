"""API routers package — all FastAPI routers for the strongswan-manager."""

from __future__ import annotations

from app.routers.audit import router as audit_router
from app.routers.auth import router as auth_router
from app.routers.dashboard import router as dashboard_router
from app.routers.health import router as health_router
from app.routers.iptables import router as iptables_router
from app.routers.operations import router as operations_router
from app.routers.routes import router as routes_router
from app.routers.tunnels import router as tunnels_router

__all__ = [
    "audit_router",
    "auth_router",
    "dashboard_router",
    "health_router",
    "iptables_router",
    "operations_router",
    "routes_router",
    "tunnels_router",
]
