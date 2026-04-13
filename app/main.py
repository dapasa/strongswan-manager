"""FastAPI application factory — assembles middleware, routers, and lifecycle hooks."""

from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import select

from app.config import get_settings
from app.db.models import AsyncOperation
from app.db.session import async_session_factory, engine
from app.logging_config import get_logger, setup_logging
from app.middleware import (
    RequestIDMiddleware,
    RequestLoggingMiddleware,
    register_exception_handlers,
)
from app.routers import (
    audit_router,
    auth_router,
    dashboard_router,
    health_router,
    iptables_router,
    operations_router,
    routes_router,
    tunnels_router,
)

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Manage application startup and shutdown."""
    setup_logging()
    logger.info("application_starting", version="1.0.0")

    # Recover orphaned async operations from previous crash/restart
    async with async_session_factory() as db:
        result = await db.execute(
            select(AsyncOperation).where(
                AsyncOperation.status.in_(["pending", "in_progress", "running"]),
            ),
        )
        orphans = result.scalars().all()
        for op in orphans:
            logger.warning(
                "orphan_operation_recovered",
                operation_id=str(op.id),
                entity_type=op.entity_type,
                entity_id=op.entity_id,
                previous_status=op.status,
            )
            op.status = "failed"
            op.error_message = "Operation interrupted by application restart"
        if orphans:
            await db.commit()
            logger.info("orphan_operations_marked_failed", count=len(orphans))

    yield
    await engine.dispose()
    logger.info("application_shutdown")


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app() -> FastAPI:
    """Build and return the fully-configured FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="VPN Manager API",
        version="1.0.0",
        description="Management API for strongSwan IPSec VPN tunnels, routes, and iptables rules.",
        lifespan=lifespan,
    )

    # -- CORS ---------------------------------------------------------------
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # -- Middleware (order matters: outermost runs first) --------------------
    # RequestID must be outermost so the ID is available for logging middleware
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RequestIDMiddleware)

    # -- Exception handlers -------------------------------------------------
    register_exception_handlers(app)

    # -- Routers ------------------------------------------------------------
    # Routers already carry their own prefixes and tags.
    app.include_router(health_router)
    app.include_router(auth_router)
    app.include_router(tunnels_router)
    app.include_router(routes_router)
    app.include_router(iptables_router)
    app.include_router(dashboard_router)
    app.include_router(audit_router)
    app.include_router(operations_router)

    return app


app = create_app()
