"""Route router — read-only until the route provisioning redesign (sc-31774)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_viewer
from app.db.models import User
from app.db.session import get_db
from app.logging_config import get_logger
from app.schemas.route import RouteDetail

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/routes", tags=["routes"])


@router.get(
    "/",
    response_model=list[RouteDetail],
    summary="List active routes",
)
async def list_routes(
    tunnel_id: int | None = Query(None, description="Filter by tunnel ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> list[RouteDetail]:
    """List all active routes, optionally filtered by tunnel."""
    from app.services import route_service

    routes = await route_service.list_routes(db, tunnel_id=tunnel_id)
    return [RouteDetail.model_validate(r) for r in routes]


@router.get(
    "/{route_id}",
    response_model=RouteDetail,
    summary="Get route detail",
)
async def get_route(
    route_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> RouteDetail:
    """Get a single route by ID."""
    from app.services import route_service

    route = await route_service.get_route(db, route_id)
    return RouteDetail.model_validate(route)
