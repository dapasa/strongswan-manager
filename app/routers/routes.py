"""Route router — CRUD for VPC routes via the AWS EC2 API (sc-31774)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_permission, require_viewer
from app.db.models import User
from app.db.session import get_db
from app.logging_config import get_logger
from app.schemas.route import RouteCreate, RouteDetail

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


@router.post(
    "/",
    response_model=RouteDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create a VPC route for a tunnel",
)
async def create_route(
    tunnel_id: int = Query(..., description="Tunnel to associate the route with"),
    data: RouteCreate = ...,
    request: Request = ...,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("routes.write")),
) -> RouteDetail:
    """Create a VPC route via the AWS EC2 API.

    The route is written to every allowlisted route table
    (MANAGED_ROUTE_TABLE_IDS). The target ENI is resolved from the
    current EIP holder (the active VPN node).

    Validation rules:
    - CIDR must be inside one of the tunnel's remote CIDRs.
    - CIDR prefix length must not be 0 (default route).
    - CIDR must not overlap any VPC CIDR block.
    - No duplicate route for the same tunnel+CIDR may exist in the DB.
    - Every managed table must be listed in failover/config.yaml.

    Returns the route record — sync_status is 'synced' if all tables
    succeeded, 'failed' if any table failed (retry is available).
    """
    from app.services import route_service

    route = await route_service.create_route(
        db,
        tunnel_id=tunnel_id,
        cidr=data.cidr,
        description=data.description,
        user=current_user,
        request=request,
    )
    return RouteDetail.model_validate(route)


@router.delete(
    "/{route_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete a VPC route",
)
async def delete_route(
    route_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("routes.write")),
) -> None:
    """Delete a VPC route via the AWS EC2 API.

    Removes the route from every allowlisted table ('route not found'
    counts as success). Soft-deletes the DB record regardless.
    """
    from app.services import route_service

    await route_service.delete_route(
        db,
        route_id=route_id,
        user=current_user,
        request=request,
    )


@router.post(
    "/{route_id}/retry",
    response_model=RouteDetail,
    summary="Retry a failed route",
)
async def retry_route(
    route_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission("routes.write")),
) -> RouteDetail:
    """Retry AWS route provisioning for a route in 'failed' state.

    Only the tables that did not succeed in the previous attempt are retried.
    The target ENI is re-resolved at retry time.
    """
    from app.services import route_service

    route = await route_service.retry_route(
        db,
        route_id=route_id,
        user=current_user,
        request=request,
    )
    return RouteDetail.model_validate(route)
