"""Route router — CRUD for VPN routes with async terragrunt operations."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_operator, require_viewer
from app.db.models import User
from app.db.session import async_session_factory, get_db
from app.logging_config import get_logger
from app.schemas.operations import AsyncOperationRef
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
    response_model=AsyncOperationRef,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create route (async)",
)
async def create_route(
    data: RouteCreate,
    request: Request,
    tunnel_id: int = Query(..., description="Tunnel to add the route to"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> AsyncOperationRef:
    """Create a route and launch async terragrunt operation.

    Returns 202 with an operation reference for polling.
    """
    from app.services import route_service

    route, operation = await route_service.create_route(
        db,
        tunnel_id=tunnel_id,
        data=data,
        user=current_user,
        request=request,
        db_factory=async_session_factory,
    )
    poll_url = f"/api/v1/operations/{operation.id}"
    return AsyncOperationRef(
        operation_id=operation.id,
        status=operation.status,
        poll_url=poll_url,
    )


@router.post(
    "/{route_id}/retry",
    response_model=AsyncOperationRef,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Retry failed route operation",
)
async def retry_route(
    route_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> AsyncOperationRef:
    """Retry a failed route operation. Only works when sync_status='failed'."""
    from app.services import route_service

    operation = await route_service.retry_route(
        db,
        route_id,
        user=current_user,
        request=request,
        db_factory=async_session_factory,
    )
    poll_url = f"/api/v1/operations/{operation.id}"
    return AsyncOperationRef(
        operation_id=operation.id,
        status=operation.status,
        poll_url=poll_url,
    )


@router.delete(
    "/{route_id}",
    response_model=AsyncOperationRef,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Delete route (async)",
)
async def delete_route(
    route_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> AsyncOperationRef:
    """Soft-delete a route and launch async terragrunt teardown.

    Returns 202 with an operation reference for polling.
    """
    from app.services import route_service

    operation = await route_service.delete_route(
        db,
        route_id,
        user=current_user,
        request=request,
        db_factory=async_session_factory,
    )
    poll_url = f"/api/v1/operations/{operation.id}"
    return AsyncOperationRef(
        operation_id=operation.id,
        status=operation.status,
        poll_url=poll_url,
    )
