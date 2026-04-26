"""Tunnel router — CRUD + live status for IPSec tunnels."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_operator, require_viewer
from app.db.models import User
from app.db.session import async_session_factory, get_db
from app.logging_config import get_logger
from app.schemas.common import PaginatedResponse
from app.schemas.iptables import IPTablesRuleCreate, IPTablesRuleDetail
from app.schemas.operations import AsyncOperationRef
from app.schemas.route import RouteCreate, RouteDetail
from app.schemas.tunnel import (
    TunnelCheckStatusResult,
    TunnelCreate,
    TunnelDetail,
    TunnelStatus,
    TunnelSummary,
    TunnelUpdate,
)
from app.services import iptables_service, route_service, tunnel_service
from app.services.iptables_service import build_iptables_command

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/tunnels", tags=["tunnels"])


@router.get(
    "/",
    response_model=PaginatedResponse[TunnelSummary],
    summary="List active tunnels",
)
async def list_tunnels(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status_filter: str | None = Query(None, alias="status", description="Filter by status"),
    sync_status: str | None = Query(None, description="Filter by sync_status"),
    search: str | None = Query(None, description="Search by name or description"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> PaginatedResponse[TunnelSummary]:
    """List all active (non-deleted) tunnels with pagination, filtering, and search."""
    tunnels, total = await tunnel_service.list_tunnels(
        db,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        sync_status_filter=sync_status,
        search=search,
    )
    items = [
        TunnelSummary(
            id=t.id,
            name=t.name,
            peer_ip=str(t.peer_ip),
            status=t.status,
            sync_status=t.sync_status,
            sync_error=t.sync_error,
            route_count=sum(1 for r in t.routes if r.deleted_at is None),
            iptables_rule_count=sum(1 for r in t.iptables_rules if r.deleted_at is None),
            created_at=t.created_at,
        )
        for t in tunnels
    ]
    offset = (page - 1) * page_size
    return PaginatedResponse[TunnelSummary](
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(offset + page_size) < total,
    )


@router.get(
    "/{tunnel_id}",
    response_model=TunnelDetail,
    summary="Get tunnel detail",
)
async def get_tunnel(
    tunnel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> TunnelDetail:
    """Get full tunnel detail including nested routes and iptables rules."""
    tunnel = await tunnel_service.get_tunnel(db, tunnel_id)
    return TunnelDetail.model_validate(tunnel)


@router.post(
    "/",
    response_model=TunnelDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create tunnel",
)
async def create_tunnel(
    data: TunnelCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> TunnelDetail:
    """Create a new IPSec tunnel and sync to infrastructure."""
    tunnel = await tunnel_service.create_tunnel(
        db,
        data=data,
        user=current_user,
        request=request,
    )
    fresh = await tunnel_service.get_tunnel(db, tunnel.id)
    return TunnelDetail.model_validate(fresh)


@router.patch(
    "/{tunnel_id}",
    response_model=TunnelDetail,
    summary="Update tunnel",
)
async def update_tunnel(
    tunnel_id: int,
    data: TunnelUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> TunnelDetail:
    """Update an existing tunnel and re-sync if connection parameters changed."""
    await tunnel_service.update_tunnel(
        db,
        tunnel_id,
        data=data,
        user=current_user,
        request=request,
    )
    tunnel = await tunnel_service.get_tunnel(db, tunnel_id)
    return TunnelDetail.model_validate(tunnel)


@router.delete(
    "/{tunnel_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete tunnel with cascade",
)
async def delete_tunnel(
    tunnel_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> None:
    """Soft-delete a tunnel and cascade to routes and iptables rules."""
    await tunnel_service.delete_tunnel(
        db,
        tunnel_id,
        user=current_user,
        request=request,
    )


@router.post(
    "/{tunnel_id}/retry",
    response_model=TunnelDetail,
    summary="Retry failed tunnel sync",
)
async def retry_tunnel_sync(
    tunnel_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> TunnelDetail:
    """Retry a failed tunnel sync operation. Only works when sync_status='failed'."""
    await tunnel_service.retry_tunnel_sync(
        db,
        tunnel_id,
        user=current_user,
        request=request,
    )
    # Re-fetch fresh from DB after commit to avoid expired state issues
    tunnel = await tunnel_service.get_tunnel(db, tunnel_id)
    return TunnelDetail.model_validate(tunnel)


@router.get(
    "/{tunnel_id}/status",
    response_model=TunnelStatus,
    summary="Get live tunnel status",
)
async def get_tunnel_status(
    tunnel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> TunnelStatus:
    """Query strongSwan via SSM for real-time tunnel state."""
    result = await tunnel_service.get_tunnel_status(db, tunnel_id)
    return TunnelStatus(**result)


@router.post(
    "/{tunnel_id}/check-status",
    response_model=TunnelCheckStatusResult,
    summary="Check operational tunnel status via SSM",
)
async def check_tunnel_status(
    tunnel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> TunnelCheckStatusResult:
    """Run 'ipsec status <tunnel_name>' on the primary instance and update the tunnel's status in the DB."""
    result = await tunnel_service.check_tunnel_status(db, tunnel_id)
    return TunnelCheckStatusResult(**result)


# ---------------------------------------------------------------------------
# Nested route endpoints: /api/v1/tunnels/{tunnel_id}/routes
# ---------------------------------------------------------------------------


@router.get(
    "/{tunnel_id}/routes",
    response_model=list[RouteDetail],
    summary="List routes for a tunnel",
    tags=["routes"],
)
async def list_tunnel_routes(
    tunnel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> list[RouteDetail]:
    """List all active routes for a specific tunnel."""
    routes = await route_service.list_routes(db, tunnel_id=tunnel_id)
    return [RouteDetail.model_validate(r) for r in routes]


@router.post(
    "/{tunnel_id}/routes",
    response_model=AsyncOperationRef,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Create route for a tunnel (async)",
    tags=["routes"],
)
async def create_tunnel_route(
    tunnel_id: int,
    data: RouteCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> AsyncOperationRef:
    """Create a route on a tunnel and launch async terragrunt operation."""
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


# ---------------------------------------------------------------------------
# Nested iptables endpoints: /api/v1/tunnels/{tunnel_id}/iptables
# ---------------------------------------------------------------------------


@router.get(
    "/{tunnel_id}/iptables",
    response_model=list[IPTablesRuleDetail],
    summary="List iptables rules for a tunnel",
    tags=["iptables"],
)
async def list_tunnel_iptables(
    tunnel_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> list[IPTablesRuleDetail]:
    """List all active iptables rules for a specific tunnel."""
    rules = await iptables_service.list_rules(db, tunnel_id=tunnel_id)
    return [
        IPTablesRuleDetail(
            id=r.id,
            tunnel_id=r.tunnel_id,
            chain=r.chain,
            protocol=r.protocol,
            source_cidr=str(r.source_cidr) if r.source_cidr else None,
            dest_cidr=str(r.dest_cidr) if r.dest_cidr else None,
            sport=r.sport,
            dport=r.dport,
            action=r.action,
            state_match=list(r.state_match) if r.state_match else None,
            comment=r.comment,
            position=r.position,
            sync_status=r.sync_status,
            sync_error=r.sync_error,
            command_preview=build_iptables_command(r),
            created_at=r.created_at,
            updated_at=r.updated_at,
        )
        for r in rules
    ]


@router.post(
    "/{tunnel_id}/iptables",
    response_model=IPTablesRuleDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create iptables rule for a tunnel",
    tags=["iptables"],
)
async def create_tunnel_iptables(
    tunnel_id: int,
    data: IPTablesRuleCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> IPTablesRuleDetail:
    """Create an iptables rule on a tunnel, apply via SSM."""
    rule = await iptables_service.create_rule(
        db,
        tunnel_id=tunnel_id,
        data=data,
        user=current_user,
        request=request,
    )
    return IPTablesRuleDetail(
        id=rule.id,
        tunnel_id=rule.tunnel_id,
        chain=rule.chain,
        protocol=rule.protocol,
        source_cidr=str(rule.source_cidr) if rule.source_cidr else None,
        dest_cidr=str(rule.dest_cidr) if rule.dest_cidr else None,
        sport=rule.sport,
        dport=rule.dport,
        action=rule.action,
        state_match=list(rule.state_match) if rule.state_match else None,
        comment=rule.comment,
        position=rule.position,
        sync_status=rule.sync_status,
        sync_error=rule.sync_error,
        command_preview=build_iptables_command(rule),
        created_at=rule.created_at,
        updated_at=rule.updated_at,
    )
