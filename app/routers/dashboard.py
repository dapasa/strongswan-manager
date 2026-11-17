"""Dashboard router — aggregated metrics for the management UI."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_viewer
from app.config import get_settings
from app.db.models import (
    AsyncOperation,
    AuditLog,
    IPTablesRule,
    Route,
    Tunnel,
    User,
)
from app.db.session import get_db
from app.schemas.dashboard import DashboardSummary, PskStaleTunnel

router = APIRouter(prefix="/api/v1/dashboard", tags=["dashboard"])


@router.get(
    "/summary",
    response_model=DashboardSummary,
    summary="Dashboard metrics",
)
async def get_dashboard_summary(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> DashboardSummary:
    """Return aggregated counts for tunnels, routes, rules, and recent activity."""
    # Active tunnels (not deleted, status='active')
    tunnel_count_result = await db.execute(
        select(func.count()).select_from(Tunnel).where(
            Tunnel.deleted_at.is_(None),
            Tunnel.status == "active",
        ),
    )
    active_tunnels = tunnel_count_result.scalar_one()

    # Active routes (not deleted)
    route_count_result = await db.execute(
        select(func.count()).select_from(Route).where(Route.deleted_at.is_(None)),
    )
    active_routes = route_count_result.scalar_one()

    # Active iptables rules (not deleted)
    iptables_count_result = await db.execute(
        select(func.count()).select_from(IPTablesRule).where(IPTablesRule.deleted_at.is_(None)),
    )
    active_iptables_rules = iptables_count_result.scalar_one()

    # Failed syncs across all entity types
    failed_tunnels = await db.execute(
        select(func.count()).select_from(Tunnel).where(
            Tunnel.deleted_at.is_(None),
            Tunnel.sync_status == "failed",
        ),
    )
    failed_routes = await db.execute(
        select(func.count()).select_from(Route).where(
            Route.deleted_at.is_(None),
            Route.sync_status == "failed",
        ),
    )
    failed_iptables = await db.execute(
        select(func.count()).select_from(IPTablesRule).where(
            IPTablesRule.deleted_at.is_(None),
            IPTablesRule.sync_status == "failed",
        ),
    )
    failed_syncs = (
        failed_tunnels.scalar_one()
        + failed_routes.scalar_one()
        + failed_iptables.scalar_one()
    )

    # Pending operations
    pending_ops_result = await db.execute(
        select(func.count()).select_from(AsyncOperation).where(
            AsyncOperation.status.in_(["pending", "running"]),
        ),
    )
    pending_operations = pending_ops_result.scalar_one()

    # Last change (most recent audit log entry)
    last_change_result = await db.execute(
        select(func.max(AuditLog.created_at)),
    )
    last_change = last_change_result.scalar_one()

    # Tunnel sync problems (failed + partial + pending)
    sync_problems_result = await db.execute(
        select(func.count()).select_from(Tunnel).where(
            Tunnel.deleted_at.is_(None),
            Tunnel.sync_status.in_(["failed", "partial", "pending"]),
        ),
    )
    sync_problems = sync_problems_result.scalar_one()

    # PSK age — query id, name, psk_rotated_at, created_at for all non-deleted tunnels
    settings = get_settings()
    threshold_days = settings.psk_max_age_days
    now = datetime.now(timezone.utc)

    psk_rows_result = await db.execute(
        select(Tunnel.id, Tunnel.name, Tunnel.psk_rotated_at, Tunnel.created_at).where(
            Tunnel.deleted_at.is_(None),
        ),
    )
    psk_rows = psk_rows_result.all()

    stale_tunnels: list[PskStaleTunnel] = []
    oldest_days: int | None = None

    for row in psk_rows:
        ref_dt = row.psk_rotated_at if row.psk_rotated_at is not None else row.created_at
        age_days = max(0, (now - ref_dt).days)
        if oldest_days is None or age_days > oldest_days:
            oldest_days = age_days
        if age_days > threshold_days:
            stale_tunnels.append(PskStaleTunnel(id=row.id, name=row.name, psk_age_days=age_days))

    stale_tunnels.sort(key=lambda x: x.psk_age_days, reverse=True)

    return DashboardSummary(
        active_tunnels=active_tunnels,
        active_routes=active_routes,
        active_iptables_rules=active_iptables_rules,
        failed_syncs=failed_syncs,
        pending_operations=pending_operations,
        last_change=last_change,
        sync_problems=sync_problems,
        psk_stale_count=len(stale_tunnels),
        psk_oldest_days=oldest_days,
        psk_stale_tunnels=stale_tunnels,
    )
