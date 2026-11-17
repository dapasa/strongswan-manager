"""Reconciler status router — read-only view of the in-memory reconciler state."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_viewer
from app.config import get_settings
from app.db.models import Tunnel, User
from app.db.session import get_db
from app.schemas.reconciler import ReconcilerStatus, ReconcilerTunnelEntry
from app.services import reconciler as _reconciler_svc

router = APIRouter(prefix="/api/v1/reconciler", tags=["reconciler"])


@router.get(
    "/status",
    response_model=ReconcilerStatus,
    summary="Reconciler state",
)
async def get_reconciler_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> ReconcilerStatus:
    """Return a read-only snapshot of the in-memory reconciler state.

    Does not trigger any reconciliation — purely observational.
    """
    settings = get_settings()
    state = _reconciler_svc._state  # module-level dict, mutated in-place
    last_run_at = _reconciler_svc._last_run_at

    base = ReconcilerStatus(
        enabled=settings.reconciler_enabled,
        interval_seconds=settings.reconciler_interval_seconds,
        max_attempts=settings.reconciler_max_attempts,
        last_run_at=last_run_at,
    )

    if not state:
        return base

    # Fetch tunnel names for the IDs currently in state
    tunnel_ids = list(state.keys())
    result = await db.execute(
        select(Tunnel.id, Tunnel.name).where(
            Tunnel.id.in_(tunnel_ids),
            Tunnel.deleted_at.is_(None),
        ),
    )
    name_map: dict[int, str] = {row.id: row.name for row in result.all()}

    retrying: list[ReconcilerTunnelEntry] = []
    maxed: list[ReconcilerTunnelEntry] = []

    for tunnel_id, attempts in state.items():
        entry = ReconcilerTunnelEntry(
            tunnel_id=tunnel_id,
            tunnel_name=name_map.get(tunnel_id, f"tunnel:{tunnel_id}"),
            attempts=attempts,
        )
        if attempts >= settings.reconciler_max_attempts:
            maxed.append(entry)
        else:
            retrying.append(entry)

    return ReconcilerStatus(
        enabled=settings.reconciler_enabled,
        interval_seconds=settings.reconciler_interval_seconds,
        max_attempts=settings.reconciler_max_attempts,
        last_run_at=last_run_at,
        retrying=retrying,
        maxed=maxed,
    )
