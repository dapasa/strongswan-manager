"""Automatic reconciliation of partial/failed tunnel syncs.

A single background task (started in app lifespan) periodically scans for
tunnels whose sync_status is 'partial' or 'failed' and re-runs the same push
logic that manual retry uses.  Concurrency guards:

  - One loop in the process — no parallel reconciliation passes.
  - Per-tunnel: skip if sync_status is not 'partial'/'failed' when reloaded
    (covers the case where a manual retry started between our query and our
    attempt).
  - Uses pg_try_advisory_xact_lock (same as manual retry) so we yield to any
    concurrent manual retry/update that holds the lock.
  - In-memory per-tunnel attempt counter; stops after reconciler_max_attempts
    consecutive automated attempts (resets on app restart).
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Tunnel
from app.exceptions import InfrastructureError
from app.logging_config import get_logger
from app.services import audit, ipsec_config, kms
from app.services.locks import LOCK_IPSEC_CONFIG, acquire_advisory_lock

if TYPE_CHECKING:
    from collections.abc import Callable

    from app.config import Settings

logger = get_logger(__name__)


async def _process_tunnel(
    state: dict[int, int],
    tunnel_id: int,
    session: AsyncSession,
    settings: Settings,
) -> None:
    """Attempt to reconcile one tunnel inside an already-open session.

    Returns immediately (without committing) if:
    - The tunnel no longer exists or is deleted.
    - sync_status changed to something other than 'failed'/'partial' since the
      scan (e.g. a concurrent manual retry already fixed it).
    - The advisory lock is held by another operation.
    """
    result = await session.execute(
        select(Tunnel).where(Tunnel.id == tunnel_id, Tunnel.deleted_at.is_(None))
    )
    tunnel = result.scalar_one_or_none()

    if tunnel is None or tunnel.sync_status not in ("failed", "partial"):
        return

    acquired = await acquire_advisory_lock(session, LOCK_IPSEC_CONFIG)
    if not acquired:
        logger.info("reconciler_skipped_locked", tunnel_id=tunnel_id)
        return

    state[tunnel_id] = state.get(tunnel_id, 0) + 1
    attempt = state[tunnel_id]

    logger.info(
        "reconciler_attempting",
        tunnel_id=tunnel_id,
        attempt=attempt,
        max_attempts=settings.reconciler_max_attempts,
        sync_status=tunnel.sync_status,
    )

    tunnel.sync_status = "pending"

    try:
        psk = await kms.decrypt_psk(tunnel.psk_encrypted)
        fan_out_result = await ipsec_config.sync_tunnel_config(tunnel, psk, session)
        tunnel.sync_status = fan_out_result.to_sync_status()
        tunnel.sync_error = fan_out_result.to_sync_error()
        tunnel.sync_details = fan_out_result.to_sync_details()
        logger.info(
            "reconciler_tunnel_synced",
            tunnel_id=tunnel_id,
            sync_status=tunnel.sync_status,
            attempt=attempt,
        )
    except InfrastructureError as exc:
        tunnel.sync_status = "failed"
        tunnel.sync_error = exc.message
        logger.error(
            "reconciler_tunnel_failed",
            tunnel_id=tunnel_id,
            error=exc.message,
            attempt=attempt,
        )
    except Exception as exc:
        tunnel.sync_status = "failed"
        tunnel.sync_error = f"Unexpected error: {exc}"
        logger.error(
            "reconciler_tunnel_unexpected",
            tunnel_id=tunnel_id,
            error=str(exc),
            attempt=attempt,
        )

    await audit.log_action(
        session,
        user_id=None,
        entity_type="tunnel",
        entity_id=tunnel.id,
        action="retry",
        new_state={
            "sync_status": tunnel.sync_status,
            "actor": "system:reconciler",
            "attempt": attempt,
        },
    )

    await session.commit()


async def reconcile_once(
    state: dict[int, int],
    session_factory: Callable,
    settings: Settings,
) -> None:
    """Single reconciliation pass: scan for partial/failed tunnels and retry each.

    Uses two session opens per tunnel: one shared session to collect the candidate
    IDs, then one dedicated session per tunnel so each sync attempt runs in its
    own transaction (and its own advisory-lock scope).
    """
    async with session_factory() as session:
        result = await session.execute(
            select(Tunnel.id).where(
                Tunnel.sync_status.in_(["partial", "failed"]),
                Tunnel.deleted_at.is_(None),
            )
        )
        tunnel_ids = list(result.scalars().all())

    if not tunnel_ids:
        return

    logger.info("reconciler_pass_start", candidate_count=len(tunnel_ids))

    for tunnel_id in tunnel_ids:
        attempts_so_far = state.get(tunnel_id, 0)
        if attempts_so_far >= settings.reconciler_max_attempts:
            logger.info(
                "reconciler_max_attempts_reached",
                tunnel_id=tunnel_id,
                attempts=attempts_so_far,
            )
            continue

        async with session_factory() as session:
            await _process_tunnel(state, tunnel_id, session, settings)


async def reconciler_loop(session_factory: Callable, settings: Settings) -> None:
    """Periodic reconciliation loop — started once in the app lifespan.

    Sleeps for reconciler_interval_seconds, then calls reconcile_once.
    Runs until cancelled (on app shutdown).  If reconciler_enabled is False,
    returns immediately.
    """
    if not settings.reconciler_enabled:
        logger.info("reconciler_disabled")
        return

    state: dict[int, int] = {}  # tunnel_id → consecutive automated attempt count

    logger.info(
        "reconciler_loop_started",
        interval=settings.reconciler_interval_seconds,
        max_attempts=settings.reconciler_max_attempts,
    )

    while True:
        try:
            await asyncio.sleep(settings.reconciler_interval_seconds)
            await reconcile_once(state, session_factory, settings)
        except asyncio.CancelledError:
            logger.info("reconciler_loop_cancelled")
            raise
        except Exception as exc:
            logger.error("reconciler_loop_error", error=str(exc))
