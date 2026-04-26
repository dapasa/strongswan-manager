"""Route orchestration service — coordinates DB + Terragrunt for async route operations."""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from app.db.models import AsyncOperation, Route, Tunnel, User
from app.exceptions import ConflictError, InfrastructureError, NotFoundError, ValidationError
from app.logging_config import get_logger
from app.services import audit, terragrunt
from app.services.locks import LOCK_TERRAGRUNT, acquire_advisory_lock

logger = get_logger(__name__)

_BACKOFF_BASE_SECONDS: float = 1.0
_BACKOFF_MAX_SECONDS: float = 30.0
_MAX_LOCK_RETRIES: int = 5

_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes from text."""
    return _ANSI_ESCAPE_RE.sub("", text)


def _extract_error_summary(exc: Exception, max_length: int = 500) -> str:
    """Extract a concise, ANSI-free error summary from an exception.

    For InfrastructureError with detail (stderr output), extracts the key
    error lines. Otherwise falls back to str(exc).
    """
    if isinstance(exc, InfrastructureError) and exc.detail:
        raw = _strip_ansi(exc.detail)
        # Look for lines containing "Error" or "error" as they are most informative
        error_lines = [
            line.strip()
            for line in raw.splitlines()
            if line.strip() and ("error" in line.lower() or "Error" in line)
        ]
        if error_lines:
            summary = "\n".join(error_lines[:5])
        else:
            # Fall back to last non-empty lines (often the most relevant)
            non_empty = [line.strip() for line in raw.splitlines() if line.strip()]
            summary = "\n".join(non_empty[-5:]) if non_empty else raw
        return summary[:max_length]
    return _strip_ansi(str(exc))[:max_length]


async def _update_route_stage(
    session: AsyncSession,
    route_id: int,
    stage: str,
) -> None:
    """Update a route's sync_status to the given stage and commit."""
    route = await session.get(Route, route_id)
    if route is not None:
        route.sync_status = stage
        await session.commit()


def _route_to_dict(route: Route) -> dict[str, Any]:
    """Serialize a Route model to a dict for audit JSONB storage."""
    return {
        "id": route.id,
        "tunnel_id": route.tunnel_id,
        "cidr": str(route.cidr),
        "description": route.description,
        "sync_status": route.sync_status,
        "sync_error": route.sync_error,
        "created_by": route.created_by,
        "created_at": route.created_at.isoformat() if route.created_at else None,
        "updated_at": route.updated_at.isoformat() if route.updated_at else None,
    }


async def list_routes(
    session: AsyncSession,
    *,
    tunnel_id: int | None = None,
) -> list[Route]:
    """List active (non-deleted) routes, optionally filtered by tunnel.

    Args:
        session: Active database session.
        tunnel_id: If provided, filter routes to this tunnel only.

    Returns:
        List of active Route instances.
    """
    stmt = select(Route).where(Route.deleted_at.is_(None))
    if tunnel_id is not None:
        stmt = stmt.where(Route.tunnel_id == tunnel_id)
    stmt = stmt.order_by(Route.id)

    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_route(session: AsyncSession, route_id: int) -> Route:
    """Get a single route by ID.

    Args:
        session: Active database session.
        route_id: Primary key of the route.

    Returns:
        The Route instance.

    Raises:
        NotFoundError: If no active route with the given ID exists.
    """
    result = await session.execute(
        select(Route).where(
            Route.id == route_id,
            Route.deleted_at.is_(None),
        ),
    )
    route = result.scalar_one_or_none()
    if route is None:
        raise NotFoundError("Route", route_id)
    return route


async def create_route(
    session: AsyncSession,
    *,
    tunnel_id: int,
    data: Any,
    user: User,
    request: Request | None = None,
    db_factory: async_sessionmaker | None = None,
) -> tuple[Route, AsyncOperation]:
    """Create a route and launch async terragrunt operation.

    1. Verify tunnel exists and is active.
    2. Verify CIDR is unique for that tunnel among active routes.
    3. Insert route with sync_status='pending'.
    4. Create AsyncOperation (status='pending').
    5. Create audit log entry.
    6. Commit transaction.
    7. Launch background task for terragrunt apply.

    Args:
        session: Active database session.
        tunnel_id: Tunnel to add the route to.
        data: RouteCreate schema instance.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.
        db_factory: Session factory for background task. Required for
            launching the background task.

    Returns:
        Tuple of (Route, AsyncOperation) for the 202 response.

    Raises:
        NotFoundError: If the tunnel does not exist.
        ValidationError: If the tunnel is not active.
        ConflictError: If the CIDR already exists on this tunnel.
    """
    # Verify tunnel exists and is active
    tunnel = await _get_active_tunnel(session, tunnel_id)

    # Verify CIDR uniqueness
    cidr_str = str(data.cidr)
    existing = await session.execute(
        select(Route.id).where(
            Route.tunnel_id == tunnel_id,
            Route.cidr == cidr_str,
            Route.deleted_at.is_(None),
        ),
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Route with CIDR '{cidr_str}' already exists on tunnel {tunnel_id}")

    # Insert route
    route = Route(
        tunnel_id=tunnel_id,
        cidr=cidr_str,
        description=data.description,
        sync_status="pending",
        created_by=user.id,
    )
    session.add(route)
    await session.flush()

    # Create async operation
    operation = AsyncOperation(
        id=uuid4(),
        entity_type="route",
        entity_id=route.id,
        operation="create",
        status="pending",
        created_by=user.id,
    )
    session.add(operation)
    await session.flush()

    # Refresh route to eagerly load server-generated columns (e.g. updated_at)
    # that were expired by flush — avoids MissingGreenlet with asyncpg driver.
    await session.refresh(route)

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="route",
        entity_id=route.id,
        action="create",
        new_state=_route_to_dict(route),
        request=request,
    )

    await session.commit()

    # Launch background task AFTER commit
    if db_factory is not None:
        asyncio.create_task(
            _execute_route_create(
                db_factory=db_factory,
                route_id=route.id,
                operation_id=str(operation.id),
                cidr=cidr_str,
                tunnel_name=tunnel.name,
            ),
        )
    else:
        logger.warning(
            "route_create_no_db_factory",
            route_id=route.id,
            msg="Background task not launched — no db_factory provided",
        )

    return route, operation


async def delete_route(
    session: AsyncSession,
    route_id: int,
    *,
    user: User,
    request: Request | None = None,
    db_factory: async_sessionmaker | None = None,
) -> AsyncOperation:
    """Soft-delete a route and launch async terragrunt teardown.

    1. Get route and its tunnel.
    2. Soft-delete route (deleted_at, sync_status='pending_delete').
    3. Create AsyncOperation (status='pending').
    4. Create audit log entry.
    5. Commit.
    6. Launch background task for terragrunt removal.

    Args:
        session: Active database session.
        route_id: Primary key of the route to delete.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.
        db_factory: Session factory for background task.

    Returns:
        AsyncOperation for the 202 response.

    Raises:
        NotFoundError: If the route does not exist.
    """
    route = await get_route(session, route_id)
    previous_state = _route_to_dict(route)

    # Load the tunnel name for terragrunt commit message
    tunnel_result = await session.execute(
        select(Tunnel.name).where(Tunnel.id == route.tunnel_id),
    )
    tunnel_name = tunnel_result.scalar_one()

    now = datetime.now(timezone.utc)
    route.deleted_at = now
    route.sync_status = "pending_delete"

    # Create async operation
    operation = AsyncOperation(
        id=uuid4(),
        entity_type="route",
        entity_id=route.id,
        operation="delete",
        status="pending",
        created_by=user.id,
    )
    session.add(operation)
    await session.flush()

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="route",
        entity_id=route.id,
        action="delete",
        previous_state=previous_state,
        request=request,
    )

    await session.commit()

    # Launch background task AFTER commit
    if db_factory is not None:
        asyncio.create_task(
            _execute_route_delete(
                db_factory=db_factory,
                route_id=route.id,
                operation_id=str(operation.id),
                cidr=str(route.cidr),
                tunnel_name=tunnel_name,
            ),
        )
    else:
        logger.warning(
            "route_delete_no_db_factory",
            route_id=route.id,
            msg="Background task not launched — no db_factory provided",
        )

    return operation


async def retry_route(
    session: AsyncSession,
    route_id: int,
    *,
    user: User,
    request: Request | None = None,
    db_factory: async_sessionmaker | None = None,
) -> AsyncOperation:
    """Retry a failed route operation.

    Only works when the route's sync_status is 'failed'. Creates a new
    AsyncOperation and launches a background terragrunt apply.

    Args:
        session: Active database session.
        route_id: Primary key of the route to retry.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.
        db_factory: Session factory for background task.

    Returns:
        AsyncOperation for the 202 response.

    Raises:
        NotFoundError: If the route does not exist.
        ConflictError: If sync_status is not 'failed'.
    """
    route = await get_route(session, route_id)

    if route.sync_status != "failed":
        raise ConflictError(
            f"Route {route_id} sync_status is '{route.sync_status}', not 'failed'. Retry only works on failed syncs."
        )

    # Load tunnel name for terragrunt commit message
    tunnel_result = await session.execute(
        select(Tunnel.name).where(Tunnel.id == route.tunnel_id),
    )
    tunnel_name = tunnel_result.scalar_one()

    # Reset sync status
    route.sync_status = "pending"
    route.sync_error = None

    # Create async operation
    operation = AsyncOperation(
        id=uuid4(),
        entity_type="route",
        entity_id=route.id,
        operation="create",
        status="pending",
        created_by=user.id,
    )
    session.add(operation)
    await session.flush()

    # Refresh route to eagerly load server-generated columns (e.g. updated_at)
    # that were expired by flush — avoids MissingGreenlet with asyncpg driver.
    await session.refresh(route)

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="route",
        entity_id=route.id,
        action="retry",
        new_state=_route_to_dict(route),
        request=request,
    )

    await session.commit()

    # Launch background task AFTER commit
    if db_factory is not None:
        asyncio.create_task(
            _execute_route_create(
                db_factory=db_factory,
                route_id=route.id,
                operation_id=str(operation.id),
                cidr=str(route.cidr),
                tunnel_name=tunnel_name,
            ),
        )

    return operation


async def get_operation(
    session: AsyncSession,
    operation_id: str,
) -> AsyncOperation:
    """Get an AsyncOperation by ID for polling.

    Args:
        session: Active database session.
        operation_id: UUID of the async operation.

    Returns:
        The AsyncOperation instance.

    Raises:
        NotFoundError: If the operation does not exist.
    """
    from uuid import UUID

    try:
        op_uuid = UUID(operation_id)
    except ValueError as exc:
        raise NotFoundError("AsyncOperation", operation_id) from exc

    result = await session.execute(
        select(AsyncOperation).where(AsyncOperation.id == op_uuid),
    )
    operation = result.scalar_one_or_none()
    if operation is None:
        raise NotFoundError("AsyncOperation", operation_id)
    return operation


# ---------------------------------------------------------------------------
# Background tasks
# ---------------------------------------------------------------------------


async def _execute_route_create(
    *,
    db_factory: async_sessionmaker,
    route_id: int,
    operation_id: str,
    cidr: str,
    tunnel_name: str,
) -> None:
    """Background task: apply a new route via terragrunt.

    Uses its own DB session (the request session is already closed).
    Acquires TERRAGRUNT_LOCK with exponential backoff retry.

    Args:
        db_factory: Async session factory for creating a fresh session.
        route_id: ID of the route to apply.
        operation_id: ID of the AsyncOperation to update.
        cidr: CIDR string for the route.
        tunnel_name: Tunnel name for commit message.
    """
    logger.info("bg_route_create_start", route_id=route_id, operation_id=operation_id)

    async with db_factory() as session:
        try:
            # Update operation to running
            operation = await _load_operation(session, operation_id)
            operation.status = "running"
            operation.started_at = datetime.now(timezone.utc)
            await session.commit()

            # Acquire lock with backoff
            await _acquire_lock_with_backoff(session)

            # Stage: cloning (git clone/pull)
            await _update_route_stage(session, route_id, "cloning")
            repo = await terragrunt.ensure_repo()

            # Stage: pushing (modify file, commit, push to remote)
            await _update_route_stage(session, route_id, "pushing")
            await terragrunt.add_route_file(cidr, tunnel_name, repo)
            await terragrunt.commit_and_push(repo, f"vpn-manager: add route {cidr} for tunnel {tunnel_name}")

            # Stage: planning (terragrunt plan)
            await _update_route_stage(session, route_id, "planning")
            await terragrunt.run_plan()

            # Stage: applying (terragrunt apply)
            await _update_route_stage(session, route_id, "applying")
            await terragrunt.run_apply_plan()

            # Done — mark synced
            route = await session.get(Route, route_id)
            if route is not None:
                route.sync_status = "synced"
                route.sync_error = None

            # Update operation
            operation = await _load_operation(session, operation_id)
            operation.status = "completed"
            operation.completed_at = datetime.now(timezone.utc)
            operation.result = {"cidr": cidr, "action": "added"}
            await session.commit()

            logger.info("bg_route_create_complete", route_id=route_id, operation_id=operation_id)

        except Exception as exc:
            logger.error(
                "bg_route_create_failed",
                route_id=route_id,
                operation_id=operation_id,
                error=str(exc),
            )
            error_summary = _extract_error_summary(exc)
            await _mark_operation_failed(
                db_factory=db_factory,
                operation_id=operation_id,
                route_id=route_id,
                error=error_summary,
            )


async def _execute_route_delete(
    *,
    db_factory: async_sessionmaker,
    route_id: int,
    operation_id: str,
    cidr: str,
    tunnel_name: str,
) -> None:
    """Background task: remove a route via terragrunt.

    Same pattern as _execute_route_create but calls remove_route.

    Args:
        db_factory: Async session factory for creating a fresh session.
        route_id: ID of the route being removed.
        operation_id: ID of the AsyncOperation to update.
        cidr: CIDR string for the route.
        tunnel_name: Tunnel name for commit message.
    """
    logger.info("bg_route_delete_start", route_id=route_id, operation_id=operation_id)

    async with db_factory() as session:
        try:
            # Update operation to running
            operation = await _load_operation(session, operation_id)
            operation.status = "running"
            operation.started_at = datetime.now(timezone.utc)
            await session.commit()

            # Acquire lock with backoff
            await _acquire_lock_with_backoff(session)

            # Stage: cloning (git clone/pull)
            await _update_route_stage(session, route_id, "cloning")
            repo = await terragrunt.ensure_repo()

            # Stage: pushing (modify file, commit, push to remote)
            await _update_route_stage(session, route_id, "pushing")
            await terragrunt.remove_route_file(cidr, tunnel_name, repo)
            await terragrunt.commit_and_push(repo, f"vpn-manager: remove route {cidr} from tunnel {tunnel_name}")

            # Stage: planning (terragrunt plan)
            await _update_route_stage(session, route_id, "planning")
            await terragrunt.run_plan()

            # Stage: applying (terragrunt apply)
            await _update_route_stage(session, route_id, "applying")
            await terragrunt.run_apply_plan()

            # Update operation
            operation = await _load_operation(session, operation_id)
            operation.status = "completed"
            operation.completed_at = datetime.now(timezone.utc)
            operation.result = {"cidr": cidr, "action": "removed"}
            await session.commit()

            logger.info("bg_route_delete_complete", route_id=route_id, operation_id=operation_id)

        except Exception as exc:
            logger.error(
                "bg_route_delete_failed",
                route_id=route_id,
                operation_id=operation_id,
                error=str(exc),
            )
            error_summary = _extract_error_summary(exc)
            await _mark_operation_failed(
                db_factory=db_factory,
                operation_id=operation_id,
                route_id=route_id,
                error=error_summary,
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


async def _get_active_tunnel(session: AsyncSession, tunnel_id: int) -> Tunnel:
    """Get a tunnel that is active (not deleted, status='active').

    Args:
        session: Active database session.
        tunnel_id: Primary key of the tunnel.

    Returns:
        The Tunnel instance.

    Raises:
        NotFoundError: If the tunnel does not exist.
        ValidationError: If the tunnel is not active.
    """
    result = await session.execute(
        select(Tunnel).where(
            Tunnel.id == tunnel_id,
            Tunnel.deleted_at.is_(None),
        ),
    )
    tunnel = result.scalar_one_or_none()
    if tunnel is None:
        raise NotFoundError("Tunnel", tunnel_id)
    if tunnel.status != "active":
        raise ValidationError(f"Tunnel {tunnel_id} is not active (status='{tunnel.status}')")
    return tunnel


async def _load_operation(session: AsyncSession, operation_id: str) -> AsyncOperation:
    """Load an AsyncOperation by ID, refreshing from DB."""
    from uuid import UUID

    result = await session.execute(
        select(AsyncOperation).where(AsyncOperation.id == UUID(operation_id)),
    )
    operation = result.scalar_one_or_none()
    if operation is None:
        raise NotFoundError("AsyncOperation", operation_id)
    return operation


async def _acquire_lock_with_backoff(session: AsyncSession) -> None:
    """Attempt to acquire TERRAGRUNT_LOCK with exponential backoff.

    Retries up to _MAX_LOCK_RETRIES times with exponential backoff
    (1s, 2s, 4s, 8s, 16s, capped at 30s).

    Args:
        session: Active database session.

    Raises:
        InfrastructureError: If the lock cannot be acquired after all retries.
    """
    delay = _BACKOFF_BASE_SECONDS

    for attempt in range(_MAX_LOCK_RETRIES):
        acquired = await acquire_advisory_lock(session, LOCK_TERRAGRUNT)
        if acquired:
            logger.info("terragrunt_lock_acquired", attempt=attempt + 1)
            return

        logger.info(
            "terragrunt_lock_retry",
            attempt=attempt + 1,
            delay=delay,
        )
        await asyncio.sleep(delay)
        delay = min(delay * 2, _BACKOFF_MAX_SECONDS)

    raise InfrastructureError(
        service="Terragrunt",
        message=f"Could not acquire terragrunt lock after {_MAX_LOCK_RETRIES} retries",
    )


async def _mark_operation_failed(
    *,
    db_factory: async_sessionmaker,
    operation_id: str,
    route_id: int,
    error: str,
) -> None:
    """Mark an async operation and its route as failed.

    Opens a fresh session to ensure the failure is persisted even
    if the original session encountered errors.

    Args:
        db_factory: Session factory for a fresh session.
        operation_id: ID of the AsyncOperation to mark failed.
        route_id: ID of the Route to mark sync_status='failed'.
        error: Error message to store.
    """
    try:
        async with db_factory() as session:
            operation = await _load_operation(session, operation_id)
            operation.status = "failed"
            operation.error_message = error[:2000]  # Truncate to reasonable length
            operation.completed_at = datetime.now(timezone.utc)

            route = await session.get(Route, route_id)
            if route is not None:
                route.sync_status = "failed"
                route.sync_error = error[:2000]

            await session.commit()
    except Exception as inner_exc:
        logger.error(
            "bg_mark_failed_error",
            operation_id=operation_id,
            error=str(inner_exc),
        )
