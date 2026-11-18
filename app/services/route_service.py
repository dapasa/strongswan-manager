"""Route read service.

Route provisioning used to commit to the infrastructure repo and run
``terragrunt apply`` from inside the manager. That path was removed: it pushed
directly to the base branch, bypassing review and the deploy pipeline. Routes
are read-only until the AWS-API-backed redesign (sc-31774) lands.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AsyncOperation, Route
from app.exceptions import NotFoundError


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
