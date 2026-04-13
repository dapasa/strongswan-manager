"""Tunnel orchestration service — coordinates DB, S3, SSM for tunnel CRUD."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.config import get_settings
from app.db.models import IPTablesRule, Route, Tunnel, User
from app.exceptions import ConflictError, InfrastructureError, NotFoundError
from app.logging_config import get_logger
from app.services import audit, ipsec_config, ssm
from app.services.iptables_service import build_iptables_command
from app.services.locks import LOCK_IPSEC_CONFIG, require_lock

logger = get_logger(__name__)


def _tunnel_to_dict(tunnel: Tunnel) -> dict[str, Any]:
    """Serialize a Tunnel model to a dict suitable for audit JSONB storage."""
    return {
        "id": tunnel.id,
        "name": tunnel.name,
        "description": tunnel.description,
        "peer_ip": str(tunnel.peer_ip),
        "local_cidrs": list(tunnel.local_cidrs),
        "remote_cidrs": list(tunnel.remote_cidrs),
        "psk_secret_name": tunnel.psk_secret_name,
        "ike_version": tunnel.ike_version,
        "ike_proposals": tunnel.ike_proposals,
        "esp_proposals": tunnel.esp_proposals,
        "dpd_action": tunnel.dpd_action,
        "dpd_delay": tunnel.dpd_delay,
        "dpd_timeout": tunnel.dpd_timeout,
        "status": tunnel.status,
        "sync_status": tunnel.sync_status,
        "sync_error": tunnel.sync_error,
        "created_by": tunnel.created_by,
        "created_at": tunnel.created_at.isoformat() if tunnel.created_at else None,
        "updated_at": tunnel.updated_at.isoformat() if tunnel.updated_at else None,
    }


async def list_tunnels(
    session: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
    status_filter: str | None = None,
    sync_status_filter: str | None = None,
    search: str | None = None,
) -> tuple[list[Tunnel], int]:
    """List active (non-deleted) tunnels with pagination and filters.

    Args:
        session: Active database session.
        page: Page number (1-indexed).
        page_size: Number of items per page.
        status_filter: Filter by tunnel status (active/inactive).
        sync_status_filter: Filter by sync status.
        search: Search term for name or description.

    Returns:
        Tuple of (list of Tunnel instances, total count).
    """
    base_where = [Tunnel.deleted_at.is_(None)]

    if status_filter is not None:
        base_where.append(Tunnel.status == status_filter)
    if sync_status_filter is not None:
        base_where.append(Tunnel.sync_status == sync_status_filter)
    if search is not None:
        search_pattern = f"%{search}%"
        base_where.append(
            Tunnel.name.ilike(search_pattern) | Tunnel.description.ilike(search_pattern),
        )

    # Count query
    count_stmt = select(func.count()).select_from(Tunnel).where(*base_where)
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Paginated items query
    offset = (page - 1) * page_size
    items_stmt = (
        select(Tunnel)
        .where(*base_where)
        .order_by(Tunnel.name)
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(items_stmt)
    return list(result.scalars().all()), total


async def get_tunnel(session: AsyncSession, tunnel_id: int) -> Tunnel:
    """Get a single tunnel by ID.

    Args:
        session: Active database session.
        tunnel_id: Primary key of the tunnel.

    Returns:
        The Tunnel instance.

    Raises:
        NotFoundError: If no active tunnel with the given ID exists.
    """
    result = await session.execute(
        select(Tunnel)
        .options(selectinload(Tunnel.creator))
        .where(
            Tunnel.id == tunnel_id,
            Tunnel.deleted_at.is_(None),
        ),
    )
    tunnel = result.scalar_one_or_none()
    if tunnel is None:
        raise NotFoundError("Tunnel", tunnel_id)
    return tunnel


async def create_tunnel(
    session: AsyncSession,
    *,
    data: Any,
    user: User,
    request: Request | None = None,
) -> Tunnel:
    """Create a new IPSec tunnel and sync configuration to infrastructure.

    1. Validate name uniqueness among active tunnels.
    2. Acquire IPSEC_CONF_LOCK advisory lock.
    3. Insert tunnel with sync_status='pending'.
    4. Regenerate ipsec.conf from DB, upload to S3, reload via SSM.
    5. Set sync_status='synced' on success, 'failed' on infra error.
    6. Create audit log entry.
    7. Commit transaction.

    Args:
        session: Active database session.
        data: TunnelCreate schema instance.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The created Tunnel instance.

    Raises:
        ConflictError: If a tunnel with the same name already exists.
        LockConflictError: If the IPSEC_CONF_LOCK is held.
    """
    # Validate name uniqueness
    existing = await session.execute(
        select(Tunnel.id).where(
            Tunnel.name == data.name,
            Tunnel.deleted_at.is_(None),
        ),
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Tunnel with name '{data.name}' already exists")

    # Acquire lock
    await require_lock(session, LOCK_IPSEC_CONFIG)

    # Insert tunnel
    tunnel = Tunnel(
        name=data.name,
        description=data.description,
        peer_ip=str(data.peer_ip),
        local_cidrs=[str(c) for c in data.local_cidrs],
        remote_cidrs=[str(c) for c in data.remote_cidrs],
        psk_secret_name=data.psk_secret_name,
        ike_version=data.ike_version,
        ike_proposals=data.ike_proposals,
        esp_proposals=data.esp_proposals,
        dpd_action=data.dpd_action,
        dpd_delay=data.dpd_delay,
        dpd_timeout=data.dpd_timeout,
        status="active",
        sync_status="pending",
        created_by=user.id,
    )
    session.add(tunnel)
    await session.flush()

    # Sync infrastructure
    try:
        await ipsec_config.sync_ipsec_config(session)
        tunnel.sync_status = "synced"
        tunnel.sync_error = None
        logger.info("tunnel_create_synced", tunnel_id=tunnel.id, name=tunnel.name)
    except InfrastructureError as exc:
        tunnel.sync_status = "failed"
        tunnel.sync_error = exc.message
        logger.error(
            "tunnel_create_sync_failed",
            tunnel_id=tunnel.id,
            name=tunnel.name,
            error=exc.message,
        )

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="tunnel",
        entity_id=tunnel.id,
        action="create",
        new_state=_tunnel_to_dict(tunnel),
        request=request,
    )

    await session.commit()
    return tunnel


async def update_tunnel(
    session: AsyncSession,
    tunnel_id: int,
    *,
    data: Any,
    user: User,
    request: Request | None = None,
) -> Tunnel:
    """Update an existing tunnel and re-sync configuration if needed.

    1. Get existing tunnel, capture previous state.
    2. Acquire IPSEC_CONF_LOCK.
    3. Update changed fields.
    4. If connection-relevant fields changed, regenerate ipsec.conf.
    5. Update sync_status accordingly.
    6. Create audit log entry.
    7. Commit transaction.

    Args:
        session: Active database session.
        tunnel_id: Primary key of the tunnel to update.
        data: TunnelUpdate schema instance.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The updated Tunnel instance.

    Raises:
        NotFoundError: If the tunnel does not exist.
        ConflictError: If renaming to a name that already exists.
        LockConflictError: If the IPSEC_CONF_LOCK is held.
    """
    tunnel = await get_tunnel(session, tunnel_id)
    previous_state = _tunnel_to_dict(tunnel)

    # Check name uniqueness if renaming
    update_data = data.model_dump(exclude_unset=True)
    if "name" in update_data and update_data["name"] != tunnel.name:
        existing = await session.execute(
            select(Tunnel.id).where(
                Tunnel.name == update_data["name"],
                Tunnel.deleted_at.is_(None),
                Tunnel.id != tunnel_id,
            ),
        )
        if existing.scalar_one_or_none() is not None:
            raise ConflictError(f"Tunnel with name '{update_data['name']}' already exists")

    # Acquire lock
    await require_lock(session, LOCK_IPSEC_CONFIG)

    # Determine if infra sync is needed
    infra_fields = {"peer_ip", "local_cidrs", "remote_cidrs", "ike_version", "ike_proposals",
                    "esp_proposals", "dpd_action", "dpd_delay", "dpd_timeout", "name"}
    needs_sync = bool(infra_fields & set(update_data.keys()))

    # Apply updates
    for field, value in update_data.items():
        if field == "peer_ip" and value is not None:
            setattr(tunnel, field, str(value))
        elif field in ("local_cidrs", "remote_cidrs") and value is not None:
            setattr(tunnel, field, [str(c) for c in value])
        else:
            setattr(tunnel, field, value)

    # Sync infrastructure if connection params changed
    if needs_sync:
        tunnel.sync_status = "pending"
        try:
            await ipsec_config.sync_ipsec_config(session)
            tunnel.sync_status = "synced"
            tunnel.sync_error = None
            logger.info("tunnel_update_synced", tunnel_id=tunnel.id)
        except InfrastructureError as exc:
            tunnel.sync_status = "failed"
            tunnel.sync_error = exc.message
            logger.error(
                "tunnel_update_sync_failed",
                tunnel_id=tunnel.id,
                error=exc.message,
            )

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="tunnel",
        entity_id=tunnel.id,
        action="update",
        previous_state=previous_state,
        new_state=_tunnel_to_dict(tunnel),
        request=request,
    )

    await session.commit()
    return tunnel


async def delete_tunnel(
    session: AsyncSession,
    tunnel_id: int,
    *,
    user: User,
    request: Request | None = None,
) -> None:
    """Soft-delete a tunnel with cascade deletion of routes and iptables rules.

    This is the most complex operation:
    1. Get tunnel with its active routes and iptables rules.
    2. Acquire IPSEC_CONF_LOCK.
    3. For each active iptables rule: remove via SSM, soft-delete.
    4. For each active route: soft-delete (terragrunt cleanup noted as async ops).
    5. Soft-delete the tunnel.
    6. Regenerate ipsec.conf (tunnel now excluded).
    7. Create audit log entries for tunnel and all cascaded entities.
    8. Commit transaction.

    Args:
        session: Active database session.
        tunnel_id: Primary key of the tunnel to delete.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Raises:
        NotFoundError: If the tunnel does not exist.
        LockConflictError: If the IPSEC_CONF_LOCK is held.
    """
    tunnel = await get_tunnel(session, tunnel_id)
    previous_state = _tunnel_to_dict(tunnel)

    # Acquire lock
    await require_lock(session, LOCK_IPSEC_CONFIG)

    now = datetime.now(timezone.utc)

    # Cascade: remove iptables rules via SSM, then soft-delete
    active_rules = [r for r in tunnel.iptables_rules if r.deleted_at is None]
    for rule in active_rules:
        try:
            delete_cmd = build_iptables_command(rule, delete=True)
            await ssm.run_on_instances(
                commands=[f"{delete_cmd} || true"],
                target="both",
            )
            await ssm.run_on_instances(
                commands=["iptables-save > /etc/iptables/rules.v4"],
                target="both",
            )
        except InfrastructureError as exc:
            logger.error(
                "cascade_iptables_remove_failed",
                rule_id=rule.id,
                tunnel_id=tunnel_id,
                error=exc.message,
            )

        rule.deleted_at = now
        rule.status = "inactive" if hasattr(rule, "status") else rule.status  # noqa: PLW0120
        rule.sync_status = "pending_delete"

        await audit.log_action(
            session,
            user_id=user.id,
            entity_type="iptables_rule",
            entity_id=rule.id,
            action="delete",
            previous_state=_iptables_rule_to_dict(rule),
            request=request,
        )

    # Cascade: soft-delete routes
    active_routes = [r for r in tunnel.routes if r.deleted_at is None]
    for route in active_routes:
        route.deleted_at = now
        route.sync_status = "pending_delete"

        await audit.log_action(
            session,
            user_id=user.id,
            entity_type="route",
            entity_id=route.id,
            action="delete",
            previous_state=_route_to_dict(route),
            request=request,
        )

    # Soft-delete the tunnel itself
    tunnel.deleted_at = now
    tunnel.sync_status = "pending_delete"

    # Regenerate ipsec.conf without the deleted tunnel
    try:
        await ipsec_config.sync_ipsec_config(session)
        logger.info("tunnel_delete_synced", tunnel_id=tunnel_id)
    except InfrastructureError as exc:
        logger.error(
            "tunnel_delete_sync_failed",
            tunnel_id=tunnel_id,
            error=exc.message,
        )

    # Audit log for tunnel
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="tunnel",
        entity_id=tunnel.id,
        action="delete",
        previous_state=previous_state,
        request=request,
    )

    await session.commit()


async def retry_tunnel_sync(
    session: AsyncSession,
    tunnel_id: int,
    *,
    user: User,
    request: Request | None = None,
) -> Tunnel:
    """Retry a failed tunnel sync operation.

    Only works when the tunnel's sync_status is 'failed'. Re-runs the
    ipsec.conf regeneration, S3 upload, and SSM reload cycle.

    Args:
        session: Active database session.
        tunnel_id: Primary key of the tunnel to retry.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The updated Tunnel instance.

    Raises:
        NotFoundError: If the tunnel does not exist.
        ConflictError: If sync_status is not 'failed'.
        LockConflictError: If the IPSEC_CONF_LOCK is held.
    """
    tunnel = await get_tunnel(session, tunnel_id)

    if tunnel.sync_status != "failed":
        raise ConflictError(
            f"Tunnel {tunnel_id} sync_status is '{tunnel.sync_status}', not 'failed'. Retry only works on failed syncs."
        )

    # Acquire lock
    await require_lock(session, LOCK_IPSEC_CONFIG)

    tunnel.sync_status = "pending"
    try:
        await ipsec_config.sync_ipsec_config(session)
        tunnel.sync_status = "synced"
        tunnel.sync_error = None
        logger.info("tunnel_retry_synced", tunnel_id=tunnel.id)
    except InfrastructureError as exc:
        tunnel.sync_status = "failed"
        tunnel.sync_error = exc.message
        logger.error(
            "tunnel_retry_sync_failed",
            tunnel_id=tunnel.id,
            error=exc.message,
        )

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="tunnel",
        entity_id=tunnel.id,
        action="retry",
        new_state=_tunnel_to_dict(tunnel),
        request=request,
    )

    await session.commit()
    return tunnel


async def get_tunnel_status(
    session: AsyncSession,
    tunnel_id: int,
) -> dict[str, Any]:
    """Get live tunnel status by running 'ipsec statusall' on the primary instance.

    Args:
        session: Active database session.
        tunnel_id: Primary key of the tunnel to check.

    Returns:
        Dict with tunnel_id, name, state (UP/DOWN/UNKNOWN), details, checked_at.

    Raises:
        NotFoundError: If the tunnel does not exist.
    """
    tunnel = await get_tunnel(session, tunnel_id)
    settings = get_settings()
    checked_at = datetime.now(timezone.utc)

    try:
        primary_id = await ssm.resolve_instance_id(settings.vpn_primary_instance_name)
        output = await ssm.execute_command(
            instance_id=primary_id,
            commands=["ipsec statusall"],
            timeout=settings.ssm_command_timeout,
        )
        state = _parse_tunnel_state(tunnel.name, output)
        return {
            "tunnel_id": tunnel.id,
            "name": tunnel.name,
            "state": state,
            "details": output if state != "UNKNOWN" else None,
            "checked_at": checked_at,
        }
    except InfrastructureError as exc:
        logger.error(
            "tunnel_status_check_failed",
            tunnel_id=tunnel_id,
            error=exc.message,
        )
        return {
            "tunnel_id": tunnel.id,
            "name": tunnel.name,
            "state": "UNKNOWN",
            "details": None,
            "checked_at": checked_at,
        }


def _parse_tunnel_state(tunnel_name: str, ipsec_output: str) -> str:
    """Parse 'ipsec statusall' output to determine tunnel state.

    Looks for the connection name in the output and checks for ESTABLISHED
    or INSTALLED keywords which indicate an active tunnel.

    Args:
        tunnel_name: Name of the tunnel connection.
        ipsec_output: Raw output from ipsec statusall.

    Returns:
        'UP', 'DOWN', or 'UNKNOWN'.
    """
    if not ipsec_output:
        return "UNKNOWN"

    # Look for connection-specific status lines
    lines = ipsec_output.lower().splitlines()
    found_connection = False
    for line in lines:
        if tunnel_name.lower() in line:
            found_connection = True
            if "established" in line or "installed" in line:
                return "UP"

    return "DOWN" if found_connection else "UNKNOWN"


def _iptables_rule_to_dict(rule: IPTablesRule) -> dict[str, Any]:
    """Serialize an IPTablesRule model to a dict for audit JSONB storage."""
    return {
        "id": rule.id,
        "tunnel_id": rule.tunnel_id,
        "chain": rule.chain,
        "protocol": rule.protocol,
        "source_cidr": str(rule.source_cidr) if rule.source_cidr else None,
        "dest_cidr": str(rule.dest_cidr) if rule.dest_cidr else None,
        "sport": rule.sport,
        "dport": rule.dport,
        "action": rule.action,
        "state_match": list(rule.state_match) if rule.state_match else None,
        "comment": rule.comment,
        "position": rule.position,
        "sync_status": rule.sync_status,
        "sync_error": rule.sync_error,
    }


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
    }
