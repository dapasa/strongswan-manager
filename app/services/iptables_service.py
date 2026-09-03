"""IPTables orchestration service — coordinates DB + SSM for iptables rule management."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import IPTablesRule, Tunnel, User
from app.exceptions import ConflictError, InfrastructureError, NotFoundError, ValidationError
from app.logging_config import get_logger
from app.services import audit, ssm
from app.services.locks import (
    LOCK_IPTABLES_PRIMARY,
    LOCK_IPTABLES_SECONDARY,
    require_lock,
)

logger = get_logger(__name__)


def _rule_to_dict(rule: IPTablesRule) -> dict[str, Any]:
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
        "created_by": rule.created_by,
        "created_at": rule.created_at.isoformat() if rule.created_at else None,
        "updated_at": rule.updated_at.isoformat() if rule.updated_at else None,
    }


def build_iptables_command(rule: IPTablesRule, *, delete: bool = False) -> str:
    """Generate an iptables command string from structured rule fields.

    Produces a command like:
        iptables -A FORWARD -p tcp -s 10.0.0.0/24 -d 172.16.0.0/16 --dport 443 -j ACCEPT

    Only includes flags for non-null fields. When ``delete=True``, uses
    ``-D`` instead of ``-A`` so the exact matching rule is removed.

    Args:
        rule: The structured IPTablesRule model instance.
        delete: If True, use -D (delete) instead of -A (append).

    Returns:
        Complete iptables command string safe for SSM execution.
    """
    action_flag = "-D" if delete else "-A"
    parts: list[str] = ["iptables", action_flag, rule.chain]

    if rule.protocol and rule.protocol != "all":
        parts.extend(["-p", rule.protocol])

    if rule.source_cidr:
        parts.extend(["-s", str(rule.source_cidr)])

    if rule.dest_cidr:
        parts.extend(["-d", str(rule.dest_cidr)])

    if rule.sport is not None:
        parts.extend(["--sport", str(rule.sport)])

    if rule.dport is not None:
        parts.extend(["--dport", str(rule.dport)])

    if rule.state_match:
        parts.extend(["-m", "state", "--state", ",".join(rule.state_match)])

    if rule.comment:
        parts.extend(["-m", "comment", "--comment", f'"{rule.comment}"'])

    parts.extend(["-j", rule.action])

    return " ".join(parts)


async def list_rules(
    session: AsyncSession,
    *,
    tunnel_id: int | None = None,
) -> list[IPTablesRule]:
    """List active (non-deleted) iptables rules with optional filters.

    Args:
        session: Active database session.
        tunnel_id: If provided, filter rules to this tunnel only.

    Returns:
        List of active IPTablesRule instances.
    """
    stmt = select(IPTablesRule).where(IPTablesRule.deleted_at.is_(None))
    if tunnel_id is not None:
        stmt = stmt.where(IPTablesRule.tunnel_id == tunnel_id)
    stmt = stmt.order_by(IPTablesRule.position.nulls_last(), IPTablesRule.id)

    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_rule(session: AsyncSession, rule_id: int) -> IPTablesRule:
    """Get a single iptables rule by ID.

    Args:
        session: Active database session.
        rule_id: Primary key of the iptables rule.

    Returns:
        The IPTablesRule instance.

    Raises:
        NotFoundError: If no active rule with the given ID exists.
    """
    result = await session.execute(
        select(IPTablesRule).where(
            IPTablesRule.id == rule_id,
            IPTablesRule.deleted_at.is_(None),
        ),
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise NotFoundError("IPTablesRule", rule_id)
    return rule


async def create_rule(
    session: AsyncSession,
    *,
    tunnel_id: int,
    data: Any,
    user: User,
    request: Request | None = None,
) -> IPTablesRule:
    """Create an iptables rule, apply it via SSM, and persist to DB.

    1. Verify tunnel exists and is active.
    2. Insert rule with sync_status='pending'.
    3. Build iptables command from structured fields.
    4. Acquire advisory lock(s) for iptables operations.
    5. Execute command via SSM on both VPN instances.
    6. Execute iptables-save via SSM.
    7. Set sync_status='synced' on success, 'failed' on error.
    8. Create audit log entry.
    9. Commit transaction.

    Args:
        session: Active database session.
        tunnel_id: Tunnel this rule belongs to.
        data: IPTablesRuleCreate schema instance.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The created IPTablesRule instance.

    Raises:
        NotFoundError: If the tunnel does not exist.
        ValidationError: If the tunnel is not active.
        LockConflictError: If the iptables lock is held.
    """
    # Verify tunnel
    await _get_active_tunnel(session, tunnel_id)

    # Acquire iptables lock (both instances)
    await require_lock(session, LOCK_IPTABLES_PRIMARY)
    await require_lock(session, LOCK_IPTABLES_SECONDARY)

    # Insert rule
    rule = IPTablesRule(
        tunnel_id=tunnel_id,
        chain=data.chain,
        protocol=data.protocol,
        source_cidr=str(data.source_cidr) if data.source_cidr else None,
        dest_cidr=str(data.dest_cidr) if data.dest_cidr else None,
        sport=data.sport,
        dport=data.dport,
        action=data.action,
        state_match=list(data.state_match) if data.state_match else None,
        comment=data.comment,
        position=data.position,
        sync_status="pending",
        created_by=user.id,
    )
    session.add(rule)
    await session.flush()

    # Build and apply command
    command = build_iptables_command(rule)
    try:
        await ssm.run_on_instances(commands=[command], target="both")
        await ssm.run_on_instances(
            commands=["iptables-save > /etc/iptables/rules.v4"],
            target="both",
        )
        rule.sync_status = "synced"
        rule.sync_error = None
        logger.info("iptables_rule_synced", rule_id=rule.id, command=command)
    except InfrastructureError as exc:
        rule.sync_status = "failed"
        rule.sync_error = exc.message
        logger.error(
            "iptables_rule_sync_failed",
            rule_id=rule.id,
            command=command,
            error=exc.message,
        )

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="iptables_rule",
        entity_id=rule.id,
        action="create",
        new_state=_rule_to_dict(rule),
        request=request,
    )

    await session.commit()
    # Refresh to load server-generated columns (created_at, updated_at) that
    # become expired after the flush. Without this the router's direct access
    # to rule.updated_at raises MissingGreenlet in the async context.
    await session.refresh(rule)
    return rule


async def update_rule(
    session: AsyncSession,
    rule_id: int,
    *,
    data: Any,
    user: User,
    request: Request | None = None,
) -> IPTablesRule:
    """Update an iptables rule by removing the old and applying the new.

    1. Get existing rule, capture previous state.
    2. If structural fields changed:
        a. Build old command with delete=True, remove via SSM.
        b. Build new command, apply via SSM.
        c. Save iptables.
    3. Update DB fields.
    4. Create audit log entry.
    5. Commit transaction.

    Args:
        session: Active database session.
        rule_id: Primary key of the rule to update.
        data: IPTablesRuleUpdate schema instance.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The updated IPTablesRule instance.

    Raises:
        NotFoundError: If the rule does not exist.
        LockConflictError: If the iptables lock is held.
    """
    rule = await get_rule(session, rule_id)
    previous_state = _rule_to_dict(rule)

    update_data = data.model_dump(exclude_unset=True)
    if not update_data:
        return rule  # Nothing to update

    # Determine if structural fields changed (requiring SSM re-apply)
    structural_fields = {
        "chain", "protocol", "source_cidr", "dest_cidr",
        "sport", "dport", "action", "state_match", "comment",
    }
    needs_ssm = bool(structural_fields & set(update_data.keys()))

    if needs_ssm:
        # Acquire locks
        await require_lock(session, LOCK_IPTABLES_PRIMARY)
        await require_lock(session, LOCK_IPTABLES_SECONDARY)

        # Remove old rule via SSM (ignore failures — rule might not be applied)
        old_delete_cmd = build_iptables_command(rule, delete=True)
        try:
            await ssm.run_on_instances(
                commands=[f"{old_delete_cmd} || true"],
                target="both",
            )
        except InfrastructureError as exc:
            logger.warning(
                "iptables_old_rule_remove_failed",
                rule_id=rule.id,
                error=exc.message,
            )

    # Apply updates to DB fields
    for field, value in update_data.items():
        if field in ("source_cidr", "dest_cidr") and value is not None:
            setattr(rule, field, str(value))
        elif field == "state_match" and value is not None:
            setattr(rule, field, list(value))
        else:
            setattr(rule, field, value)

    if needs_ssm:
        # Apply new rule via SSM
        rule.sync_status = "pending"
        new_cmd = build_iptables_command(rule)
        try:
            await ssm.run_on_instances(commands=[new_cmd], target="both")
            await ssm.run_on_instances(
                commands=["iptables-save > /etc/iptables/rules.v4"],
                target="both",
            )
            rule.sync_status = "synced"
            rule.sync_error = None
            logger.info("iptables_rule_updated_synced", rule_id=rule.id, command=new_cmd)
        except InfrastructureError as exc:
            rule.sync_status = "failed"
            rule.sync_error = exc.message
            logger.error(
                "iptables_rule_update_sync_failed",
                rule_id=rule.id,
                error=exc.message,
            )

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="iptables_rule",
        entity_id=rule.id,
        action="update",
        previous_state=previous_state,
        new_state=_rule_to_dict(rule),
        request=request,
    )

    await session.commit()
    # Refresh to reload updated_at after onupdate=func.now() marks it expired.
    await session.refresh(rule)
    return rule


async def retry_rule(
    session: AsyncSession,
    rule_id: int,
    *,
    user: User,
    request: Request | None = None,
) -> IPTablesRule:
    """Retry a failed iptables rule sync.

    Only works when the rule's sync_status is 'failed'. Re-applies the
    iptables command via SSM.

    Args:
        session: Active database session.
        rule_id: Primary key of the rule to retry.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The updated IPTablesRule instance.

    Raises:
        NotFoundError: If the rule does not exist.
        ConflictError: If sync_status is not 'failed'.
        LockConflictError: If the iptables lock is held.
    """
    rule = await get_rule(session, rule_id)

    if rule.sync_status != "failed":
        raise ConflictError(
            f"IPTables rule {rule_id} sync_status is '{rule.sync_status}', not 'failed'. "
            "Retry only works on failed syncs."
        )

    # Acquire locks
    await require_lock(session, LOCK_IPTABLES_PRIMARY)
    await require_lock(session, LOCK_IPTABLES_SECONDARY)

    rule.sync_status = "pending"
    command = build_iptables_command(rule)
    try:
        await ssm.run_on_instances(commands=[command], target="both")
        await ssm.run_on_instances(
            commands=["iptables-save > /etc/iptables/rules.v4"],
            target="both",
        )
        rule.sync_status = "synced"
        rule.sync_error = None
        logger.info("iptables_rule_retry_synced", rule_id=rule.id, command=command)
    except InfrastructureError as exc:
        rule.sync_status = "failed"
        rule.sync_error = exc.message
        logger.error(
            "iptables_rule_retry_sync_failed",
            rule_id=rule.id,
            error=exc.message,
        )

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="iptables_rule",
        entity_id=rule.id,
        action="retry",
        new_state=_rule_to_dict(rule),
        request=request,
    )

    await session.commit()
    # Refresh to reload updated_at after retry sets sync_status and commits.
    await session.refresh(rule)
    return rule


async def delete_rule(
    session: AsyncSession,
    rule_id: int,
    *,
    user: User,
    request: Request | None = None,
) -> None:
    """Remove an iptables rule via SSM and soft-delete from DB.

    1. Get rule.
    2. Build delete command.
    3. Acquire iptables lock(s).
    4. Execute delete command via SSM (|| true to avoid failure if already removed).
    5. Save iptables via SSM.
    6. Soft-delete in DB.
    7. Create audit log entry.
    8. Commit transaction.

    Args:
        session: Active database session.
        rule_id: Primary key of the rule to delete.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Raises:
        NotFoundError: If the rule does not exist.
        LockConflictError: If the iptables lock is held.
    """
    rule = await get_rule(session, rule_id)
    previous_state = _rule_to_dict(rule)

    # Acquire locks
    await require_lock(session, LOCK_IPTABLES_PRIMARY)
    await require_lock(session, LOCK_IPTABLES_SECONDARY)

    # Remove via SSM
    delete_cmd = build_iptables_command(rule, delete=True)
    try:
        await ssm.run_on_instances(
            commands=[f"{delete_cmd} || true"],
            target="both",
        )
        await ssm.run_on_instances(
            commands=["iptables-save > /etc/iptables/rules.v4"],
            target="both",
        )
        logger.info("iptables_rule_removed", rule_id=rule.id)
    except InfrastructureError as exc:
        logger.error(
            "iptables_rule_remove_failed",
            rule_id=rule.id,
            error=exc.message,
        )

    # Soft-delete in DB
    rule.deleted_at = datetime.now(timezone.utc)
    rule.sync_status = "pending_delete"

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="iptables_rule",
        entity_id=rule.id,
        action="delete",
        previous_state=previous_state,
        request=request,
    )

    await session.commit()


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
