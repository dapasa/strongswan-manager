"""IPTables router — CRUD for structured iptables rules applied via SSM."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import assert_permission, get_current_user, require_viewer
from app.db.models import User
from app.db.session import get_db
from app.logging_config import get_logger
from app.schemas.iptables import IPTablesRuleCreate, IPTablesRuleDetail, IPTablesRuleUpdate
from app.services import iptables_service
from app.services.iptables_service import build_iptables_command

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/iptables", tags=["iptables"])


def _to_detail(rule: object) -> IPTablesRuleDetail:
    """Map an IPTablesRule ORM instance to IPTablesRuleDetail."""
    r = rule  # type: ignore[assignment]
    return IPTablesRuleDetail(
        id=r.id,
        tunnel_id=r.tunnel_id,
        rule_table=getattr(r, "rule_table", "filter") or "filter",
        chain=r.chain,
        protocol=r.protocol,
        source_cidr=str(r.source_cidr) if r.source_cidr else None,
        dest_cidr=str(r.dest_cidr) if r.dest_cidr else None,
        sport=r.sport,
        dport=r.dport,
        action=r.action,
        to_source=str(r.to_source) if r.to_source else None,
        state_match=list(r.state_match) if r.state_match else None,
        comment=r.comment,
        position=r.position,
        sync_status=r.sync_status,
        sync_error=r.sync_error,
        command_preview=build_iptables_command(r),
        created_by=r.created_by,
        created_at=r.created_at,
        updated_at=r.updated_at,
    )


def _perm_for_action(action: str) -> str:
    """Return the required permission key for the given iptables action."""
    return "iptables.snat" if action == "SNAT" else "iptables.filter"


@router.get(
    "/",
    response_model=list[IPTablesRuleDetail],
    summary="List active iptables rules",
)
async def list_rules(
    tunnel_id: int | None = Query(None, description="Filter by tunnel ID"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> list[IPTablesRuleDetail]:
    """List all active iptables rules with optional tunnel filter."""
    rules = await iptables_service.list_rules(db, tunnel_id=tunnel_id)
    return [_to_detail(r) for r in rules]


@router.get(
    "/{rule_id}",
    response_model=IPTablesRuleDetail,
    summary="Get iptables rule detail",
)
async def get_rule(
    rule_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> IPTablesRuleDetail:
    """Get a single iptables rule with generated command preview."""
    rule = await iptables_service.get_rule(db, rule_id)
    return _to_detail(rule)


@router.post(
    "/",
    response_model=IPTablesRuleDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create iptables rule",
)
async def create_rule(
    data: IPTablesRuleCreate,
    request: Request,
    tunnel_id: int = Query(..., description="Tunnel this rule belongs to"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IPTablesRuleDetail:
    """Create an iptables rule, apply via SSM, and persist.

    Requires 'iptables.filter' for ACCEPT/DROP/REJECT actions or
    'iptables.snat' for SNAT actions.
    """
    perm = _perm_for_action(data.action)
    await assert_permission(current_user, perm, db)

    rule = await iptables_service.create_rule(
        db,
        tunnel_id=tunnel_id,
        data=data,
        user=current_user,
        request=request,
    )
    return _to_detail(rule)


@router.patch(
    "/{rule_id}",
    response_model=IPTablesRuleDetail,
    summary="Update iptables rule",
)
async def update_rule(
    rule_id: int,
    data: IPTablesRuleUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IPTablesRuleDetail:
    """Update an iptables rule — removes old and applies new via SSM if structural fields changed.

    Checks permission based on the existing rule's action. If the update
    changes the action to SNAT, 'iptables.snat' is also required.
    """
    existing = await iptables_service.get_rule(db, rule_id)
    perm = _perm_for_action(existing.action)
    await assert_permission(current_user, perm, db)

    # If action is being changed, also check the new action's permission
    if data.action is not None and data.action != existing.action:
        new_perm = _perm_for_action(data.action)
        if new_perm != perm:
            await assert_permission(current_user, new_perm, db)

    rule = await iptables_service.update_rule(
        db,
        rule_id,
        data=data,
        user=current_user,
        request=request,
    )
    return _to_detail(rule)


@router.post(
    "/{rule_id}/retry",
    response_model=IPTablesRuleDetail,
    summary="Retry failed iptables rule sync",
)
async def retry_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> IPTablesRuleDetail:
    """Retry a failed iptables rule sync. Only works when sync_status='failed'.

    Requires the permission matching the existing rule's action.
    """
    existing = await iptables_service.get_rule(db, rule_id)
    perm = _perm_for_action(existing.action)
    await assert_permission(current_user, perm, db)

    rule = await iptables_service.retry_rule(
        db,
        rule_id,
        user=current_user,
        request=request,
    )
    return _to_detail(rule)


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete iptables rule",
)
async def delete_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> None:
    """Remove iptables rule via SSM and soft-delete from database.

    Requires the permission matching the existing rule's action.
    """
    existing = await iptables_service.get_rule(db, rule_id)
    perm = _perm_for_action(existing.action)
    await assert_permission(current_user, perm, db)

    await iptables_service.delete_rule(
        db,
        rule_id,
        user=current_user,
        request=request,
    )
