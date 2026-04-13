"""IPTables router — CRUD for structured iptables rules applied via SSM."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin, require_viewer
from app.db.models import User
from app.db.session import get_db
from app.logging_config import get_logger
from app.schemas.iptables import IPTablesRuleCreate, IPTablesRuleDetail, IPTablesRuleUpdate
from app.services import iptables_service
from app.services.iptables_service import build_iptables_command

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/iptables", tags=["iptables"])


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
    return [
        IPTablesRuleDetail(
            **{
                "id": r.id,
                "tunnel_id": r.tunnel_id,
                "chain": r.chain,
                "protocol": r.protocol,
                "source_cidr": str(r.source_cidr) if r.source_cidr else None,
                "dest_cidr": str(r.dest_cidr) if r.dest_cidr else None,
                "sport": r.sport,
                "dport": r.dport,
                "action": r.action,
                "state_match": list(r.state_match) if r.state_match else None,
                "comment": r.comment,
                "position": r.position,
                "sync_status": r.sync_status,
                "sync_error": r.sync_error,
                "command_preview": build_iptables_command(r),
                "created_by": r.created_by,
                "created_at": r.created_at,
                "updated_at": r.updated_at,
            }
        )
        for r in rules
    ]


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
    current_user: User = Depends(require_admin),
) -> IPTablesRuleDetail:
    """Create an iptables rule, apply via SSM, and persist."""
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
    current_user: User = Depends(require_admin),
) -> IPTablesRuleDetail:
    """Update an iptables rule — removes old and applies new via SSM if structural fields changed."""
    rule = await iptables_service.update_rule(
        db,
        rule_id,
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


@router.post(
    "/{rule_id}/retry",
    response_model=IPTablesRuleDetail,
    summary="Retry failed iptables rule sync",
)
async def retry_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> IPTablesRuleDetail:
    """Retry a failed iptables rule sync. Only works when sync_status='failed'."""
    rule = await iptables_service.retry_rule(
        db,
        rule_id,
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


@router.delete(
    "/{rule_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete iptables rule",
)
async def delete_rule(
    rule_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    """Remove iptables rule via SSM and soft-delete from database."""
    await iptables_service.delete_rule(
        db,
        rule_id,
        user=current_user,
        request=request,
    )
