"""Access requests router — Tier 2 elevated access requests via Shortcut."""

from __future__ import annotations

from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import get_current_user
from app.config import get_settings
from app.db.models import AccessRequest, TIER2_PERMISSION_KEYS
from app.db.session import get_db
from app.exceptions import NotFoundError, ValidationError
from app.logging_config import get_logger
from app.schemas.access_request import (
    AccessRequestCreate,
    AccessRequestDetail,
    Tier2Catalog,
    Tier2CatalogEntry,
)
from app.db.models import User
from app.services import audit
from app.services.permissions import TIER2_CATALOG
from app.services.secrets_cache import resolve_shortcut_token
from app.services.shortcut_service import ShortcutError, create_story

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/access-requests", tags=["access-requests"])


@router.get(
    "/catalog",
    response_model=Tier2Catalog,
    summary="List available Tier 2 elevated access types",
)
async def get_catalog(
    current_user: User = Depends(get_current_user),
) -> Tier2Catalog:
    """Return the catalog of Tier 2 elevated access permissions.

    ``enabled`` is False when SHORTCUT_API_TOKEN is not configured —
    the UI should hide the request flow in that case.
    """
    settings = get_settings()
    enabled = bool(resolve_shortcut_token(settings))
    entries = [
        Tier2CatalogEntry(
            permission_key=key,
            description=meta["description"],
            max_duration_hours=meta["max_duration_hours"],
        )
        for key, meta in TIER2_CATALOG.items()
    ]
    return Tier2Catalog(entries=entries, enabled=enabled)


@router.post(
    "/",
    response_model=AccessRequestDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create a Tier 2 elevated access request",
)
async def create_access_request(
    data: AccessRequestCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> AccessRequestDetail:
    """Submit a Tier 2 elevated access request.

    - Creates a Shortcut story in the requested workflow state.
    - The access_poller background job polls Shortcut and grants/revokes
      access when the story is approved by an authorized lead.

    Returns 400 if:
    - The permission key is not in the Tier 2 catalog.
    - The duration exceeds the catalog maximum.
    - There is already a non-final request for this user/permission.
    - Shortcut is not configured.
    """
    settings = get_settings()
    token = resolve_shortcut_token(settings)
    if not token:
        raise ValidationError("Elevated access requests require Shortcut integration (not configured)")

    if data.permission_key not in TIER2_CATALOG:
        raise ValidationError(f"Unknown Tier 2 permission key: {data.permission_key!r}")

    catalog_meta = TIER2_CATALOG[data.permission_key]
    if data.duration_hours > catalog_meta["max_duration_hours"]:
        raise ValidationError(
            f"Requested duration {data.duration_hours}h exceeds maximum "
            f"{catalog_meta['max_duration_hours']}h for {data.permission_key!r}"
        )

    # Check for an existing non-final request
    result = await db.execute(
        select(AccessRequest).where(
            AccessRequest.user_id == current_user.id,
            AccessRequest.permission_key == data.permission_key,
            AccessRequest.status.notin_(["rejected", "invalid", "revoked", "expired"]),
        )
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        raise ValidationError(
            f"An active or pending request for {data.permission_key!r} already exists "
            f"(id={existing.id}, status={existing.status!r})"
        )

    # Build Shortcut story fields
    story_name = (
        f"[{settings.shortcut_environment.upper()}] Elevated access: "
        f"{data.permission_key} for {current_user.email} ({data.duration_hours}h)"
    )
    story_description = (
        f"**Permission**: {data.permission_key}\n"
        f"**Duration**: {data.duration_hours} hour(s)\n"
        f"**Justification**: {data.justification}\n\n"
        f"*Submitted by {current_user.email}*"
    )
    labels = ["access-request", "strongswan-manager", "tier-2"]

    try:
        story = await create_story(
            token=token,
            workflow_state_id=settings.shortcut_wf_requested_id,
            project_id=settings.shortcut_project_id,
            group_id=settings.shortcut_group_id,
            requested_by_id=current_user.shortcut_member_id,
            name=story_name,
            description=story_description,
            labels=labels,
        )
    except ShortcutError as exc:
        logger.error("shortcut_create_story_failed", error=str(exc))
        raise ValidationError(f"Failed to create Shortcut story: {exc}") from exc

    # Persist the access request
    req = AccessRequest(
        user_id=current_user.id,
        permission_key=data.permission_key,
        duration_seconds=data.duration_hours * 3600,
        justification=data.justification,
        shortcut_story_id=story["id"],
        shortcut_story_url=story.get("app_url"),
        status="requested",
    )
    db.add(req)
    await db.flush()

    await audit.log_action(
        db,
        user_id=current_user.id,
        entity_type="access_request",
        entity_id=req.id,
        action="access_request",
        new_state={
            "permission_key": req.permission_key,
            "duration_hours": data.duration_hours,
            "shortcut_story_id": req.shortcut_story_id,
        },
    )
    await db.commit()

    logger.info(
        "access_request_created",
        request_id=req.id,
        user_id=current_user.id,
        permission_key=req.permission_key,
        shortcut_story_id=req.shortcut_story_id,
    )
    return AccessRequestDetail.from_orm_with_hours(req)


@router.get(
    "/",
    response_model=list[AccessRequestDetail],
    summary="List current user's access requests",
)
async def list_access_requests(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
) -> list[AccessRequestDetail]:
    """Return all Tier 2 access requests submitted by the current user, newest first."""
    result = await db.execute(
        select(AccessRequest)
        .where(AccessRequest.user_id == current_user.id)
        .order_by(AccessRequest.id.desc())
    )
    requests = result.scalars().all()
    return [AccessRequestDetail.from_orm_with_hours(r) for r in requests]
