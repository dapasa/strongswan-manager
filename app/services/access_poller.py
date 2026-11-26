"""Background poller for Tier 2 access requests (Shortcut-approved).

The manager is on a private network, so webhooks are not available.
One poller loop (started once in the app lifespan) periodically checks
all non-final access requests against Shortcut and applies grants/revocations.

Design:
  - Poll cycle: sleep N seconds, then process every non-final request.
  - Each request is processed in its own session.
  - Shortcut errors are logged and retried on the next cycle (never grant on error).
  - Expiry is enforced both here (eagerly) and at permission-check time (fail-closed).
  - If SHORTCUT_API_TOKEN is empty, the poller returns immediately without
    starting the loop.

State transitions applied by the poller:
  requested → active      (card in Approved + lead approver + not requester)
  requested → rejected    (card in Completed/Rejected before Approved)
  requested → invalid     (approved by non-lead or by requester)
  active    → revoked     (card left Approved, card gone, or manual admin revoke)
  active    → expired     (expires_at <= now)
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import AccessRequest, AuditLog
from app.logging_config import get_logger
from app.services import shortcut_service
from app.services.secrets_cache import resolve_shortcut_token
from app.services.shortcut_service import ShortcutError, find_approver_in_history

if __debug__:
    from app.config import Settings

logger = get_logger(__name__)


async def _audit(
    session: AsyncSession,
    *,
    user_id: int | None,
    entity_id: int | None,
    action: str,
    new_state: dict | None = None,
) -> None:
    """Write an audit log entry.  Caller commits."""
    session.add(
        AuditLog(
            user_id=user_id,
            action=action,
            entity_type="access_request",
            entity_id=entity_id,
            new_state=new_state,
        )
    )


async def _expire_active_requests(
    session: AsyncSession,
    req: AccessRequest,
) -> bool:
    """Mark a request expired if its expiry has passed.  Returns True if expired."""
    if req.status != "active":
        return False
    if req.expires_at is None:
        return False
    now = datetime.now(timezone.utc)
    if req.expires_at <= now:
        req.status = "expired"
        req.revoked_at = now
        req.reason = "Access expired"
        await _audit(
            session,
            user_id=req.user_id,
            entity_id=req.id,
            action="access_revoke",
            new_state={"reason": "expired", "expires_at": req.expires_at.isoformat()},
        )
        logger.info("access_request_expired", request_id=req.id, user_id=req.user_id)
        return True
    return False


async def _process_request(
    request_id: int,
    session: AsyncSession,
    settings: "Settings",
) -> None:
    """Process a single non-final access request within an open session.

    Loads the request fresh, checks expiry, then polls Shortcut.
    Commits the session before returning.
    """
    token = resolve_shortcut_token(settings)

    result = await session.execute(
        select(AccessRequest).where(AccessRequest.id == request_id)
    )
    req = result.scalar_one_or_none()
    if req is None or req.status not in ("requested", "active"):
        return  # Already final or gone

    # --- Eager expiry check ---
    if await _expire_active_requests(session, req):
        # Try to comment on card (best-effort)
        if req.shortcut_story_id:
            await shortcut_service.post_comment(
                token=token,
                story_id=req.shortcut_story_id,
                text=f"Access grant **expired** at {req.expires_at.isoformat() if req.expires_at else 'N/A'} UTC.",
            )
        await session.commit()
        return

    if not req.shortcut_story_id:
        # Story creation failed earlier; nothing to poll
        logger.warning("access_request_no_story_id", request_id=request_id)
        return

    story_id = req.shortcut_story_id

    # --- Poll Shortcut ---
    try:
        story = await shortcut_service.get_story(token=token, story_id=story_id)
    except ShortcutError as exc:
        logger.warning("shortcut_poll_error", request_id=request_id, error=str(exc))
        return  # Retry next cycle

    now = datetime.now(timezone.utc)

    # 404 — story deleted
    if story is None:
        if req.status == "active":
            req.status = "revoked"
            req.revoked_at = now
            req.reason = "Shortcut story deleted"
            await _audit(
                session,
                user_id=req.user_id,
                entity_id=req.id,
                action="access_revoke",
                new_state={"reason": "story_deleted"},
            )
            logger.info("access_revoked_story_deleted", request_id=request_id)
        else:
            # Still in 'requested' — mark rejected
            req.status = "rejected"
            req.reason = "Shortcut story deleted before approval"
            await _audit(
                session,
                user_id=req.user_id,
                entity_id=req.id,
                action="access_reject",
                new_state={"reason": "story_deleted"},
            )
        await session.commit()
        return

    current_wf_state = story.get("workflow_state_id")
    approved_id = settings.shortcut_wf_approved_id
    completed_id = settings.shortcut_wf_completed_id
    rejected_id = settings.shortcut_wf_rejected_id

    # --- Active grant: check if card left Approved ---
    if req.status == "active":
        if current_wf_state != approved_id:
            req.status = "revoked"
            req.revoked_at = now
            req.reason = f"Shortcut card left Approved (state={current_wf_state})"
            if req.shortcut_story_id:
                await shortcut_service.post_comment(
                    token=token,
                    story_id=req.shortcut_story_id,
                    text=(
                        f"Access for **{story.get('name', '')}** has been **revoked** "
                        "because the card left the Approved state."
                    ),
                )
            await _audit(
                session,
                user_id=req.user_id,
                entity_id=req.id,
                action="access_revoke",
                new_state={"reason": "card_left_approved", "wf_state": current_wf_state},
            )
            logger.info("access_revoked_card_left_approved", request_id=request_id)
        # Still active — nothing to do until expiry or state change
        await session.commit()
        return

    # --- Requested: check for Approved / Rejected / Completed transitions ---
    if req.status == "requested":
        if current_wf_state in (rejected_id, completed_id):
            # Went straight to final without approval
            req.status = "rejected"
            req.reason = f"Shortcut card moved to final state (state={current_wf_state}) before approval"
            await _audit(
                session,
                user_id=req.user_id,
                entity_id=req.id,
                action="access_reject",
                new_state={"wf_state": current_wf_state},
            )
            logger.info("access_rejected_card_final", request_id=request_id)
            await session.commit()
            return

        if current_wf_state != approved_id:
            # Still in Requested (or some other intermediate state)
            await session.commit()
            return

        # Card is in Approved — find who approved it
        try:
            history = await shortcut_service.get_story_history(
                token=token, story_id=story_id
            )
        except ShortcutError as exc:
            logger.warning("shortcut_history_error", request_id=request_id, error=str(exc))
            await session.commit()
            return  # Retry next cycle

        approver_member_id = find_approver_in_history(history, approved_state_id=approved_id)

        if approver_member_id is None:
            # Cannot determine approver — log and retry
            logger.warning("shortcut_no_approver_found", request_id=request_id, story_id=story_id)
            await session.commit()
            return

        leads = settings.shortcut_lead_member_ids
        requester_member_id = story.get("requested_by_id")  # may differ if fallback was used
        # Also check against user's stored member id as requester
        # (the story's requested_by_id is the most reliable identity)

        is_lead = approver_member_id in leads
        is_self_approval = (
            approver_member_id == requester_member_id
            or (req.user_id is not None and approver_member_id == _get_user_member_id_from_story(story))
        )

        if not is_lead or is_self_approval:
            reason_parts = []
            if not is_lead:
                reason_parts.append(f"approver {approver_member_id} is not in the lead list")
            if is_self_approval:
                reason_parts.append("requester cannot approve their own request")
            reason = "; ".join(reason_parts)

            req.status = "invalid"
            req.approved_by_member_id = approver_member_id
            req.reason = reason
            comment = (
                f"Access request **invalid**: {reason}. "
                "No access has been granted. Please have an authorized lead approve."
            )
            await shortcut_service.post_comment(token=token, story_id=story_id, text=comment)
            await _audit(
                session,
                user_id=req.user_id,
                entity_id=req.id,
                action="access_invalid",
                new_state={"reason": reason, "approver": approver_member_id},
            )
            logger.warning(
                "access_invalid_approval",
                request_id=request_id,
                approver=approver_member_id,
                reason=reason,
            )
            await session.commit()
            return

        # Valid approval — grant access
        expires_at = now + _duration_delta(req.duration_seconds)
        req.status = "active"
        req.approved_by_member_id = approver_member_id
        req.approved_at = now
        req.expires_at = expires_at

        perm_key = req.permission_key
        expires_str = expires_at.strftime("%Y-%m-%d %H:%M UTC")
        comment = (
            f"Access **granted**.\n"
            f"- Permission: `{perm_key}`\n"
            f"- User: user_id={req.user_id}\n"
            f"- Expires: {expires_str}"
        )
        await shortcut_service.post_comment(token=token, story_id=story_id, text=comment)
        await _audit(
            session,
            user_id=req.user_id,
            entity_id=req.id,
            action="access_grant",
            new_state={
                "permission_key": perm_key,
                "approved_by": approver_member_id,
                "expires_at": expires_at.isoformat(),
            },
        )
        logger.info(
            "access_granted",
            request_id=request_id,
            user_id=req.user_id,
            permission_key=perm_key,
            expires_at=expires_at.isoformat(),
        )

    await session.commit()


def _get_user_member_id_from_story(story: dict) -> str | None:
    """Extract the requested_by_id from the story dict (best-effort)."""
    return story.get("requested_by_id")


def _duration_delta(seconds: int):
    """Return a timedelta for the given number of seconds."""
    from datetime import timedelta
    return timedelta(seconds=seconds)


async def poll_once(session_factory: Callable, settings: "Settings") -> None:
    """Single poller pass: process all non-final access requests."""
    token = resolve_shortcut_token(settings)
    if not token:
        return

    async with session_factory() as session:
        result = await session.execute(
            select(AccessRequest.id).where(
                AccessRequest.status.in_(["requested", "active"])
            )
        )
        request_ids = list(result.scalars().all())

    if not request_ids:
        return

    logger.info("access_poller_pass", candidate_count=len(request_ids))

    for request_id in request_ids:
        try:
            async with session_factory() as session:
                await _process_request(request_id, session, settings)
        except Exception as exc:
            logger.error(
                "access_poller_request_error",
                request_id=request_id,
                error=str(exc),
            )


async def access_poller_loop(session_factory: Callable, settings: "Settings") -> None:
    """Periodic access-request poller — started once in the app lifespan.

    Mirrors the reconciler_loop pattern.  Returns immediately when neither
    SHORTCUT_TOKEN_SECRET_ARN nor SHORTCUT_API_TOKEN is configured.
    """
    is_configured = bool(settings.shortcut_token_secret_arn) or bool(
        settings.shortcut_api_token.get_secret_value()
    )
    if not is_configured:
        logger.info("access_poller_disabled")
        return

    logger.info(
        "access_poller_started",
        interval=settings.shortcut_poll_interval_seconds,
    )

    while True:
        try:
            await asyncio.sleep(settings.shortcut_poll_interval_seconds)
            await poll_once(session_factory, settings)
        except asyncio.CancelledError:
            logger.info("access_poller_cancelled")
            raise
        except Exception as exc:
            logger.error("access_poller_loop_error", error=str(exc))
