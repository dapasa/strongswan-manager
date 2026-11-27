"""Permission catalog and DB helpers for Tier 1 and Tier 2 access control.

Tier 1 — per-action grants stored in ``user_permissions``.
Tier 2 — time-limited elevated access in ``access_requests``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import (
    TIER1_PERMISSION_KEYS,
    TIER2_PERMISSION_KEYS,
    AccessRequest,
    UserPermission,
)
from app.logging_config import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Tier 1 catalog
# ---------------------------------------------------------------------------

TIER1_CATALOG: dict[str, str] = {
    "tunnels.write": "Create, update, delete, and retry tunnels",
    "tunnels.connect": "Initiate and terminate tunnels",
    "tunnels.psk": "Rotate the PSK for tunnels",
    "routes.write": "Create, delete, and retry VPC routes",
    "iptables.filter": "Create/update/retry/delete ACCEPT, DROP, REJECT rules",
    "iptables.snat": "Create/update/retry/delete SNAT rules",
    "capture.headers": "Packet capture header visibility (future feature)",
}

# ---------------------------------------------------------------------------
# Tier 2 catalog
# ---------------------------------------------------------------------------

TIER2_CATALOG: dict[str, dict[str, Any]] = {
    "capture.full": {
        "description": "Full packet capture; patient data may be present in the payload",
        "max_duration_hours": 4,
    },
}


# ---------------------------------------------------------------------------
# Tier 1 — DB helpers
# ---------------------------------------------------------------------------

async def get_user_permission_keys(session: AsyncSession, user_id: int) -> list[str]:
    """Return the list of Tier 1 permission keys granted to a user."""
    result = await session.execute(
        select(UserPermission.permission_key).where(UserPermission.user_id == user_id)
    )
    return list(result.scalars().all())


async def set_user_permissions(
    session: AsyncSession,
    user_id: int,
    permission_keys: list[str],
) -> list[str]:
    """Replace the full set of Tier 1 permissions for a user.

    Unknown keys (not in TIER1_PERMISSION_KEYS) are silently ignored.

    Args:
        session: Active database session (caller commits).
        user_id: Primary key of the user.
        permission_keys: Desired full list of permission keys.

    Returns:
        The effective list of permission keys after the update.
    """
    valid = set(TIER1_PERMISSION_KEYS)
    new_keys = {k for k in permission_keys if k in valid}

    # Load existing
    result = await session.execute(
        select(UserPermission).where(UserPermission.user_id == user_id)
    )
    existing = {p.permission_key: p for p in result.scalars().all()}

    # Remove permissions not in the new set
    for key, perm_obj in existing.items():
        if key not in new_keys:
            await session.delete(perm_obj)

    # Add permissions not yet in DB
    for key in new_keys:
        if key not in existing:
            session.add(UserPermission(user_id=user_id, permission_key=key))

    await session.flush()
    return list(new_keys)


# ---------------------------------------------------------------------------
# Tier 2 — DB helpers
# ---------------------------------------------------------------------------

async def get_active_tier2_permission_keys(
    session: AsyncSession,
    user_id: int,
) -> list[str]:
    """Return Tier 2 permission keys that are currently active (not expired)."""
    now = datetime.now(timezone.utc)
    result = await session.execute(
        select(AccessRequest.permission_key).where(
            AccessRequest.user_id == user_id,
            AccessRequest.status == "active",
            AccessRequest.expires_at > now,
        )
    )
    return list(result.scalars().all())


async def has_active_tier2(
    session: AsyncSession,
    user_id: int,
    permission_key: str,
) -> bool:
    """Check if a user has an active, non-expired Tier 2 grant for the given key."""
    now = datetime.now(timezone.utc)
    result = await session.execute(
        select(AccessRequest.id).where(
            AccessRequest.user_id == user_id,
            AccessRequest.permission_key == permission_key,
            AccessRequest.status == "active",
            AccessRequest.expires_at > now,
        )
    )
    return result.scalar_one_or_none() is not None
