"""PostgreSQL advisory lock utilities for serializing infrastructure operations."""

from __future__ import annotations

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.exceptions import LockConflictError
from app.logging_config import get_logger

logger = get_logger(__name__)

# Well-known lock key constants
LOCK_IPSEC_CONFIG: int = 1
LOCK_TERRAGRUNT: int = 2
LOCK_IPTABLES_PRIMARY: int = 3
LOCK_IPTABLES_SECONDARY: int = 4


async def acquire_advisory_lock(session: AsyncSession, lock_key: int) -> bool:
    """Attempt to acquire a PostgreSQL transaction-scoped advisory lock (non-blocking).

    Uses ``pg_try_advisory_xact_lock`` which auto-releases when the
    transaction commits or rolls back.

    Args:
        session: Active async database session.
        lock_key: Integer lock identifier.

    Returns:
        True if the lock was acquired, False if already held by another session.
    """
    result = await session.execute(
        text("SELECT pg_try_advisory_xact_lock(:lock_key)"),
        {"lock_key": lock_key},
    )
    acquired = result.scalar_one()
    logger.info(
        "advisory_lock_attempt",
        lock_key=lock_key,
        acquired=acquired,
    )
    return bool(acquired)


async def require_lock(session: AsyncSession, lock_key: int) -> None:
    """Acquire an advisory lock or raise ``LockConflictError``.

    Convenience wrapper around :func:`acquire_advisory_lock` for callers
    that must abort when the lock is unavailable.

    Args:
        session: Active async database session.
        lock_key: Integer lock identifier.

    Raises:
        LockConflictError: If the lock is already held.
    """
    acquired = await acquire_advisory_lock(session, lock_key)
    if not acquired:
        logger.warning("advisory_lock_denied", lock_key=lock_key)
        raise LockConflictError(lock_id=lock_key)
