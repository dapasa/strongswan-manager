"""Health check router — unauthenticated liveness and readiness probes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.exceptions import InfrastructureError
from app.logging_config import get_logger
from app.schemas.common import HealthResponse
from app.services import s3
from app.services.server_service import execute_on_all_servers

logger = get_logger(__name__)

router = APIRouter(tags=["health"])


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Liveness probe",
)
async def health_check() -> HealthResponse:
    """Return basic health status. No authentication required."""
    return HealthResponse(status="ok")


@router.get(
    "/health/ready",
    response_model=HealthResponse,
    summary="Readiness probe",
)
async def readiness_check(
    db: AsyncSession = Depends(get_db),
) -> HealthResponse:
    """Check connectivity to database, S3, and SSH servers. No authentication required.

    SSH check semantics:
    - No servers registered  → ``warn``   (degraded, not an error)
    - All servers reachable  → ``ok``
    - Some servers reachable → ``degraded``
    - All servers unreachable → ``failed``
    """
    checks: dict[str, str] = {}

    # Database check
    try:
        await db.execute(text("SELECT 1"))
        checks["db"] = "ok"
    except Exception:
        logger.warning("readiness_db_check_failed")
        checks["db"] = "failed"

    # S3 check
    try:
        s3_ok = await s3.check_connectivity()
        checks["s3"] = "ok" if s3_ok else "failed"
    except Exception:
        logger.warning("readiness_s3_check_failed")
        checks["s3"] = "failed"

    # SSH fan-out check — replaces SSM connectivity check
    try:
        fan_out = await execute_on_all_servers(db, ["echo ok"])
        if fan_out.is_success:
            checks["ssh"] = "ok"
        elif fan_out.is_partial:
            logger.warning(
                "readiness_ssh_check_degraded",
                succeeded=fan_out.succeeded,
                failed=fan_out.failed,
                total=fan_out.total,
            )
            checks["ssh"] = "degraded"
        else:
            # All failed
            logger.warning(
                "readiness_ssh_check_failed",
                failed=fan_out.failed,
                total=fan_out.total,
            )
            checks["ssh"] = "failed"
    except InfrastructureError:
        # No active servers registered — warn but don't block readiness
        logger.warning("readiness_ssh_no_servers")
        checks["ssh"] = "warn"
    except Exception:
        logger.warning("readiness_ssh_check_error")
        checks["ssh"] = "failed"

    all_ok = all(v == "ok" for v in checks.values())
    return HealthResponse(
        status="ok" if all_ok else "not_ready",
        checks=checks,
    )
