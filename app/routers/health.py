"""Health check router — unauthenticated liveness and readiness probes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db
from app.logging_config import get_logger
from app.schemas.common import HealthResponse
from app.services import s3, ssm

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
    """Check connectivity to database, S3, and SSM. No authentication required."""
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

    # SSM check
    try:
        ssm_ok = await ssm.check_connectivity()
        checks["ssm"] = "ok" if ssm_ok else "failed"
    except Exception:
        logger.warning("readiness_ssm_check_failed")
        checks["ssm"] = "failed"

    all_ok = all(v == "ok" for v in checks.values())
    return HealthResponse(
        status="ok" if all_ok else "not_ready",
        checks=checks,
    )
