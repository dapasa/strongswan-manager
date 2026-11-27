"""Packet capture router — start, list, read output, and delete captures."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import require_operator
from app.db.models import User
from app.db.session import get_db
from app.schemas.capture import CaptureOut, CaptureOutput, CaptureStart
from app.services import capture_service

router = APIRouter(prefix="/api/v1/captures", tags=["captures"])


@router.post("", response_model=CaptureOut, status_code=202)
async def start_capture(
    body: CaptureStart,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> CaptureOut:
    """Start a new packet capture on a VPN node.

    Requires at minimum the ``capture.headers`` Tier 1 permission.
    Full-payload mode additionally requires an active Tier 2 ``capture.full`` grant.
    """
    capture = await capture_service.start_capture(
        db, data=body, user=current_user, request=request
    )
    return capture


@router.get("/{capture_id}", response_model=CaptureOut)
async def get_capture(
    capture_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> CaptureOut:
    """Get a single capture by ID (used for status polling after a 202 response)."""
    return await capture_service.get_capture(db, capture_id)


@router.get("", response_model=list[CaptureOut])
async def list_captures(
    server_id: int | None = Query(default=None),
    limit: int = Query(default=50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> list[CaptureOut]:
    """List packet captures, optionally filtered by server."""
    return await capture_service.list_captures(db, server_id=server_id, limit=limit)


@router.get("/{capture_id}/output", response_model=CaptureOutput)
async def read_capture_output(
    capture_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> CaptureOutput:
    """Read and parse a completed capture.

    Downloads the pcap from S3 and passes it through ``tcpdump -r``.
    Payload is only shown if the user has an active Tier 2 ``capture.full`` grant
    and the capture was taken in full mode.
    No binary download is provided.
    """
    result = await capture_service.read_capture(
        db, capture_id, user=current_user, request=request
    )
    return result


@router.delete("/{capture_id}", status_code=204)
async def delete_capture(
    capture_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> None:
    """Delete a capture: remove the S3 object and mark the record deleted."""
    await capture_service.delete_capture(
        db, capture_id, user=current_user, request=request
    )
