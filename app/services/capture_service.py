"""Packet capture service — start, read, and delete captures on VPN nodes via SSM + S3."""

from __future__ import annotations

import asyncio
import ipaddress
import shlex
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import boto3
from botocore.exceptions import ClientError
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import PacketCapture, Server
from app.exceptions import ConflictError, InfrastructureError, NotFoundError, ValidationError
from app.logging_config import get_logger
from app.services import audit
from app.services.permissions import has_active_tier2
from app.services.transport.factory import get_transport
from app.schemas.capture import HEADERS_SNAPLEN, FULL_SNAPLEN, CaptureStart

if TYPE_CHECKING:
    from app.db.models import User

logger = get_logger(__name__)

# Maximum lines returned when reading a capture
_MAX_OUTPUT_LINES = 500

# Presigned URL extra time beyond capture duration (seconds)
_PRESIGN_BUFFER_SECONDS = 180

# Extra SSM timeout beyond capture duration (seconds for upload + overhead)
_SSM_TIMEOUT_BUFFER_SECONDS = 90

# Valid interfaces
_VALID_INTERFACES = frozenset(("ens5", "ens6", "any"))


# ---------------------------------------------------------------------------
# BPF filter builder
# ---------------------------------------------------------------------------

def build_bpf_filter(
    *,
    interface: str,
    host_filter: str | None,
    port_filter: int | None,
    protocol_filter: str,
) -> str:
    """Build a safe BPF filter expression from structured fields.

    Never accepts free-form BPF from the user. The filter is assembled from
    validated, typed fields only.

    Returns an empty string when no filters are set.
    """
    if interface not in _VALID_INTERFACES:
        raise ValidationError(f"Invalid interface: {interface!r}")

    parts: list[str] = []

    if protocol_filter and protocol_filter != "all":
        # Protocol is validated upstream to one of tcp/udp/icmp
        parts.append(protocol_filter)

    if host_filter:
        # Validate again at service layer (defense in depth)
        try:
            net = ipaddress.ip_network(host_filter, strict=False)
        except ValueError:
            raise ValidationError(f"Invalid host filter: {host_filter!r}")
        # Use 'host' for single addresses, 'net' for CIDRs
        if net.num_addresses == 1:
            parts.append(f"host {net.network_address}")
        else:
            parts.append(f"net {net}")

    if port_filter is not None:
        if not (1 <= port_filter <= 65535):
            raise ValidationError(f"Invalid port: {port_filter}")
        parts.append(f"port {port_filter}")

    return " and ".join(parts)


# ---------------------------------------------------------------------------
# S3 helpers (using default credential chain / instance role)
# ---------------------------------------------------------------------------

def _s3_client():
    """Return a boto3 S3 client using the default credential chain."""
    settings = get_settings()
    return boto3.client("s3", region_name=settings.aws_region)


def generate_presigned_put_url(bucket: str, key: str, ttl_seconds: int) -> str:
    """Generate a presigned S3 PUT URL for the given key."""
    s3 = _s3_client()
    try:
        return s3.generate_presigned_url(
            "put_object",
            Params={"Bucket": bucket, "Key": key},
            ExpiresIn=ttl_seconds,
        )
    except ClientError as exc:
        raise InfrastructureError(
            service="s3",
            message=f"Failed to generate presigned URL: {exc}",
        ) from exc


def get_object_bytes(bucket: str, key: str) -> bytes:
    """Download an S3 object and return its bytes."""
    s3 = _s3_client()
    try:
        resp = s3.get_object(Bucket=bucket, Key=key)
        return resp["Body"].read()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code in ("NoSuchKey", "404"):
            raise NotFoundError("S3 object", 0) from exc
        raise InfrastructureError(
            service="s3",
            message=f"Failed to download capture: {exc}",
        ) from exc


def delete_s3_object(bucket: str, key: str) -> None:
    """Delete an S3 object (idempotent — missing key is OK)."""
    s3 = _s3_client()
    try:
        s3.delete_object(Bucket=bucket, Key=key)
    except ClientError as exc:
        raise InfrastructureError(
            service="s3",
            message=f"Failed to delete capture object: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# Node script builder
# ---------------------------------------------------------------------------

def build_capture_script(
    *,
    capture_id: int,
    interface: str,
    bpf_filter: str,
    duration_seconds: int,
    snaplen: int,
    max_size_bytes: int,
    presigned_url: str,
) -> str:
    """Build the shell script that runs on the VPN node.

    The script:
    1. Sets a trap to delete the temp file on EXIT (success or failure).
    2. Runs tcpdump with timeout, writing to /dev/shm.
    3. Checks the file size against the limit.
    4. Uploads via curl to the presigned URL.

    All user-controlled values are either validated integers/enums or passed
    through shlex.quote to prevent injection.
    """
    tmpfile = f"/dev/shm/capture_{capture_id}.pcap"
    quoted_url = shlex.quote(presigned_url)
    quoted_iface = shlex.quote(interface)

    # Build tcpdump args safely (all validated)
    tcpdump_parts = [
        "sudo", "tcpdump",
        "-i", quoted_iface,
        "-s", str(snaplen),
        "-w", tmpfile,
    ]
    if bpf_filter:
        # bpf_filter is built from validated typed fields only, never raw user input
        tcpdump_parts.append(shlex.quote(bpf_filter))

    tcpdump_cmd = " ".join(tcpdump_parts)

    script = f"""\
TMPFILE={tmpfile}
trap 'rm -f "$TMPFILE"' EXIT
timeout {duration_seconds} {tcpdump_cmd}; RC=$?
if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ]; then
  echo "tcpdump exited with RC=$RC" >&2
  exit "$RC"
fi
SIZE=$(stat -c%s "$TMPFILE" 2>/dev/null || echo 0)
if [ "$SIZE" -eq 0 ]; then
  echo "No packets captured (empty file)" >&2
  exit 1
fi
if [ "$SIZE" -gt {max_size_bytes} ]; then
  echo "Capture too large: $SIZE bytes (limit {max_size_bytes})" >&2
  exit 1
fi
curl -sf -T "$TMPFILE" {quoted_url}
"""
    return script


# ---------------------------------------------------------------------------
# Service operations
# ---------------------------------------------------------------------------

async def _get_server(session: AsyncSession, server_id: int) -> Server:
    """Load a server by ID, raising NotFoundError if absent or soft-deleted."""
    result = await session.execute(
        select(Server).where(Server.id == server_id, Server.deleted_at.is_(None))
    )
    server = result.scalar_one_or_none()
    if server is None:
        raise NotFoundError("Server", server_id)
    return server


async def start_capture(
    session: AsyncSession,
    *,
    data: CaptureStart,
    user: "User",
    request: Request | None = None,
) -> PacketCapture:
    """Start a packet capture on a VPN node.

    1. Check permissions (capture.headers for headers mode; capture.full Tier 2 for full).
    2. Verify no capture is already running on this server.
    3. Build BPF filter from structured fields.
    4. Generate presigned S3 PUT URL.
    5. Insert PacketCapture row (status=running).
    6. Build node script and run via SSM transport (single server).
    7. Update row to completed/failed.
    8. Audit log.

    Args:
        session: Async DB session.
        data: Validated CaptureStart payload.
        user: Authenticated user.
        request: FastAPI request (for audit context).

    Returns:
        The completed PacketCapture row.
    """
    settings = get_settings()
    if not settings.capture_bucket:
        raise ValidationError("Packet capture feature is disabled (CAPTURE_BUCKET not set)")

    # Check duration limit
    max_dur = settings.capture_max_duration_seconds
    if data.duration_seconds > max_dur:
        raise ValidationError(
            f"duration_seconds exceeds maximum allowed: {data.duration_seconds} > {max_dur}"
        )

    # Permission check
    from app.auth.dependencies import assert_permission
    from app.exceptions import AuthorizationError

    if data.mode == "full":
        # Tier 2 required at capture start
        if not await has_active_tier2(session, user.id, "capture.full"):
            raise AuthorizationError("Active Tier 2 grant for 'capture.full' required")
    else:
        # headers mode — Tier 1 or admin
        await assert_permission(user, "capture.headers", session)

    server = await _get_server(session, data.server_id)

    # Check for existing running capture on this server
    result = await session.execute(
        select(PacketCapture).where(
            PacketCapture.server_id == data.server_id,
            PacketCapture.status == "running",
            PacketCapture.deleted_at.is_(None),
        )
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        raise ConflictError(
            f"Server {data.server_id} already has a running capture (id={existing.id})"
        )

    # Build BPF filter
    bpf_filter = build_bpf_filter(
        interface=data.interface,
        host_filter=data.host_filter,
        port_filter=data.port_filter,
        protocol_filter=data.protocol_filter,
    )

    # Determine snaplen
    snaplen = FULL_SNAPLEN if data.mode == "full" else HEADERS_SNAPLEN

    # Insert capture row (status=running) so we have an ID for the S3 key
    capture = PacketCapture(
        server_id=data.server_id,
        user_id=user.id,
        mode=data.mode,
        interface=data.interface,
        host_filter=data.host_filter,
        port_filter=data.port_filter,
        protocol_filter=data.protocol_filter,
        duration_seconds=data.duration_seconds,
        snaplen=snaplen,
        status="running",
        started_at=datetime.now(timezone.utc),
    )
    session.add(capture)
    await session.flush()

    # S3 key
    bucket = settings.capture_bucket
    s3_key = f"captures/{capture.id}.pcap"
    capture.s3_object_key = s3_key

    # Presigned URL TTL = duration + buffer
    ttl = data.duration_seconds + _PRESIGN_BUFFER_SECONDS
    presigned_url = generate_presigned_put_url(bucket, s3_key, ttl)

    # Build node script
    max_bytes = settings.capture_max_size_mb * 1024 * 1024
    script = build_capture_script(
        capture_id=capture.id,
        interface=data.interface,
        bpf_filter=bpf_filter,
        duration_seconds=data.duration_seconds,
        snaplen=snaplen,
        max_size_bytes=max_bytes,
        presigned_url=presigned_url,
    )

    # SSM timeout: capture duration + buffer
    ssm_timeout = data.duration_seconds + _SSM_TIMEOUT_BUFFER_SECONDS

    # Execute on the specific server (not all servers — capture is per-node)
    try:
        transport = get_transport(server)
        cmd_result = await transport.execute([script], timeout=ssm_timeout)
        # Try to extract size from stdout if reported
        for line in (cmd_result.stdout or "").splitlines():
            if line.strip().isdigit():
                try:
                    capture.size_bytes = int(line.strip())
                except ValueError:
                    pass
        capture.status = "completed"
        capture.completed_at = datetime.now(timezone.utc)
        capture.error = None
        logger.info(
            "packet_capture_completed",
            capture_id=capture.id,
            server_id=data.server_id,
            mode=data.mode,
        )
    except Exception as exc:
        capture.status = "failed"
        capture.error = str(exc)
        capture.completed_at = datetime.now(timezone.utc)
        logger.error(
            "packet_capture_failed",
            capture_id=capture.id,
            server_id=data.server_id,
            error=str(exc),
        )

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="packet_capture",
        entity_id=capture.id,
        action="capture_start",
        new_state={
            "id": capture.id,
            "server_id": capture.server_id,
            "mode": capture.mode,
            "interface": capture.interface,
            "host_filter": capture.host_filter,
            "port_filter": capture.port_filter,
            "protocol_filter": capture.protocol_filter,
            "duration_seconds": capture.duration_seconds,
            "status": capture.status,
        },
        request=request,
    )

    await session.commit()
    await session.refresh(capture)
    return capture


async def read_capture(
    session: AsyncSession,
    capture_id: int,
    *,
    user: "User",
    request: Request | None = None,
) -> dict:
    """Download and parse a completed capture, returning up to _MAX_OUTPUT_LINES lines.

    - Full payload (-A flag) is only shown when user has active Tier 2 capture.full.
    - In headers mode, payload is never shown regardless of Tier 2.
    - Audit logs the view action.

    Returns a dict with keys: capture_id, lines, truncated, mode, payload_shown.
    """
    result = await session.execute(
        select(PacketCapture).where(
            PacketCapture.id == capture_id,
            PacketCapture.deleted_at.is_(None),
        )
    )
    capture = result.scalar_one_or_none()
    if capture is None:
        raise NotFoundError("PacketCapture", capture_id)

    if capture.status != "completed":
        raise ConflictError(
            f"Capture {capture_id} is in status '{capture.status}', not 'completed'"
        )

    settings = get_settings()
    if not settings.capture_bucket:
        raise ValidationError("Packet capture feature is disabled")

    # Permission check at view time
    from app.auth.dependencies import assert_permission
    from app.exceptions import AuthorizationError

    if capture.mode == "full":
        if not await has_active_tier2(session, user.id, "capture.full"):
            raise AuthorizationError(
                "Active Tier 2 grant for 'capture.full' required to view full capture"
            )
    else:
        await assert_permission(user, "capture.headers", session)

    # Determine whether to show payload
    show_payload = capture.mode == "full"
    # (Tier 2 already verified above for full mode)

    # Download from S3
    loop = asyncio.get_running_loop()
    pcap_bytes = await loop.run_in_executor(
        None,
        lambda: get_object_bytes(settings.capture_bucket, capture.s3_object_key),
    )

    # Parse with tcpdump -r - -nn [-A]
    tcpdump_args = ["tcpdump", "-r", "-", "-nn"]
    if show_payload:
        tcpdump_args.append("-A")

    try:
        proc = await asyncio.create_subprocess_exec(
            *tcpdump_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout_bytes, stderr_bytes = await proc.communicate(input=pcap_bytes)
        output_text = stdout_bytes.decode("utf-8", errors="replace")
        # Merge stderr too (tcpdump writes summary to stderr)
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        all_lines = output_text.splitlines() + (
            stderr_text.splitlines() if stderr_text.strip() else []
        )
    except FileNotFoundError:
        raise InfrastructureError(
            service="tcpdump",
            message="tcpdump not found on manager host",
        )

    truncated = len(all_lines) > _MAX_OUTPUT_LINES
    lines = all_lines[:_MAX_OUTPUT_LINES]

    # Audit
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="packet_capture",
        entity_id=capture.id,
        action="capture_view",
        new_state={"capture_id": capture_id, "payload_shown": show_payload},
        request=request,
    )
    await session.commit()

    return {
        "capture_id": capture_id,
        "lines": lines,
        "truncated": truncated,
        "mode": capture.mode,
        "payload_shown": show_payload,
    }


async def delete_capture(
    session: AsyncSession,
    capture_id: int,
    *,
    user: "User",
    request: Request | None = None,
) -> None:
    """Delete a capture: remove S3 object and mark row as deleted.

    Admin can delete any capture. Operators must have capture.headers permission.
    """
    result = await session.execute(
        select(PacketCapture).where(
            PacketCapture.id == capture_id,
            PacketCapture.deleted_at.is_(None),
        )
    )
    capture = result.scalar_one_or_none()
    if capture is None:
        raise NotFoundError("PacketCapture", capture_id)

    settings = get_settings()

    # Delete from S3 if completed and has a key
    if capture.s3_object_key and capture.status == "completed":
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(
                None,
                lambda: delete_s3_object(settings.capture_bucket, capture.s3_object_key),
            )
        except InfrastructureError as exc:
            logger.warning(
                "capture_s3_delete_failed",
                capture_id=capture_id,
                error=str(exc),
            )

    capture.deleted_at = datetime.now(timezone.utc)
    capture.deleted_by = user.id
    capture.status = "deleted"

    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="packet_capture",
        entity_id=capture.id,
        action="capture_delete",
        previous_state={"capture_id": capture_id, "s3_key": capture.s3_object_key},
        request=request,
    )
    await session.commit()


async def list_captures(
    session: AsyncSession,
    *,
    server_id: int | None = None,
    limit: int = 50,
) -> list[PacketCapture]:
    """List non-deleted captures, optionally filtered by server."""
    stmt = (
        select(PacketCapture)
        .where(PacketCapture.deleted_at.is_(None))
        .order_by(PacketCapture.id.desc())
        .limit(limit)
    )
    if server_id is not None:
        stmt = stmt.where(PacketCapture.server_id == server_id)
    result = await session.execute(stmt)
    return list(result.scalars().all())
