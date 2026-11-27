"""Packet capture service — start, read, and delete captures on VPN nodes via SSM + S3."""

from __future__ import annotations

import asyncio
import ipaddress
import shlex
from datetime import datetime, timedelta, timezone
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

# curl upload timeout — must fit within _SSM_TIMEOUT_BUFFER_SECONDS
_CURL_TIMEOUT_SECONDS = 60

# Valid interfaces
_VALID_INTERFACES = frozenset(("ens5", "ens6", "any"))

# Strong references to in-flight capture tasks: the event loop only keeps weak ones,
# so an unreferenced task can be garbage-collected before it finishes.
_background_tasks: set[asyncio.Task] = set()


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
    """Hard-delete all versions and delete markers for *key* in a versioned bucket.

    A simple ``delete_object`` on a versioned bucket only inserts a delete
    marker — the data is not removed.  This function lists all versions and
    delete markers with the exact ``key`` prefix and issues a per-version
    delete so the object is fully purged.

    Idempotent: a key with no versions produces no error.
    """
    s3 = _s3_client()
    try:
        paginator = s3.get_paginator("list_object_versions")
        pages = paginator.paginate(Bucket=bucket, Prefix=key)
        objects_to_delete: list[dict] = []
        for page in pages:
            for ver in page.get("Versions", []):
                if ver["Key"] == key:
                    objects_to_delete.append({"Key": ver["Key"], "VersionId": ver["VersionId"]})
            for dm in page.get("DeleteMarkers", []):
                if dm["Key"] == key:
                    objects_to_delete.append({"Key": dm["Key"], "VersionId": dm["VersionId"]})

        if not objects_to_delete:
            return  # Key never existed or already fully deleted

        # delete_objects supports up to 1000 items per call
        for i in range(0, len(objects_to_delete), 1000):
            batch = objects_to_delete[i : i + 1000]
            resp = s3.delete_objects(
                Bucket=bucket,
                Delete={"Objects": batch, "Quiet": True},
            )
            errors = resp.get("Errors", [])
            if errors:
                detail = "; ".join(
                    f"{e['Key']}@{e.get('VersionId', '')} — {e['Message']}"
                    for e in errors
                )
                raise InfrastructureError(
                    service="s3",
                    message=f"Failed to delete {len(errors)} object version(s): {detail}",
                )
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
    curl_timeout_seconds: int = _CURL_TIMEOUT_SECONDS,
) -> str:
    """Build the shell script that runs on the VPN node.

    Design:
    1. Sets a trap to delete the temp file on EXIT (success or failure).
    2. Runs tcpdump in a subshell with ``ulimit -f`` to enforce a hard file-size
       cap in 512-byte blocks.  SIGXFSZ (RC=153) means size was exceeded — the
       pcap is still a valid (truncated) capture and is uploaded anyway.
    3. Echos ``CAPTURE_SIZE=N`` and ``TRUNCATED_BY_SIZE=0/1`` for the manager to
       parse from SSM stdout.
    4. Uploads via ``curl`` with ``--max-time`` to bound the upload duration.

    SSM Run Command executes as root on the node, so ``sudo`` is not used —
    dropping it ensures ``ulimit -f`` is inherited by the tcpdump child.

    All user-controlled values are validated typed fields; the presigned URL
    and interface name are always passed through ``shlex.quote``.
    """
    tmpfile = f"/dev/shm/capture_{capture_id}.pcap"
    quoted_url = shlex.quote(presigned_url)
    quoted_iface = shlex.quote(interface)

    # ulimit -f unit is 512-byte blocks
    ulimit_blocks = max_size_bytes // 512

    # Build tcpdump command — no sudo (SSM runs as root; ulimit must be inherited)
    tcpdump_parts = [
        "tcpdump",
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
( ulimit -f {ulimit_blocks}; timeout {duration_seconds} {tcpdump_cmd} ); RC=$?
# RC=0: stopped cleanly, RC=124: timed out by timeout(1), RC=153: SIGXFSZ (size limit)
# All three produce a valid (possibly truncated) pcap - upload it
# Any other RC is a real tcpdump error
if [ "$RC" -ne 0 ] && [ "$RC" -ne 124 ] && [ "$RC" -ne 153 ]; then
  echo "tcpdump exited with RC=$RC" >&2
  exit "$RC"
fi
SIZE=$(stat -c%s "$TMPFILE" 2>/dev/null || echo 0)
if [ "$SIZE" -eq 0 ]; then
  echo "No packets captured (empty file)" >&2
  exit 1
fi
TRUNCATED=0
if [ "$RC" -eq 153 ]; then TRUNCATED=1; fi
echo "CAPTURE_SIZE=$SIZE"
echo "TRUNCATED_BY_SIZE=$TRUNCATED"
curl -sf --max-time {curl_timeout_seconds} -T "$TMPFILE" {quoted_url}
"""
    return script


# ---------------------------------------------------------------------------
# Background task
# ---------------------------------------------------------------------------

async def _run_capture_background(
    *,
    capture_id: int,
    server_id: int,
    script: str,
    ssm_timeout: int,
    user_id: int,
) -> None:
    """Background asyncio task: execute SSM capture and persist result to DB.

    Uses its own DB sessions so the HTTP request session is not held open.
    Fires the ``capture_start`` audit log on completion (success or failure).
    """
    from app.db.session import async_session_factory

    logger.info("capture_bg_start", capture_id=capture_id, server_id=server_id)

    status = "failed"
    error_msg: str | None = None
    size_bytes: int | None = None
    truncated_by_size = False

    try:
        # Fetch the server in its own short-lived session
        async with async_session_factory() as session:
            result = await session.execute(
                select(Server).where(Server.id == server_id)
            )
            server = result.scalar_one_or_none()

        if server is None:
            raise InfrastructureError(
                service="capture",
                message=f"Server {server_id} not found in background task",
            )

        transport = get_transport(server)
        cmd_result = await transport.execute([script], timeout=ssm_timeout)

        # Parse stdout for CAPTURE_SIZE and TRUNCATED_BY_SIZE
        for line in (cmd_result.stdout or "").splitlines():
            line = line.strip()
            if line.startswith("CAPTURE_SIZE="):
                try:
                    size_bytes = int(line.split("=", 1)[1])
                except (ValueError, IndexError):
                    pass
            elif line.startswith("TRUNCATED_BY_SIZE="):
                truncated_by_size = line.split("=", 1)[1].strip() == "1"

        status = "completed"
        logger.info(
            "capture_bg_complete",
            capture_id=capture_id,
            size_bytes=size_bytes,
            truncated_by_size=truncated_by_size,
        )

    except Exception as exc:
        error_msg = str(exc)[:500]
        logger.error("capture_bg_failed", capture_id=capture_id, error=error_msg)

    # Persist result in a fresh session
    try:
        async with async_session_factory() as session:
            cap_result = await session.execute(
                select(PacketCapture).where(PacketCapture.id == capture_id)
            )
            capture = cap_result.scalar_one_or_none()
            if capture is None:
                logger.error("capture_bg_row_gone", capture_id=capture_id)
                return

            capture.status = status
            capture.completed_at = datetime.now(timezone.utc)
            capture.size_bytes = size_bytes
            capture.truncated_by_size = truncated_by_size
            capture.error = error_msg

            await audit.log_action(
                session,
                user_id=user_id,
                entity_type="packet_capture",
                entity_id=capture_id,
                action="capture_start",
                new_state={
                    "id": capture_id,
                    "status": status,
                    "size_bytes": size_bytes,
                    "truncated_by_size": truncated_by_size,
                    "error": error_msg,
                },
            )
            await session.commit()

    except Exception as save_exc:
        logger.error(
            "capture_bg_save_failed",
            capture_id=capture_id,
            error=str(save_exc),
        )


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
    """Validate, commit a 'running' row, then launch the SSM capture as a background task.

    Returns immediately with the ``running`` capture so the caller can respond
    with HTTP 202.  The background task updates the row to ``completed`` or
    ``failed`` and fires the audit log.

    Per-node concurrency is enforced by the committed ``running`` row: any
    concurrent request sees it before launching another capture.  Rows that
    have been ``running`` longer than their max expected duration are treated as
    stale (manager restart / lost SSM task) and are marked ``failed`` before
    allowing a new capture.

    Args:
        session: Async DB session (used for validation and initial commit only).
        data: Validated CaptureStart payload.
        user: Authenticated user.
        request: FastAPI request (unused here — audit fires in the background).

    Returns:
        The newly inserted PacketCapture row (status='running').
    """
    settings = get_settings()
    if not settings.capture_bucket:
        raise ValidationError("Packet capture feature is disabled (CAPTURE_BUCKET not set)")

    max_dur = settings.capture_max_duration_seconds
    if data.duration_seconds > max_dur:
        raise ValidationError(
            f"duration_seconds {data.duration_seconds} exceeds maximum {max_dur}"
        )

    # Permission check
    from app.auth.dependencies import assert_permission
    from app.exceptions import AuthorizationError

    if data.mode == "full":
        if not await has_active_tier2(session, user.id, "capture.full"):
            raise AuthorizationError("Active Tier 2 grant for 'capture.full' required")
    else:
        await assert_permission(user, "capture.headers", session)

    server = await _get_server(session, data.server_id)

    now = datetime.now(timezone.utc)

    # Check for running capture; mark stale ones failed so they don't block the node
    result = await session.execute(
        select(PacketCapture).where(
            PacketCapture.server_id == data.server_id,
            PacketCapture.status == "running",
            PacketCapture.deleted_at.is_(None),
        )
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        stale_after = timedelta(
            seconds=existing.duration_seconds + _SSM_TIMEOUT_BUFFER_SECONDS + 60
        )
        if existing.started_at and (now - existing.started_at) > stale_after:
            logger.warning(
                "capture_stale_recovered",
                capture_id=existing.id,
                server_id=data.server_id,
                age_seconds=(now - existing.started_at).total_seconds(),
            )
            existing.status = "failed"
            existing.error = "Capture timed out (stale — manager may have restarted)"
            existing.completed_at = now
            await session.flush()
        else:
            raise ConflictError(
                f"Server {data.server_id} already has a running capture (id={existing.id})"
            )

    # Build BPF filter from structured fields
    bpf_filter = build_bpf_filter(
        interface=data.interface,
        host_filter=data.host_filter,
        port_filter=data.port_filter,
        protocol_filter=data.protocol_filter,
    )

    snaplen = FULL_SNAPLEN if data.mode == "full" else HEADERS_SNAPLEN

    # Insert running row and flush to obtain the capture ID
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
        started_at=now,
    )
    session.add(capture)
    await session.flush()

    s3_key = f"captures/{capture.id}.pcap"
    capture.s3_object_key = s3_key

    # Generate presigned URL before commit — if this fails, the row is not committed
    bucket = settings.capture_bucket
    ttl = data.duration_seconds + _PRESIGN_BUFFER_SECONDS
    presigned_url = generate_presigned_put_url(bucket, s3_key, ttl)

    # Build the node script
    max_bytes = settings.capture_max_size_mb * 1024 * 1024
    ssm_timeout = data.duration_seconds + _SSM_TIMEOUT_BUFFER_SECONDS
    script = build_capture_script(
        capture_id=capture.id,
        interface=data.interface,
        bpf_filter=bpf_filter,
        duration_seconds=data.duration_seconds,
        snaplen=snaplen,
        max_size_bytes=max_bytes,
        presigned_url=presigned_url,
    )

    # Commit so concurrent requests see the running row immediately
    await session.commit()
    await session.refresh(capture)

    # Launch background task (the HTTP response is returned before it finishes)
    task = asyncio.create_task(
        _run_capture_background(
            capture_id=capture.id,
            server_id=data.server_id,
            script=script,
            ssm_timeout=ssm_timeout,
            user_id=user.id,
        )
    )
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)

    logger.info(
        "capture_accepted",
        capture_id=capture.id,
        server_id=data.server_id,
        mode=data.mode,
        duration_seconds=data.duration_seconds,
    )
    return capture


async def get_capture(session: AsyncSession, capture_id: int) -> PacketCapture:
    """Get a single non-deleted capture by ID (used for status polling)."""
    result = await session.execute(
        select(PacketCapture).where(
            PacketCapture.id == capture_id,
            PacketCapture.deleted_at.is_(None),
        )
    )
    capture = result.scalar_one_or_none()
    if capture is None:
        raise NotFoundError("PacketCapture", capture_id)
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

    from app.auth.dependencies import assert_permission
    from app.exceptions import AuthorizationError

    if capture.mode == "full":
        if not await has_active_tier2(session, user.id, "capture.full"):
            raise AuthorizationError(
                "Active Tier 2 grant for 'capture.full' required to view full capture"
            )
    else:
        await assert_permission(user, "capture.headers", session)

    # Payload shown only in full mode (Tier 2 already verified above)
    show_payload = capture.mode == "full"

    # Download from S3 in executor to avoid blocking the event loop
    loop = asyncio.get_running_loop()
    pcap_bytes = await loop.run_in_executor(
        None,
        lambda: get_object_bytes(settings.capture_bucket, capture.s3_object_key),
    )

    # Parse with tcpdump -r - -nn [-A] on the manager host
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
    """Delete a capture: remove all S3 versions and mark row deleted."""
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
