"""Drift detection service — compares on-disk VPN configs to DB-rendered expectations.

PSKs and file contents are NEVER logged or returned.
Comparison is by sha256 hash only; hashes may appear in the response.
"""

from __future__ import annotations

import hashlib
import shlex
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Tunnel
from app.logging_config import get_logger
from app.services import kms
from app.services.ipsec_config import render_connection_conf, render_secrets_file, render_swanctl_conf
from app.services.server_service import _remote_conf_path, _remote_stroke_secrets_path, get_server
from app.services.transport.factory import get_transport

logger = get_logger(__name__)


def _sha256(content: str) -> str:
    """Return lowercase hex sha256 of *content* encoded as UTF-8."""
    return hashlib.sha256(content.encode()).hexdigest()


def _parse_sha256sum_output(stdout: str) -> dict[str, str]:
    """Parse ``sha256sum`` stdout into ``{absolute_path: hex_hash}``.

    ``sha256sum`` writes one line per file: ``<hash>  <path>`` (two spaces).
    Missing files produce no output line.
    """
    result: dict[str, str] = {}
    for line in stdout.strip().splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            hash_val, path = parts
            result[path.strip()] = hash_val
    return result


async def detect_server_drift(
    session: AsyncSession,
    server_id: int,
    *,
    tunnel_id: int | None = None,
) -> dict:
    """Detect config drift between DB state and on-disk files for one server.

    For each active tunnel (optionally filtered by *tunnel_id*):

    * Renders expected file content from the DB, decrypting the PSK via KMS.
    * Computes sha256 of each expected file.
    * Runs ``sha256sum`` on the actual files via the server's own transport.
    * Compares hashes → ``in_sync``, ``drifted``, or ``missing_on_node``.

    Also lists files in the manager-owned directories that do not belong to any
    known tunnel (orphans).  Only the basenames are listed — no file contents are
    read or returned.

    PSKs and file contents are never logged or returned.

    Args:
        session: Active database session.
        server_id: Target server primary key.
        tunnel_id: When set, restricts the check to that one tunnel.

    Returns:
        dict matching ``ServerDriftReport`` schema.

    Raises:
        NotFoundError: If the server does not exist.
        TransportError: If the transport fails during hash retrieval.
    """
    server = await get_server(session, server_id)
    settings = get_settings()
    transport = get_transport(server)
    checked_at = datetime.now(timezone.utc)

    stmt = select(Tunnel).where(Tunnel.deleted_at.is_(None))
    if tunnel_id is not None:
        stmt = stmt.where(Tunnel.id == tunnel_id)
    db_result = await session.execute(stmt)
    tunnels = list(db_result.scalars().all())

    tunnel_results = []

    for tunnel in tunnels:
        if not tunnel.psk_encrypted:
            logger.warning("drift_psk_missing", server_id=server_id, tunnel=tunnel.name)
            continue

        try:
            psk = await kms.decrypt_psk(tunnel.psk_encrypted)
        except Exception as exc:
            logger.error("drift_kms_error", server_id=server_id, tunnel=tunnel.name, error=str(exc))
            continue

        # Build expected content and hashes (PSK never stored or logged)
        expected_hashes: dict[str, str] = {}
        if server.ipsec_engine == "swanctl":
            conf_path = _remote_conf_path(tunnel.name, "swanctl")
            expected_hashes[conf_path] = _sha256(render_swanctl_conf(tunnel, psk))
        else:
            conf_path = _remote_conf_path(tunnel.name, "stroke")
            secrets_path = _remote_stroke_secrets_path(tunnel.name)
            expected_hashes[conf_path] = _sha256(render_connection_conf(tunnel))
            expected_hashes[secrets_path] = _sha256(render_secrets_file(tunnel, psk))

        # Retrieve actual hashes from node.
        # "; true" ensures the shell command exits 0 even if some files are missing,
        # so the transport does not raise on a missing file — the missing path simply
        # has no entry in the parsed output.
        all_paths = " ".join(shlex.quote(p) for p in expected_hashes)
        cmd_result = await transport.execute([f"sha256sum {all_paths} 2>/dev/null; true"])
        actual_hashes = _parse_sha256sum_output(cmd_result.stdout)

        # Determine per-tunnel status
        all_present = all(p in actual_hashes for p in expected_hashes)
        all_match = all_present and all(
            actual_hashes[p] == h for p, h in expected_hashes.items()
        )

        if not all_present:
            status = "missing_on_node"
        elif all_match:
            status = "in_sync"
        else:
            status = "drifted"

        logger.info(
            "drift_tunnel_checked",
            server_id=server_id,
            tunnel=tunnel.name,
            status=status,
        )

        tunnel_results.append({
            "tunnel_id": tunnel.id,
            "tunnel_name": tunnel.name,
            "status": status,
            "expected_hashes": expected_hashes,
            "actual_hashes": actual_hashes,
        })

    # Detect orphan files in manager-owned directories.
    # Lists filenames only — no content is read.
    orphan_files: list[str] = []
    known_names: set[str] = {t.name for t in tunnels}

    if server.ipsec_engine == "swanctl":
        dirs_and_exts = [(settings.vpn_swanctl_conf_dir, ".conf")]
    else:
        dirs_and_exts = [
            (settings.vpn_conf_dir, ".conf"),
            (settings.vpn_stroke_secrets_dir, ".secrets"),
        ]

    for dir_path, ext in dirs_and_exts:
        try:
            ls_result = await transport.execute([
                f"ls -1 {shlex.quote(dir_path)} 2>/dev/null; true"
            ])
            for fname in ls_result.stdout.strip().splitlines():
                fname = fname.strip()
                if fname.endswith(ext):
                    stem = fname[: -len(ext)]
                    if stem not in known_names:
                        orphan_files.append(f"{dir_path}/{fname}")
        except Exception as exc:
            logger.warning("drift_ls_failed", server_id=server_id, dir=dir_path, error=str(exc))

    return {
        "server_id": server.id,
        "server_name": server.name,
        "tunnels": tunnel_results,
        "orphan_files": orphan_files,
        "checked_at": checked_at,
    }
