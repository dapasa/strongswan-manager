"""IPSec configuration service — manages per-connection .conf and .secrets files in S3.

Each tunnel maps to two S3 objects:
    connections/{name}.conf     — StrongSwan connection configuration
    secrets/{name}.secrets      — PSK secret for the connection

The sync_config function uploads both files and triggers an ipsec reload on
all VPN servers via SSH fan-out. The remove_config function deletes both files
and reloads.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Tunnel
from app.logging_config import get_logger
from app.services import s3
from app.services.server_service import (
    sftp_delete_on_all_servers,
    sftp_push_on_all_servers,
    sftp_rename_on_all_servers,
)
from app.utils.fan_out import FanOutResult

logger = get_logger(__name__)


def render_connection_conf(tunnel: Tunnel) -> str:
    """Render a StrongSwan connection config file from a Tunnel model.

    Matches the format used in the existing infrastructure:
    ``connections/{name}.conf``

    Args:
        tunnel: The Tunnel model instance.

    Returns:
        The rendered .conf file content.
    """
    local_cidrs = ",".join(str(c) for c in tunnel.local_cidrs)
    remote_cidrs = ",".join(str(c) for c in tunnel.remote_cidrs)

    lines = [
        f"conn {tunnel.name}",
        "    left=%any",
        f"    leftid={str(tunnel.local_cidrs[0]).split('/')[0] if tunnel.local_cidrs else '%any'}",
        f"    leftsubnet={local_cidrs}",
        "    leftauth=psk",
        "    leftsendcert=never",
        f"    right={tunnel.peer_ip}",
        "    rightid=%any",
        f"    rightsubnet={remote_cidrs}",
        "    rightauth=psk",
    ]

    # IKE and ESP proposals
    if tunnel.ike_proposals:
        lines.append(f"    ike={tunnel.ike_proposals}")
    if tunnel.esp_proposals:
        lines.append(f"    esp={tunnel.esp_proposals}")

    lines.extend([
        "    authby=psk",
        "    type=tunnel",
        "    auto=add",
        "    forceencaps=yes",
        "    fragmentation=yes",
        f"    dpdaction={tunnel.dpd_action}",
        f"    dpddelay={tunnel.dpd_delay}s",
        f"    dpdtimeout={tunnel.dpd_timeout}s",
        "    compress=no",
        f"    keyexchange=ikev{tunnel.ike_version}",
        "    ikelifetime=86400s",
        "    keylife=3600s",
        "    rekeymargin=3m",
        "    keyingtries=%forever",
        "    mobike=no",
    ])

    return "\n".join(lines) + "\n"


def render_secrets_file(tunnel: Tunnel, psk: str) -> str:
    """Render a StrongSwan secrets file for a tunnel.

    Format: ``<right_ip> <left_ip> : PSK "<psk>"``

    Args:
        tunnel: The Tunnel model instance.
        psk: The pre-shared key value.

    Returns:
        The rendered .secrets file content.
    """
    left_ip = str(tunnel.local_cidrs[0]).split("/")[0] if tunnel.local_cidrs else "%any"
    return f'{tunnel.peer_ip} {left_ip} : PSK "{psk}"\n'


def _conf_key(name: str) -> str:
    """S3 key for a connection config file."""
    return f"connections/{name}.conf"


def _secrets_key(name: str) -> str:
    """S3 key for a connection secrets file."""
    return f"secrets/{name}.secrets"


async def sync_tunnel_config(tunnel: Tunnel, psk: str, session: AsyncSession) -> FanOutResult:
    """Upload connection config and secrets to S3, then reload ipsec on all servers.

    Called after tunnel create or update. The caller MUST have acquired
    the LOCK_IPSEC_CONFIG advisory lock.

    S3 upload failure raises InfrastructureError (fatal). SSH fan-out failures
    are captured in the returned FanOutResult (non-fatal — caller decides).

    Args:
        tunnel: The Tunnel model instance with current field values.
        psk: The pre-shared key for this tunnel.
        session: Active database session for server discovery.

    Returns:
        FanOutResult with per-server SSH execution outcomes.

    Raises:
        InfrastructureError: If S3 upload fails or no active servers are registered.
    """
    logger.info("ipsec_sync_start", tunnel=tunnel.name)

    conf_content = render_connection_conf(tunnel)
    secrets_content = render_secrets_file(tunnel, psk)

    await s3.upload_file(_conf_key(tunnel.name), conf_content)
    await s3.upload_file(_secrets_key(tunnel.name), secrets_content)

    result = await sftp_push_on_all_servers(session, tunnel.name, conf_content, secrets_content)

    logger.info("ipsec_sync_complete", tunnel=tunnel.name)
    return result


async def remove_tunnel_config(name: str, session: AsyncSession) -> FanOutResult:
    """Delete connection config and secrets from S3, then reload ipsec on all servers.

    Called after tunnel soft-delete. The caller MUST have acquired
    the LOCK_IPSEC_CONFIG advisory lock.

    Args:
        name: The tunnel connection name.
        session: Active database session for server discovery.

    Returns:
        FanOutResult with per-server SSH execution outcomes.

    Raises:
        InfrastructureError: If S3 delete fails or no active servers are registered.
    """
    logger.info("ipsec_remove_start", tunnel=name)

    await s3.delete_file(_conf_key(name))
    await s3.delete_file(_secrets_key(name))

    result = await sftp_delete_on_all_servers(session, name)

    logger.info("ipsec_remove_complete", tunnel=name)
    return result


async def rename_tunnel_config(
    old_name: str,
    tunnel: Tunnel,
    psk: str,
    session: AsyncSession,
) -> FanOutResult:
    """Handle tunnel rename by removing old files and uploading new ones.

    Args:
        old_name: The previous tunnel name.
        tunnel: The Tunnel model with the new name.
        psk: The pre-shared key.
        session: Active database session for server discovery.

    Returns:
        FanOutResult with per-server SSH execution outcomes.

    Raises:
        InfrastructureError: If any S3 operation fails or no active servers are registered.
    """
    logger.info("ipsec_rename_start", old_name=old_name, new_name=tunnel.name)

    await s3.delete_file(_conf_key(old_name))
    await s3.delete_file(_secrets_key(old_name))

    conf_content = render_connection_conf(tunnel)
    secrets_content = render_secrets_file(tunnel, psk)
    await s3.upload_file(_conf_key(tunnel.name), conf_content)
    await s3.upload_file(_secrets_key(tunnel.name), secrets_content)

    result = await sftp_rename_on_all_servers(session, old_name, tunnel.name, conf_content, secrets_content)

    logger.info("ipsec_rename_complete", old_name=old_name, new_name=tunnel.name)
    return result
