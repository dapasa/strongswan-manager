"""IPSec configuration service — manages per-connection .conf and .secrets files in S3.

Each tunnel maps to two S3 objects:
    connections/{name}.conf     — StrongSwan connection configuration
    secrets/{name}.secrets      — PSK secret for the connection

The sync_config function uploads both files and triggers an ipsec reload on
the VPN instances. The remove_config function deletes both files and reloads.
"""

from __future__ import annotations

from app.db.models import Tunnel
from app.logging_config import get_logger
from app.services import s3, ssm

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
    local_cidrs = ",".join(tunnel.local_cidrs)
    remote_cidrs = ",".join(tunnel.remote_cidrs)

    lines = [
        f"conn {tunnel.name}",
        "    left=%any",
        f"    leftid={tunnel.local_cidrs[0].split('/')[0] if tunnel.local_cidrs else '%any'}",
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
    left_ip = tunnel.local_cidrs[0].split("/")[0] if tunnel.local_cidrs else "%any"
    return f'{tunnel.peer_ip} {left_ip} : PSK "{psk}"\n'


def _conf_key(name: str) -> str:
    """S3 key for a connection config file."""
    return f"connections/{name}.conf"


def _secrets_key(name: str) -> str:
    """S3 key for a connection secrets file."""
    return f"secrets/{name}.secrets"


async def sync_tunnel_config(tunnel: Tunnel, psk: str) -> None:
    """Upload connection config and secrets to S3, then reload ipsec.

    Called after tunnel create or update. The caller MUST have acquired
    the LOCK_IPSEC_CONFIG advisory lock.

    Args:
        tunnel: The Tunnel model instance with current field values.
        psk: The pre-shared key for this tunnel.

    Raises:
        InfrastructureError: If S3 upload or SSM reload fails.
    """
    logger.info("ipsec_sync_start", tunnel=tunnel.name)

    conf_content = render_connection_conf(tunnel)
    secrets_content = render_secrets_file(tunnel, psk)

    await s3.upload_file(_conf_key(tunnel.name), conf_content)
    await s3.upload_file(_secrets_key(tunnel.name), secrets_content)
    await ssm.reload_ipsec()

    logger.info("ipsec_sync_complete", tunnel=tunnel.name)


async def remove_tunnel_config(name: str) -> None:
    """Delete connection config and secrets from S3, then reload ipsec.

    Called after tunnel soft-delete. The caller MUST have acquired
    the LOCK_IPSEC_CONFIG advisory lock.

    Args:
        name: The tunnel connection name.

    Raises:
        InfrastructureError: If S3 delete or SSM reload fails.
    """
    logger.info("ipsec_remove_start", tunnel=name)

    await s3.delete_file(_conf_key(name))
    await s3.delete_file(_secrets_key(name))
    await ssm.reload_ipsec()

    logger.info("ipsec_remove_complete", tunnel=name)


async def rename_tunnel_config(old_name: str, tunnel: Tunnel, psk: str) -> None:
    """Handle tunnel rename by removing old files and uploading new ones.

    Args:
        old_name: The previous tunnel name.
        tunnel: The Tunnel model with the new name.
        psk: The pre-shared key.

    Raises:
        InfrastructureError: If any S3 or SSM operation fails.
    """
    logger.info("ipsec_rename_start", old_name=old_name, new_name=tunnel.name)

    # Delete old files
    await s3.delete_file(_conf_key(old_name))
    await s3.delete_file(_secrets_key(old_name))

    # Upload new files
    conf_content = render_connection_conf(tunnel)
    secrets_content = render_secrets_file(tunnel, psk)
    await s3.upload_file(_conf_key(tunnel.name), conf_content)
    await s3.upload_file(_secrets_key(tunnel.name), secrets_content)

    await ssm.reload_ipsec()

    logger.info("ipsec_rename_complete", old_name=old_name, new_name=tunnel.name)
