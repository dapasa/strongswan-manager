"""IPSec configuration service — renders and pushes per-connection config to VPN nodes.

The PSK is always passed in at call time; it is decrypted from the DB just
before calling these functions and is never stored in plaintext.
"""

from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import Tunnel
from app.logging_config import get_logger
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

    # Strict proposals: stroke requires '!' suffix to disable proposal negotiation.
    # Strip any existing '!' first to avoid '!!'.
    ike_strict = (tunnel.ike_proposals.rstrip("!") + "!") if tunnel.ike_proposals else None
    esp_strict = (tunnel.esp_proposals.rstrip("!") + "!") if tunnel.esp_proposals else None

    lines = [
        f"conn {tunnel.name}",
        "    left=%any",
    ]

    # leftid: use the explicit local identity if configured; omit otherwise so
    # strongSwan defaults to the outgoing interface address.
    if tunnel.local_id:
        lines.append(f"    leftid={tunnel.local_id}")

    lines.extend([
        f"    leftsubnet={local_cidrs}",
        "    leftauth=psk",
        "    leftsendcert=never",
        f"    right={tunnel.peer_ip}",
        "    rightid=%any",
        f"    rightsubnet={remote_cidrs}",
        "    rightauth=psk",
    ])

    # IKE and ESP proposals (strict mode: '!' prevents fallback to other suites)
    if ike_strict:
        lines.append(f"    ike={ike_strict}")
    if esp_strict:
        lines.append(f"    esp={esp_strict}")

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
        f"    ikelifetime={tunnel.ike_lifetime}s",
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


def render_swanctl_conf(tunnel: Tunnel, psk: str) -> str:
    """Render a swanctl conf.d file combining connections and secrets for one tunnel.

    This produces a SINGLE file written to ``conf.d/<name>.conf`` with mode 0600.
    The file contains both the ``connections { ... }`` block and the
    ``secrets { ike-<name> { ... } }`` block so that ``swanctl --load-all`` picks
    up everything from a single file.

    Unmapped stroke fields (intentionally omitted):
    - ``rekeymargin=3m`` — swanctl ``rand_rekey_time`` but not stored in the model.
    - ``dpdtimeout=150s`` — swanctl relies on IKEv2 retransmit; no direct mapping.

    Mapped field notes:
    - ``leftsendcert=never`` → ``send_cert = never`` inside ``local { }``.
    - ``leftid`` → ``local { id = <local_id> }`` when local_id is set; omitted otherwise.
    - ``ikelifetime`` → ``rekey_time`` on the IKE connection (swanctl controls IKE SA
      lifetime via ``rekey_time`` at the connection level, not inside children).
    - swanctl proposals are strict by default; no ``!`` suffix needed.

    Args:
        tunnel: The Tunnel model instance.
        psk: The pre-shared key value.

    Returns:
        The rendered swanctl conf.d file content.
    """
    local_cidrs = ",".join(str(c) for c in tunnel.local_cidrs)
    remote_cidrs = ",".join(str(c) for c in tunnel.remote_cidrs)

    conn_lines = [
        "connections {",
        f"  {tunnel.name} {{",
        f"    version = {tunnel.ike_version}",
        "    local_addrs = %any",
        f"    remote_addrs = {tunnel.peer_ip}",
        "    encap = yes",
        "    fragmentation = yes",
        "    mobike = no",
        # swanctl: rekey_time on the IKE connection controls IKE SA lifetime
        # (equivalent to stroke's ikelifetime)
        f"    rekey_time = {tunnel.ike_lifetime}s",
        f"    dpd_delay = {tunnel.dpd_delay}s",
        "    keyingtries = 0",
    ]

    # swanctl proposals are strict by default; no '!' suffix needed
    if tunnel.ike_proposals:
        conn_lines.append(f"    proposals = {tunnel.ike_proposals}")

    local_block = [
        "",
        "    local {",
    ]
    # local_id: use explicit identity when set; omit otherwise (strongSwan uses source IP)
    if tunnel.local_id:
        local_block.append(f"      id = {tunnel.local_id}")
    local_block.extend([
        "      auth = psk",
        # send_cert = never is a stroke-only option; omit for swanctl PSK auth
        "    }",
    ])
    conn_lines.extend(local_block)

    conn_lines.extend([
        "    remote {",
        # id = %any: wildcard selector — matches any IKE identity from the peer,
        # which is correct for PSK matching where the remote identity is not fixed.
        "      id = %any",
        "      auth = psk",
        "    }",
        "    children {",
        f"      {tunnel.name} {{",
        f"        local_ts = {local_cidrs}",
        f"        remote_ts = {remote_cidrs}",
        f"        dpd_action = {tunnel.dpd_action}",
        "        start_action = none",
        "        rekey_time = 3600s",
    ])

    if tunnel.esp_proposals:
        conn_lines.append(f"        esp_proposals = {tunnel.esp_proposals}")

    conn_lines.extend([
        "      }",
        "    }",
        "  }",
        "}",
    ])

    # Escape PSK for UCL double-quoted string format (swanctl uses UCL).
    # A raw '"' in the PSK terminates the string early; '\' must also be escaped.
    _escaped_psk = psk.replace("\\", "\\\\").replace('"', '\\"')
    secrets_lines = [
        "secrets {",
        f"  ike-{tunnel.name} {{",
        "    id = %any",
        f'    secret = "{_escaped_psk}"',
        "  }",
        "}",
    ]

    return "\n".join(conn_lines + [""] + secrets_lines) + "\n"


async def sync_tunnel_config(tunnel: Tunnel, psk: str, session: AsyncSession) -> FanOutResult:
    """Render config and push to all VPN servers via SSH/SSM fan-out.

    Called after tunnel create or update. The caller MUST have acquired
    the LOCK_IPSEC_CONFIG advisory lock.

    Args:
        tunnel: The Tunnel model instance with current field values.
        psk: The plaintext PSK — decrypted from DB by the caller, never logged.
        session: Active database session for server discovery.

    Returns:
        FanOutResult with per-server SSH execution outcomes.

    Raises:
        InfrastructureError: If no active servers are registered or fan-out fails fatally.
    """
    logger.info("ipsec_sync_start", tunnel=tunnel.name)

    conf_content = render_connection_conf(tunnel)
    secrets_content = render_secrets_file(tunnel, psk)
    swanctl_content = render_swanctl_conf(tunnel, psk)

    result = await sftp_push_on_all_servers(
        session, tunnel.name, conf_content, secrets_content, swanctl_content=swanctl_content
    )

    logger.info("ipsec_sync_complete", tunnel=tunnel.name)
    return result


async def remove_tunnel_config(name: str, session: AsyncSession) -> FanOutResult:
    """Remove config files from all VPN servers, then reload ipsec.

    Called after tunnel soft-delete. The caller MUST have acquired
    the LOCK_IPSEC_CONFIG advisory lock.

    Args:
        name: The tunnel connection name.
        session: Active database session for server discovery.

    Returns:
        FanOutResult with per-server SSH execution outcomes.

    Raises:
        InfrastructureError: If no active servers are registered.
    """
    logger.info("ipsec_remove_start", tunnel=name)

    result = await sftp_delete_on_all_servers(session, name)

    logger.info("ipsec_remove_complete", tunnel=name)
    return result


async def rename_tunnel_config(
    old_name: str,
    tunnel: Tunnel,
    psk: str,
    session: AsyncSession,
) -> FanOutResult:
    """Handle tunnel rename: remove old config files and push new ones to all servers.

    Args:
        old_name: The previous tunnel name.
        tunnel: The Tunnel model with the new name.
        psk: The plaintext PSK — decrypted from DB by the caller, never logged.
        session: Active database session for server discovery.

    Returns:
        FanOutResult with per-server SSH execution outcomes.

    Raises:
        InfrastructureError: If no active servers are registered.
    """
    logger.info("ipsec_rename_start", old_name=old_name, new_name=tunnel.name)

    conf_content = render_connection_conf(tunnel)
    secrets_content = render_secrets_file(tunnel, psk)
    swanctl_content = render_swanctl_conf(tunnel, psk)

    result = await sftp_rename_on_all_servers(
        session, old_name, tunnel.name, conf_content, secrets_content,
        swanctl_content=swanctl_content
    )

    logger.info("ipsec_rename_complete", old_name=old_name, new_name=tunnel.name)
    return result
