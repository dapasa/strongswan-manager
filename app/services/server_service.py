"""Server management service — CRUD operations and transport connectivity testing."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Server, User
from app.exceptions import ConflictError, InfrastructureError, NotFoundError
from app.logging_config import get_logger
from app.services import audit
from app.services.transport.base import TransportError
from app.services.transport.factory import get_transport
from app.utils.crypto import encrypt_ssh_key, validate_ssh_private_key
from app.utils.fan_out import FanOutResult, ServerResult

logger = get_logger(__name__)

# SSH connection timeout in seconds (used for check_reachable)
SSH_CONNECT_TIMEOUT = 10

# swanctl command to reload all connections after config push / delete
_LOAD_ALL = "sudo /usr/sbin/swanctl --load-all"


def _remote_conf_path(name: str) -> str:
    """Remote path for a tunnel's .conf file on VPN servers."""
    return f"{get_settings().vpn_conf_dir}/{name}.conf"


def _remote_secrets_path(name: str) -> str:
    """Remote path for a tunnel's .secrets file on VPN servers."""
    return f"{get_settings().vpn_secrets_dir}/{name}.secrets"


async def execute_command(
    session: AsyncSession,
    server_id: int,
    commands: list[str],
    *,
    timeout: int | None = None,
) -> ServerResult:
    """Execute shell commands on a server via SSH.

    Args:
        session: DB session to load the server record.
        server_id: Target server primary key.
        commands: Shell commands to execute (joined with ' && ').
        timeout: Per-command timeout in seconds. Defaults to ssh_command_timeout from settings.

    Returns:
        ServerResult with success=True and output on success, or success=False with error.
    """
    server = await get_server(session, server_id)
    effective_timeout = timeout if timeout is not None else get_settings().ssh_command_timeout

    try:
        result = await asyncio.wait_for(
            get_transport(server).execute(commands),
            timeout=effective_timeout,
        )

        logger.info("server_execute_command_success", server_id=server.id, name=server.name)
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=True,
            output=result.stdout,
        )

    except asyncio.TimeoutError:
        logger.warning("server_execute_command_timeout", server_id=server.id, name=server.name)
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error="Command timed out",
        )
    except TransportError as exc:
        logger.warning(
            "server_execute_command_transport_error",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=f"Transport error: {exc}",
        )
    except Exception as exc:
        logger.error(
            "server_execute_command_unexpected",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=f"Unexpected error: {exc}",
        )


async def execute_on_all_servers(
    session: AsyncSession,
    commands: list[str],
    *,
    timeout: int | None = None,
) -> FanOutResult:
    """Execute commands on ALL active servers concurrently.

    Queries all active non-deleted servers, runs commands on each via
    asyncio.gather, and returns aggregate results. Never raises on partial
    failure — caller decides how to handle the FanOutResult.

    Args:
        session: DB session.
        commands: Shell commands to execute on each server.
        timeout: Per-server timeout in seconds.

    Returns:
        FanOutResult with per-server outcomes.

    Raises:
        InfrastructureError: If no active servers are registered.
    """
    stmt = select(Server).where(Server.is_active.is_(True), Server.deleted_at.is_(None))
    result = await session.execute(stmt)
    servers = list(result.scalars().all())

    if not servers:
        raise InfrastructureError(
            service="servers",
            message="No active servers registered — cannot execute commands",
        )

    tasks = [execute_command(session, s.id, commands, timeout=timeout) for s in servers]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    server_results: list[ServerResult] = []
    for i, outcome in enumerate(gathered):
        if isinstance(outcome, Exception):
            server_results.append(
                ServerResult(
                    server_id=servers[i].id,
                    server_name=servers[i].name,
                    success=False,
                    error=f"Unexpected error: {outcome}",
                )
            )
        else:
            server_results.append(outcome)

    succeeded = sum(1 for r in server_results if r.success)
    failed = len(server_results) - succeeded

    logger.info(
        "server_execute_on_all_servers",
        total=len(servers),
        succeeded=succeeded,
        failed=failed,
    )

    return FanOutResult(
        total=len(servers),
        succeeded=succeeded,
        failed=failed,
        servers=server_results,
    )


async def sftp_push_tunnel_config(
    server: Server,
    name: str,
    conf_content: str,
    secrets_content: str | None,
    *,
    timeout: int | None = None,
) -> ServerResult:
    """Open SSH to server, write .conf (and optionally .secrets) via sudo tee, run swanctl --load-all.

    Uses sudo tee instead of SFTP so that the SSH user does not need direct write access
    to the config directories — only sudo privileges for tee, chmod, and mkdir.

    Args:
        server: Target Server instance.
        name: Tunnel connection name (used to derive remote file paths).
        conf_content: Content to write to the .conf file.
        secrets_content: Content for the .secrets file, or None to skip writing it.
        timeout: Operation timeout in seconds. Defaults to ssh_command_timeout from settings.

    Returns:
        ServerResult with success=True on success, or success=False with error message.
    """
    effective_timeout = timeout if timeout is not None else get_settings().ssh_command_timeout
    conf_path = _remote_conf_path(name)
    secrets_path = _remote_secrets_path(name)
    transport = get_transport(server)

    async def _run() -> ServerResult:
        await transport.write_file(conf_path, conf_content, mode="644", make_dirs=True)

        if secrets_content is not None:
            await transport.write_file(secrets_path, secrets_content, mode="640", make_dirs=True)

        await transport.execute([_LOAD_ALL])

        logger.info("server_sftp_push_success", server_id=server.id, name=server.name, tunnel=name)
        return ServerResult(server_id=server.id, server_name=server.name, success=True)

    try:
        return await asyncio.wait_for(_run(), timeout=effective_timeout)
    except asyncio.TimeoutError:
        logger.warning("server_sftp_push_timeout", server_id=server.id, name=server.name, tunnel=name)
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error="Command timed out",
        )
    except TransportError as exc:
        logger.warning(
            "server_sftp_push_error",
            server_id=server.id,
            name=server.name,
            tunnel=name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=str(exc),
        )
    except Exception as exc:
        logger.error(
            "server_sftp_push_unexpected",
            server_id=server.id,
            name=server.name,
            tunnel=name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=f"Unexpected error: {exc}",
        )


async def sftp_delete_tunnel_config(
    server: Server,
    name: str,
    *,
    timeout: int | None = None,
) -> ServerResult:
    """Open SSH to server, remove .conf and .secrets via sudo rm -f (idempotent), run swanctl --load-all.

    Args:
        server: Target Server instance.
        name: Tunnel connection name.
        timeout: Operation timeout in seconds. Defaults to ssh_command_timeout from settings.

    Returns:
        ServerResult with success=True on success (including file-not-found), or success=False with error.
    """
    effective_timeout = timeout if timeout is not None else get_settings().ssh_command_timeout
    conf_path = _remote_conf_path(name)
    secrets_path = _remote_secrets_path(name)
    transport = get_transport(server)

    async def _run() -> ServerResult:
        await transport.delete_file(conf_path)
        await transport.delete_file(secrets_path)
        await transport.execute([_LOAD_ALL])

        logger.info("server_sftp_delete_success", server_id=server.id, name=server.name, tunnel=name)
        return ServerResult(server_id=server.id, server_name=server.name, success=True)

    try:
        return await asyncio.wait_for(_run(), timeout=effective_timeout)
    except asyncio.TimeoutError:
        logger.warning("server_sftp_delete_timeout", server_id=server.id, name=server.name, tunnel=name)
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error="Command timed out",
        )
    except TransportError as exc:
        logger.warning(
            "server_sftp_delete_error",
            server_id=server.id,
            name=server.name,
            tunnel=name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=str(exc),
        )
    except Exception as exc:
        logger.error(
            "server_sftp_delete_unexpected",
            server_id=server.id,
            name=server.name,
            tunnel=name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=f"Unexpected error: {exc}",
        )


async def _sftp_rename_on_server(
    server: Server,
    old_name: str,
    new_name: str,
    conf_content: str,
    secrets_content: str,
    *,
    timeout: int | None = None,
) -> ServerResult:
    """Delete old config files and push new ones via the transport layer.

    Uses delete_file (idempotent) + write_file for the rename-and-rewrite
    pattern required when a tunnel connection name changes.

    Args:
        server: Target Server instance.
        old_name: Previous tunnel name (files to delete).
        new_name: New tunnel name (files to write).
        conf_content: Content for the new .conf file.
        secrets_content: Content for the new .secrets file.
        timeout: Operation timeout in seconds. Defaults to ssh_command_timeout from settings.

    Returns:
        ServerResult with success=True on success, or success=False with error.
    """
    effective_timeout = timeout if timeout is not None else get_settings().ssh_command_timeout
    old_conf = _remote_conf_path(old_name)
    old_secrets = _remote_secrets_path(old_name)
    new_conf = _remote_conf_path(new_name)
    new_secrets = _remote_secrets_path(new_name)
    transport = get_transport(server)

    async def _run() -> ServerResult:
        await transport.delete_file(old_conf)
        await transport.delete_file(old_secrets)
        await transport.write_file(new_conf, conf_content, mode="644", make_dirs=True)
        await transport.write_file(new_secrets, secrets_content, mode="640", make_dirs=True)
        await transport.execute([_LOAD_ALL])

        logger.info(
            "server_sftp_rename_success",
            server_id=server.id,
            name=server.name,
            old_tunnel=old_name,
            new_tunnel=new_name,
        )
        return ServerResult(server_id=server.id, server_name=server.name, success=True)

    try:
        return await asyncio.wait_for(_run(), timeout=effective_timeout)
    except asyncio.TimeoutError:
        logger.warning(
            "server_sftp_rename_timeout",
            server_id=server.id,
            name=server.name,
            old_tunnel=old_name,
            new_tunnel=new_name,
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error="Command timed out",
        )
    except TransportError as exc:
        logger.warning(
            "server_sftp_rename_error",
            server_id=server.id,
            name=server.name,
            old_tunnel=old_name,
            new_tunnel=new_name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=str(exc),
        )
    except Exception as exc:
        logger.error(
            "server_sftp_rename_unexpected",
            server_id=server.id,
            name=server.name,
            old_tunnel=old_name,
            new_tunnel=new_name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=f"Unexpected error: {exc}",
        )


async def sftp_push_on_all_servers(
    session: AsyncSession,
    name: str,
    conf_content: str,
    secrets_content: str | None,
    *,
    timeout: int | None = None,
) -> FanOutResult:
    """Fan-out sftp_push_tunnel_config to all active servers concurrently.

    Args:
        session: DB session for server discovery.
        name: Tunnel connection name.
        conf_content: Content for the .conf file.
        secrets_content: Content for the .secrets file, or None to push conf only.
        timeout: Per-server timeout in seconds.

    Returns:
        FanOutResult with per-server outcomes.

    Raises:
        InfrastructureError: If no active servers are registered.
    """
    stmt = select(Server).where(Server.is_active.is_(True), Server.deleted_at.is_(None))
    result = await session.execute(stmt)
    servers = list(result.scalars().all())

    if not servers:
        raise InfrastructureError(
            service="servers",
            message="No active servers registered — cannot push tunnel config",
        )

    tasks = [
        sftp_push_tunnel_config(s, name, conf_content, secrets_content, timeout=timeout)
        for s in servers
    ]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    server_results: list[ServerResult] = []
    for i, outcome in enumerate(gathered):
        if isinstance(outcome, Exception):
            server_results.append(
                ServerResult(
                    server_id=servers[i].id,
                    server_name=servers[i].name,
                    success=False,
                    error=f"Unexpected error: {outcome}",
                )
            )
        else:
            server_results.append(outcome)

    succeeded = sum(1 for r in server_results if r.success)
    failed = len(server_results) - succeeded

    logger.info(
        "server_sftp_push_on_all_servers",
        total=len(servers),
        succeeded=succeeded,
        failed=failed,
    )

    return FanOutResult(
        total=len(servers),
        succeeded=succeeded,
        failed=failed,
        servers=server_results,
    )


async def sftp_delete_on_all_servers(
    session: AsyncSession,
    name: str,
    *,
    timeout: int | None = None,
) -> FanOutResult:
    """Fan-out sftp_delete_tunnel_config to all active servers concurrently.

    Args:
        session: DB session for server discovery.
        name: Tunnel connection name.
        timeout: Per-server timeout in seconds.

    Returns:
        FanOutResult with per-server outcomes.

    Raises:
        InfrastructureError: If no active servers are registered.
    """
    stmt = select(Server).where(Server.is_active.is_(True), Server.deleted_at.is_(None))
    result = await session.execute(stmt)
    servers = list(result.scalars().all())

    if not servers:
        raise InfrastructureError(
            service="servers",
            message="No active servers registered — cannot delete tunnel config",
        )

    tasks = [sftp_delete_tunnel_config(s, name, timeout=timeout) for s in servers]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    server_results: list[ServerResult] = []
    for i, outcome in enumerate(gathered):
        if isinstance(outcome, Exception):
            server_results.append(
                ServerResult(
                    server_id=servers[i].id,
                    server_name=servers[i].name,
                    success=False,
                    error=f"Unexpected error: {outcome}",
                )
            )
        else:
            server_results.append(outcome)

    succeeded = sum(1 for r in server_results if r.success)
    failed = len(server_results) - succeeded

    logger.info(
        "server_sftp_delete_on_all_servers",
        total=len(servers),
        succeeded=succeeded,
        failed=failed,
    )

    return FanOutResult(
        total=len(servers),
        succeeded=succeeded,
        failed=failed,
        servers=server_results,
    )


async def sftp_rename_on_all_servers(
    session: AsyncSession,
    old_name: str,
    new_name: str,
    conf_content: str,
    secrets_content: str,
    *,
    timeout: int | None = None,
) -> FanOutResult:
    """Fan-out delete-old + push-new in a single SSH connection per server.

    Args:
        session: DB session for server discovery.
        old_name: Previous tunnel name (files to remove).
        new_name: New tunnel name (files to write).
        conf_content: Content for the new .conf file.
        secrets_content: Content for the new .secrets file.
        timeout: Per-server timeout in seconds.

    Returns:
        FanOutResult with per-server outcomes.

    Raises:
        InfrastructureError: If no active servers are registered.
    """
    stmt = select(Server).where(Server.is_active.is_(True), Server.deleted_at.is_(None))
    result = await session.execute(stmt)
    servers = list(result.scalars().all())

    if not servers:
        raise InfrastructureError(
            service="servers",
            message="No active servers registered — cannot rename tunnel config",
        )

    tasks = [
        _sftp_rename_on_server(s, old_name, new_name, conf_content, secrets_content, timeout=timeout)
        for s in servers
    ]
    gathered = await asyncio.gather(*tasks, return_exceptions=True)

    server_results: list[ServerResult] = []
    for i, outcome in enumerate(gathered):
        if isinstance(outcome, Exception):
            server_results.append(
                ServerResult(
                    server_id=servers[i].id,
                    server_name=servers[i].name,
                    success=False,
                    error=f"Unexpected error: {outcome}",
                )
            )
        else:
            server_results.append(outcome)

    succeeded = sum(1 for r in server_results if r.success)
    failed = len(server_results) - succeeded

    logger.info(
        "server_sftp_rename_on_all_servers",
        total=len(servers),
        succeeded=succeeded,
        failed=failed,
    )

    return FanOutResult(
        total=len(servers),
        succeeded=succeeded,
        failed=failed,
        servers=server_results,
    )


def _server_to_dict(server: Server) -> dict[str, Any]:
    """Serialize a Server model to a dict suitable for audit JSONB storage.

    IMPORTANT: ssh_private_key_encrypted is NEVER included.
    """
    return {
        "id": server.id,
        "name": server.name,
        "connection_type": server.connection_type,
        # SSH fields (None for SSM servers)
        "hostname": server.hostname,
        "ssh_port": server.ssh_port,
        "ssh_user": server.ssh_user,
        # SSM fields (None for SSH servers)
        "ec2_instance_id": server.ec2_instance_id,
        "aws_role_arn": server.aws_role_arn,
        "aws_region_override": server.aws_region_override,
        "description": server.description,
        "is_active": server.is_active,
        "last_check_at": server.last_check_at.isoformat() if server.last_check_at else None,
        "last_check_status": server.last_check_status,
        "created_at": server.created_at.isoformat() if server.created_at else None,
        "updated_at": server.updated_at.isoformat() if server.updated_at else None,
    }


async def list_servers(
    session: AsyncSession,
    *,
    page: int = 1,
    page_size: int = 20,
    status_filter: str | None = None,
    search: str | None = None,
) -> tuple[list[Server], int]:
    """List active (non-deleted) servers with pagination and filters.

    Args:
        session: Active database session.
        page: Page number (1-indexed).
        page_size: Number of items per page.
        status_filter: Filter by last_check_status ('reachable' or 'unreachable').
        search: Search term for name or hostname.

    Returns:
        Tuple of (list of Server instances, total count).
    """
    base_where = [Server.deleted_at.is_(None)]

    if status_filter is not None:
        base_where.append(Server.last_check_status == status_filter)
    if search is not None:
        search_pattern = f"%{search}%"
        base_where.append(
            Server.name.ilike(search_pattern)
            | Server.hostname.ilike(search_pattern)
            | Server.ec2_instance_id.ilike(search_pattern),
        )

    # Count query
    count_stmt = select(func.count()).select_from(Server).where(*base_where)
    total_result = await session.execute(count_stmt)
    total = total_result.scalar_one()

    # Paginated items query
    offset = (page - 1) * page_size
    items_stmt = (
        select(Server)
        .where(*base_where)
        .order_by(Server.name)
        .offset(offset)
        .limit(page_size)
    )
    result = await session.execute(items_stmt)
    return list(result.scalars().all()), total


async def get_server(session: AsyncSession, server_id: int) -> Server:
    """Get a single server by ID.

    Args:
        session: Active database session.
        server_id: Primary key of the server.

    Returns:
        The Server instance.

    Raises:
        NotFoundError: If no active server with the given ID exists.
    """
    result = await session.execute(
        select(Server).where(
            Server.id == server_id,
            Server.deleted_at.is_(None),
        ),
    )
    server = result.scalar_one_or_none()
    if server is None:
        raise NotFoundError("Server", server_id)
    return server


async def create_server(
    session: AsyncSession,
    *,
    data: Any,
    user: User,
    request: Request | None = None,
) -> Server:
    """Create a new server (SSH or SSM transport).

    For SSH servers:
      1. Validate SSH private key format.
      2. Encrypt SSH key with Fernet.
    For SSM servers:
      1. No key needed — ec2_instance_id is the identity.
    Common:
      1. Validate name uniqueness among active servers.
      2. Insert server record.
      3. Create audit log entry.
      4. Commit transaction.

    Args:
        session: Active database session.
        data: ServerCreate schema instance.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The created Server instance.

    Raises:
        ConflictError: If a server with the same name already exists.
        ValueError: If the SSH key is invalid (SSH servers only).
        EncryptionError: If the encryption key is not configured (SSH servers only).
    """
    # Validate name uniqueness
    existing = await session.execute(
        select(Server.id).where(
            Server.name == data.name,
            Server.deleted_at.is_(None),
        ),
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Server name already exists")

    connection_type = getattr(data, "connection_type", "ssh") or "ssh"

    if connection_type == "ssm":
        server = Server(
            name=data.name,
            connection_type="ssm",
            ec2_instance_id=data.ec2_instance_id,
            aws_role_arn=getattr(data, "aws_role_arn", None),
            aws_region_override=getattr(data, "aws_region_override", None),
            description=data.description,
            is_active=True,
            created_by=user.id,
        )
    else:
        # SSH server — validate and encrypt the private key
        validate_ssh_private_key(data.ssh_private_key)
        encrypted_key = encrypt_ssh_key(data.ssh_private_key)
        server = Server(
            name=data.name,
            connection_type="ssh",
            hostname=data.hostname,
            ssh_port=data.ssh_port,
            ssh_user=data.ssh_user,
            ssh_private_key_encrypted=encrypted_key,
            description=data.description,
            is_active=True,
            created_by=user.id,
        )

    session.add(server)
    await session.flush()

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="server",
        entity_id=server.id,
        action="create",
        new_state=_server_to_dict(server),
        request=request,
    )

    await session.commit()
    logger.info("server_created", server_id=server.id, name=server.name)
    return server


async def update_server(
    session: AsyncSession,
    server_id: int,
    *,
    data: Any,
    user: User,
    request: Request | None = None,
) -> Server:
    """Update an existing server.

    1. Get existing server, capture previous state.
    2. Validate name uniqueness if renaming.
    3. Validate and re-encrypt SSH key if changed.
    4. Apply partial updates.
    5. Create audit log entry.
    6. Commit transaction.

    Args:
        session: Active database session.
        server_id: Primary key of the server to update.
        data: ServerUpdate schema instance.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The updated Server instance.

    Raises:
        NotFoundError: If the server does not exist.
        ConflictError: If renaming to a name that already exists.
        ValueError: If the new SSH key is invalid.
        EncryptionError: If the encryption key is not configured.
    """
    server = await get_server(session, server_id)
    previous_state = _server_to_dict(server)

    update_data = data.model_dump(exclude_unset=True)

    # Check name uniqueness if renaming
    if "name" in update_data and update_data["name"] != server.name:
        existing = await session.execute(
            select(Server.id).where(
                Server.name == update_data["name"],
                Server.deleted_at.is_(None),
                Server.id != server_id,
            ),
        )
        if existing.scalar_one_or_none() is not None:
            raise ConflictError(f"Server name already exists")

    # Validate and encrypt new SSH key if provided
    ssh_private_key = update_data.pop("ssh_private_key", None)
    if ssh_private_key is not None:
        validate_ssh_private_key(ssh_private_key)
        server.ssh_private_key_encrypted = encrypt_ssh_key(ssh_private_key)

    # Apply remaining updates
    for field, value in update_data.items():
        setattr(server, field, value)

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="server",
        entity_id=server.id,
        action="update",
        previous_state=previous_state,
        new_state=_server_to_dict(server),
        request=request,
    )

    await session.commit()
    logger.info("server_updated", server_id=server.id, name=server.name)
    return server


async def delete_server(
    session: AsyncSession,
    server_id: int,
    *,
    user: User,
    request: Request | None = None,
) -> None:
    """Soft-delete a server by setting deleted_at to the current timestamp.

    Args:
        session: Active database session.
        server_id: Primary key of the server to delete.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Raises:
        NotFoundError: If the server does not exist.
    """
    server = await get_server(session, server_id)
    previous_state = _server_to_dict(server)

    server.deleted_at = datetime.now(timezone.utc)

    # Audit log
    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="server",
        entity_id=server.id,
        action="delete",
        previous_state=previous_state,
        request=request,
    )

    await session.commit()
    logger.info("server_deleted", server_id=server.id, name=server.name)


async def test_connection(session: AsyncSession, server_id: int) -> dict[str, Any]:
    """Test transport connectivity to a server without persisting the result.

    1. Retrieve server.
    2. Attempt transport.check_reachable with timeout.
    3. Return success/failure with descriptive message.

    Args:
        session: Active database session.
        server_id: Primary key of the server to test.

    Returns:
        Dict with server_id, server_name, success, message, tested_at.

    Raises:
        NotFoundError: If the server does not exist.
    """
    server = await get_server(session, server_id)
    tested_at = datetime.now(timezone.utc)

    transport_label = "SSM" if server.connection_type == "ssm" else "SSH"
    try:
        await get_transport(server).check_reachable(timeout=SSH_CONNECT_TIMEOUT)

        server.last_check_at = tested_at
        server.last_check_status = "reachable"
        await session.commit()

        logger.info("server_test_connection_success", server_id=server.id, name=server.name)
        return {
            "server_id": server.id,
            "server_name": server.name,
            "success": True,
            "message": f"{transport_label} connection successful",
            "tested_at": tested_at,
        }
    except TransportError as exc:
        logger.warning(
            "server_test_connection_failed",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )
        server.last_check_at = tested_at
        server.last_check_status = "unreachable"
        await session.commit()

        return {
            "server_id": server.id,
            "server_name": server.name,
            "success": False,
            "message": f"{transport_label} connection failed: {exc}",
            "tested_at": tested_at,
        }
    except Exception as exc:
        logger.error(
            "server_test_connection_unexpected",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )
        server.last_check_at = tested_at
        server.last_check_status = "unreachable"
        await session.commit()

        return {
            "server_id": server.id,
            "server_name": server.name,
            "success": False,
            "message": "Connection test failed unexpectedly",
            "tested_at": tested_at,
        }


async def check_status(session: AsyncSession, server_id: int) -> dict[str, Any]:
    """Check transport connectivity and persist the result to the database.

    Same as test_connection but additionally updates last_check_at and
    last_check_status on the server record.

    Args:
        session: Active database session.
        server_id: Primary key of the server to check.

    Returns:
        Dict with server_id, server_name, success, message, status, checked_at.

    Raises:
        NotFoundError: If the server does not exist.
    """
    server = await get_server(session, server_id)
    checked_at = datetime.now(timezone.utc)

    transport_label = "SSM" if server.connection_type == "ssm" else "SSH"
    try:
        await get_transport(server).check_reachable(timeout=SSH_CONNECT_TIMEOUT)
        status = "reachable"
        message = f"{transport_label} connection successful"
        success = True
        logger.info("server_check_status_reachable", server_id=server.id, name=server.name)

    except TransportError as exc:
        status = "unreachable"
        message = f"{transport_label} connection failed: {exc}"
        success = False
        logger.warning(
            "server_check_status_unreachable",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )
    except Exception as exc:
        status = "unreachable"
        message = "Status check failed unexpectedly"
        success = False
        logger.error(
            "server_check_status_unexpected",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )

    # Persist status to database
    server.last_check_at = checked_at
    server.last_check_status = status
    await session.commit()

    return {
        "server_id": server.id,
        "server_name": server.name,
        "success": success,
        "message": message,
        "status": status,
        "checked_at": checked_at,
    }
