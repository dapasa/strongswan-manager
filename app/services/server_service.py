"""Server management service — CRUD operations and SSH connectivity testing."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import Any

import asyncssh
from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import get_settings
from app.db.models import Server, User
from app.exceptions import ConflictError, InfrastructureError, NotFoundError
from app.logging_config import get_logger
from app.services import audit
from app.utils.crypto import decrypt_ssh_key, encrypt_ssh_key, validate_ssh_private_key
from app.utils.fan_out import FanOutResult, ServerResult

logger = get_logger(__name__)

# SSH connection timeout in seconds
SSH_CONNECT_TIMEOUT = 10


async def _connect_ssh(server: Server) -> asyncssh.SSHClientConnection:
    """Create an asyncssh connection to a server.

    Decrypts the stored SSH key and connects using the server's hostname,
    port, and user. Returns the connection — caller must use as context manager.

    Raises:
        asyncssh.Error: On SSH connection failure.
        OSError: On network-level failure.
        EncryptionError: If the stored SSH key cannot be decrypted.
    """
    raw_key = decrypt_ssh_key(server.ssh_private_key_encrypted)
    key = asyncssh.import_private_key(raw_key)
    return asyncssh.connect(
        server.hostname,
        port=server.ssh_port,
        username=server.ssh_user,
        client_keys=[key],
        known_hosts=None,
        connect_timeout=SSH_CONNECT_TIMEOUT,
    )


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
    command = " && ".join(commands)

    try:
        async with await _connect_ssh(server) as conn:
            result = await asyncio.wait_for(
                conn.run(command),
                timeout=effective_timeout,
            )

        if result.exit_status != 0:
            stderr = result.stderr or ""
            stdout = result.stdout or ""
            logger.warning(
                "server_execute_command_nonzero",
                server_id=server.id,
                name=server.name,
                exit_status=result.exit_status,
                stdout=stdout,
                stderr=stderr,
            )
            detail = (stderr or stdout).strip() or f"exit {result.exit_status}"
            return ServerResult(
                server_id=server.id,
                server_name=server.name,
                success=False,
                error=f"Command exited with status {result.exit_status}: {detail}",
            )

        logger.info("server_execute_command_success", server_id=server.id, name=server.name)
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=True,
            output=result.stdout or "",
        )

    except asyncio.TimeoutError:
        logger.warning("server_execute_command_timeout", server_id=server.id, name=server.name)
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error="Command timed out",
        )
    except asyncssh.Error as exc:
        logger.warning(
            "server_execute_command_ssh_error",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=f"SSH error: {exc}",
        )
    except OSError as exc:
        logger.error(
            "server_execute_command_os_error",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )
        return ServerResult(
            server_id=server.id,
            server_name=server.name,
            success=False,
            error=f"Connection failed: {exc}",
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
            service="SSH",
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


def _server_to_dict(server: Server) -> dict[str, Any]:
    """Serialize a Server model to a dict suitable for audit JSONB storage.

    IMPORTANT: ssh_private_key_encrypted is NEVER included.
    """
    return {
        "id": server.id,
        "name": server.name,
        "hostname": server.hostname,
        "ssh_port": server.ssh_port,
        "ssh_user": server.ssh_user,
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
            Server.name.ilike(search_pattern) | Server.hostname.ilike(search_pattern),
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
    """Create a new server with encrypted SSH key storage.

    1. Validate SSH private key format.
    2. Validate name uniqueness among active servers.
    3. Encrypt SSH key with Fernet.
    4. Insert server record.
    5. Create audit log entry.
    6. Commit transaction.

    Args:
        session: Active database session.
        data: ServerCreate schema instance.
        user: Authenticated user performing the operation.
        request: FastAPI request for audit context.

    Returns:
        The created Server instance.

    Raises:
        ConflictError: If a server with the same name already exists.
        ValueError: If the SSH key is invalid.
        EncryptionError: If the encryption key is not configured.
    """
    # Validate SSH key format
    validate_ssh_private_key(data.ssh_private_key)

    # Validate name uniqueness
    existing = await session.execute(
        select(Server.id).where(
            Server.name == data.name,
            Server.deleted_at.is_(None),
        ),
    )
    if existing.scalar_one_or_none() is not None:
        raise ConflictError(f"Server name already exists")

    # Encrypt the SSH key
    encrypted_key = encrypt_ssh_key(data.ssh_private_key)

    # Insert server
    server = Server(
        name=data.name,
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
    """Test SSH connectivity to a server without persisting the result.

    1. Retrieve server and decrypt SSH key.
    2. Attempt asyncssh.connect with timeout.
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

    try:
        async with await _connect_ssh(server):
            pass  # Connection succeeded, just close it

        server.last_check_at = tested_at
        server.last_check_status = "reachable"
        await session.commit()

        logger.info("server_test_connection_success", server_id=server.id, name=server.name)
        return {
            "server_id": server.id,
            "server_name": server.name,
            "success": True,
            "message": "SSH connection successful",
            "tested_at": tested_at,
        }
    except asyncssh.Error as exc:
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
            "message": f"SSH connection failed: {exc}",
            "tested_at": tested_at,
        }
    except OSError as exc:
        logger.error(
            "server_test_connection_os_error",
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
            "message": f"Connection failed: {exc}",
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
    """Check SSH connectivity and persist the result to the database.

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

    try:
        async with await _connect_ssh(server):
            pass  # Connection succeeded

        status = "reachable"
        message = "SSH connection successful"
        success = True
        logger.info("server_check_status_reachable", server_id=server.id, name=server.name)

    except asyncssh.Error as exc:
        status = "unreachable"
        message = f"SSH connection failed: {exc}"
        success = False
        logger.warning(
            "server_check_status_unreachable",
            server_id=server.id,
            name=server.name,
            error=str(exc),
        )
    except OSError as exc:
        status = "unreachable"
        message = f"Connection failed: {exc}"
        success = False
        logger.error(
            "server_check_status_os_error",
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
