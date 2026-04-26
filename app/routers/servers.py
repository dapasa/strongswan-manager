"""Servers router — CRUD + SSH connectivity testing for VPN servers."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import require_admin, require_operator, require_viewer
from app.db.models import User
from app.db.session import get_db
from app.logging_config import get_logger
from app.schemas.common import PaginatedResponse
from app.schemas.server import (
    ServerCreate,
    ServerDetail,
    ServerStatusResult,
    ServerSummary,
    ServerTestResult,
    ServerUpdate,
)
from app.services import server_service

logger = get_logger(__name__)

router = APIRouter(prefix="/api/v1/servers", tags=["servers"])


@router.get(
    "/",
    response_model=PaginatedResponse[ServerSummary],
    summary="List active servers",
)
async def list_servers(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Items per page"),
    status_filter: str | None = Query(None, alias="status", description="Filter by last_check_status"),
    search: str | None = Query(None, description="Search by name or hostname"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> PaginatedResponse[ServerSummary]:
    """List all active (non-deleted) servers with pagination, filtering, and search."""
    servers, total = await server_service.list_servers(
        db,
        page=page,
        page_size=page_size,
        status_filter=status_filter,
        search=search,
    )
    items = [ServerSummary.model_validate(s) for s in servers]
    offset = (page - 1) * page_size
    return PaginatedResponse[ServerSummary](
        items=items,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(offset + page_size) < total,
    )


@router.get(
    "/{server_id}",
    response_model=ServerDetail,
    summary="Get server detail",
)
async def get_server(
    server_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_viewer),
) -> ServerDetail:
    """Get full server detail by ID. SSH key is never exposed."""
    server = await server_service.get_server(db, server_id)
    return ServerDetail.model_validate(server)


@router.post(
    "/",
    response_model=ServerDetail,
    status_code=status.HTTP_201_CREATED,
    summary="Create server",
)
async def create_server(
    data: ServerCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ServerDetail:
    """Create a new server with encrypted SSH key storage."""
    server = await server_service.create_server(
        db,
        data=data,
        user=current_user,
        request=request,
    )
    return ServerDetail.model_validate(server)


@router.patch(
    "/{server_id}",
    response_model=ServerDetail,
    summary="Update server",
)
async def update_server(
    server_id: int,
    data: ServerUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> ServerDetail:
    """Update an existing server. SSH key is re-encrypted if changed."""
    server = await server_service.update_server(
        db,
        server_id,
        data=data,
        user=current_user,
        request=request,
    )
    return ServerDetail.model_validate(server)


@router.delete(
    "/{server_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Delete server (soft delete)",
)
async def delete_server(
    server_id: int,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
) -> None:
    """Soft-delete a server by setting deleted_at timestamp."""
    await server_service.delete_server(
        db,
        server_id,
        user=current_user,
        request=request,
    )


@router.post(
    "/{server_id}/test",
    response_model=ServerTestResult,
    summary="Test SSH connection",
)
async def test_server_connection(
    server_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> ServerTestResult:
    """Test SSH connectivity to a server. Does not persist the result."""
    result = await server_service.test_connection(db, server_id)
    return ServerTestResult(**result)


@router.post(
    "/{server_id}/status",
    response_model=ServerStatusResult,
    summary="Check and persist server status",
)
async def check_server_status(
    server_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_operator),
) -> ServerStatusResult:
    """Check SSH connectivity and persist the result to the database."""
    result = await server_service.check_status(db, server_id)
    return ServerStatusResult(**result)
