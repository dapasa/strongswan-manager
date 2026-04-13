"""Shared test fixtures for vpn-manager-backend.

Uses PostgreSQL from docker-compose for DB tests (models use PG-specific types:
INET, CIDR, ARRAY, JSONB). Schema tests are pure Pydantic and need no DB.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from app.db.base import Base
from app.db.models import IPTablesRule, Route, Tunnel, User


# ---------------------------------------------------------------------------
# Database fixtures (require running PostgreSQL from docker-compose)
# ---------------------------------------------------------------------------

TEST_DATABASE_URL = "postgresql+asyncpg://vpnmanager:changeme@localhost:5432/vpnmanager_test"


@pytest.fixture(scope="session")
def anyio_backend() -> str:
    return "asyncio"


@pytest.fixture(scope="session")
async def test_engine() -> AsyncGenerator[AsyncEngine, None]:
    """Create a test-only async engine pointing to a separate test database.

    Creates the ``vpnmanager_test`` database if it does not exist, then creates
    all tables. After the session, drops all tables.
    """
    # Connect to default DB to create the test database
    admin_engine = create_async_engine(
        "postgresql+asyncpg://vpnmanager:changeme@localhost:5432/vpnmanager",
        isolation_level="AUTOCOMMIT",
    )
    async with admin_engine.connect() as conn:
        result = await conn.execute(
            text("SELECT 1 FROM pg_database WHERE datname = 'vpnmanager_test'"),
        )
        if not result.scalar():
            await conn.execute(text("CREATE DATABASE vpnmanager_test"))
    await admin_engine.dispose()

    # Now connect to the test database
    engine = create_async_engine(TEST_DATABASE_URL, echo=False)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest.fixture
async def db_session(test_engine: AsyncEngine) -> AsyncGenerator[AsyncSession, None]:
    """Yield an async session that rolls back after each test."""
    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    async with session_factory() as session:
        async with session.begin():
            yield session
            # Rollback after each test to keep isolation
            await session.rollback()


# ---------------------------------------------------------------------------
# FastAPI test client
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_admin_user() -> User:
    """Return a mock admin User object for dependency overrides."""
    user = MagicMock(spec=User)
    user.id = 1
    user.sub = "test-admin-sub"
    user.email = "admin@test.com"
    user.display_name = "Test Admin"
    user.role = "admin"
    user.is_active = True
    return user


@pytest.fixture
def mock_viewer_user() -> User:
    """Return a mock viewer User object for dependency overrides."""
    user = MagicMock(spec=User)
    user.id = 2
    user.sub = "test-viewer-sub"
    user.email = "viewer@test.com"
    user.display_name = "Test Viewer"
    user.role = "viewer"
    user.is_active = True
    return user


@pytest.fixture
async def async_client(
    db_session: AsyncSession,
    mock_admin_user: User,
) -> AsyncGenerator[httpx.AsyncClient, None]:
    """Yield an httpx.AsyncClient wired to the FastAPI app with overridden deps.

    Overrides:
    - ``get_db`` → test db_session
    - ``get_current_user`` → mock admin user
    """
    from app.auth.dependencies import get_current_user
    from app.db.session import get_db
    from app.main import app

    async def _override_get_db() -> AsyncGenerator[AsyncSession, None]:
        yield db_session

    async def _override_get_current_user() -> User:
        return mock_admin_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

    app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Factory fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def create_test_user(db_session: AsyncSession):
    """Factory fixture that creates a User in the DB with sensible defaults."""

    async def _factory(**overrides: Any) -> User:
        defaults: dict[str, Any] = {
            "sub": "oidc-subject-001",
            "email": "testuser@example.com",
            "display_name": "Test User",
            "role": "admin",
            "is_active": True,
        }
        defaults.update(overrides)
        user = User(**defaults)
        db_session.add(user)
        await db_session.flush()
        return user

    return _factory


@pytest.fixture
def create_test_tunnel(db_session: AsyncSession):
    """Factory fixture that creates a Tunnel in the DB with sensible defaults."""

    async def _factory(user: User | None = None, **overrides: Any) -> Tunnel:
        defaults: dict[str, Any] = {
            "name": "test-tunnel",
            "peer_ip": "203.0.113.1",
            "local_cidrs": ["10.0.0.0/24"],
            "remote_cidrs": ["192.168.1.0/24"],
            "psk_secret_name": "vpn/test-tunnel-psk",
            "ike_version": "2",
            "dpd_action": "restart",
            "dpd_delay": 30,
            "dpd_timeout": 150,
            "status": "active",
            "sync_status": "pending",
        }
        if user is not None:
            defaults["created_by"] = user.id
        defaults.update(overrides)
        tunnel = Tunnel(**defaults)
        db_session.add(tunnel)
        await db_session.flush()
        return tunnel

    return _factory


@pytest.fixture
def create_test_route(db_session: AsyncSession):
    """Factory fixture that creates a Route in the DB with sensible defaults."""

    async def _factory(
        tunnel: Tunnel,
        user: User | None = None,
        **overrides: Any,
    ) -> Route:
        defaults: dict[str, Any] = {
            "tunnel_id": tunnel.id,
            "cidr": "172.16.0.0/16",
            "description": "Test route",
            "sync_status": "pending",
        }
        if user is not None:
            defaults["created_by"] = user.id
        defaults.update(overrides)
        route = Route(**defaults)
        db_session.add(route)
        await db_session.flush()
        return route

    return _factory


@pytest.fixture
def create_test_iptables_rule(db_session: AsyncSession):
    """Factory fixture that creates an IPTablesRule in the DB with sensible defaults."""

    async def _factory(
        tunnel: Tunnel,
        user: User | None = None,
        **overrides: Any,
    ) -> IPTablesRule:
        defaults: dict[str, Any] = {
            "tunnel_id": tunnel.id,
            "chain": "FORWARD",
            "protocol": "tcp",
            "source_cidr": "10.0.0.0/24",
            "dest_cidr": "192.168.1.0/24",
            "dport": 443,
            "action": "ACCEPT",
            "comment": "Test iptables rule",
            "sync_status": "pending",
        }
        if user is not None:
            defaults["created_by"] = user.id
        defaults.update(overrides)
        rule = IPTablesRule(**defaults)
        db_session.add(rule)
        await db_session.flush()
        return rule

    return _factory


# ---------------------------------------------------------------------------
# Mock fixtures for external services
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_s3_service():
    """Patch S3 service functions with AsyncMock."""
    with (
        patch("app.services.s3.download_ipsec_conf", new_callable=AsyncMock) as mock_download,
        patch("app.services.s3.upload_ipsec_conf", new_callable=AsyncMock) as mock_upload,
        patch("app.services.s3.check_connectivity", new_callable=AsyncMock) as mock_check,
    ):
        mock_download.return_value = "# ipsec.conf test content"
        mock_upload.return_value = None
        mock_check.return_value = True
        yield {
            "download_ipsec_conf": mock_download,
            "upload_ipsec_conf": mock_upload,
            "check_connectivity": mock_check,
        }


@pytest.fixture
def mock_ssm_service():
    """Patch SSM service functions with AsyncMock."""
    with (
        patch("app.services.ssm.execute_command", new_callable=AsyncMock) as mock_exec,
        patch("app.services.ssm.reload_ipsec", new_callable=AsyncMock) as mock_reload,
        patch("app.services.ssm.run_on_instances", new_callable=AsyncMock) as mock_run,
        patch("app.services.ssm.resolve_instance_id", new_callable=AsyncMock) as mock_resolve,
        patch("app.services.ssm.check_connectivity", new_callable=AsyncMock) as mock_check,
    ):
        mock_exec.return_value = "command output"
        mock_reload.return_value = None
        mock_run.return_value = None
        mock_resolve.return_value = "i-0abc123def456"
        mock_check.return_value = True
        yield {
            "execute_command": mock_exec,
            "reload_ipsec": mock_reload,
            "run_on_instances": mock_run,
            "resolve_instance_id": mock_resolve,
            "check_connectivity": mock_check,
        }


@pytest.fixture
def mock_terragrunt_service():
    """Patch Terragrunt service functions with AsyncMock."""
    mock_repo = MagicMock()
    with (
        patch("app.services.terragrunt.ensure_repo", new_callable=AsyncMock) as mock_ensure,
        patch("app.services.terragrunt.add_route", new_callable=AsyncMock) as mock_add,
        patch("app.services.terragrunt.remove_route", new_callable=AsyncMock) as mock_remove,
        patch("app.services.terragrunt.check_connectivity", new_callable=AsyncMock) as mock_check,
    ):
        mock_ensure.return_value = mock_repo
        mock_add.return_value = None
        mock_remove.return_value = None
        mock_check.return_value = True
        yield {
            "ensure_repo": mock_ensure,
            "add_route": mock_add,
            "remove_route": mock_remove,
            "check_connectivity": mock_check,
        }
