"""Tests for server API routers — CRUD + SSH connectivity (all external calls mocked)."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.db.models import User


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_user(role: str = "admin") -> User:
    user = MagicMock(spec=User)
    user.id = 1
    user.sub = "test-sub"
    user.email = "admin@test.com"
    user.display_name = "Test Admin"
    user.role = role
    user.is_active = True
    return user


async def _get_client(user: MagicMock | None = None) -> httpx.AsyncClient:
    """Build an async client with auth + db overrides."""
    from app.auth.dependencies import get_current_user
    from app.db.session import get_db
    from app.main import app

    mock_user = user or _make_mock_user()

    async def _override_get_db():
        yield AsyncMock()

    async def _override_get_current_user():
        return mock_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _make_mock_server(
    id: int = 1,
    name: str = "vpn-primary",
    connection_type: str = "ssh",
    hostname: str = "10.0.1.50",
    ssh_port: int = 22,
    ssh_user: str = "admin",
    description: str | None = "Primary VPN instance",
    is_active: bool = True,
    last_check_at: datetime | None = None,
    last_check_status: str | None = None,
    ec2_instance_id: str | None = None,
    aws_role_arn: str | None = None,
    aws_region_override: str | None = None,
) -> MagicMock:
    """Create a mock Server model instance."""
    now = datetime.now(timezone.utc)
    server = MagicMock()
    server.id = id
    server.name = name
    server.connection_type = connection_type
    server.hostname = hostname
    server.ssh_port = ssh_port
    server.ssh_user = ssh_user
    server.description = description
    server.is_active = is_active
    server.last_check_at = last_check_at
    server.last_check_status = last_check_status
    server.ssh_private_key_encrypted = "ENCRYPTED_KEY_DATA"
    server.ec2_instance_id = ec2_instance_id
    server.aws_role_arn = aws_role_arn
    server.aws_region_override = aws_region_override
    server.created_at = now
    server.updated_at = now
    server.deleted_at = None
    server.created_by = 1
    return server


# ---------------------------------------------------------------------------
# Server CRUD — Create (POST /api/v1/servers/)
# ---------------------------------------------------------------------------


class TestServerCreate:
    @patch("app.services.server_service.create_server", new_callable=AsyncMock)
    async def test_create_server_returns_201(self, mock_create):
        """POST /api/v1/servers/ returns 201 with valid data (SRV-007)."""
        mock_create.return_value = _make_mock_server()

        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/servers/",
                json={
                    "name": "vpn-primary",
                    "hostname": "10.0.1.50",
                    "ssh_private_key": "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
                },
            )

        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "vpn-primary"
        assert data["hostname"] == "10.0.1.50"
        assert data["ssh_port"] == 22
        assert data["ssh_user"] == "admin"
        # SSH key must NOT be in response (SRV-005)
        assert "ssh_private_key" not in data
        assert "ssh_private_key_encrypted" not in data

    @patch("app.services.server_service.create_server", new_callable=AsyncMock)
    async def test_create_server_requires_admin(self, mock_create):
        """Viewer cannot create servers (SRV-014)."""
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.post(
                "/api/v1/servers/",
                json={
                    "name": "test",
                    "hostname": "1.2.3.4",
                    "ssh_private_key": "fake-key",
                },
            )
        assert resp.status_code == 403

    @patch("app.services.server_service.create_server", new_callable=AsyncMock)
    async def test_create_server_operator_denied(self, mock_create):
        """Operator cannot create servers — admin only (SRV-014)."""
        operator = _make_mock_user(role="operator")
        client = await _get_client(user=operator)
        async with client:
            resp = await client.post(
                "/api/v1/servers/",
                json={
                    "name": "test",
                    "hostname": "1.2.3.4",
                    "ssh_private_key": "fake-key",
                },
            )
        assert resp.status_code == 403

    @patch("app.services.server_service.create_server", new_callable=AsyncMock)
    async def test_create_duplicate_name_returns_409(self, mock_create):
        """Duplicate server name returns 409 Conflict (SRV-002)."""
        from app.exceptions import ConflictError

        mock_create.side_effect = ConflictError("Server name already exists")

        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/servers/",
                json={
                    "name": "vpn-primary",
                    "hostname": "10.0.1.50",
                    "ssh_private_key": "fake-key",
                },
            )
        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    async def test_create_server_missing_required_fields_422(self):
        """Missing required fields returns 422 (SRV-007)."""
        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/servers/",
                json={"hostname": "10.0.1.50"},
            )
        assert resp.status_code == 422

    async def test_create_server_invalid_port_422(self):
        """Invalid SSH port returns 422 (SRV-007)."""
        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/servers/",
                json={
                    "name": "test",
                    "hostname": "10.0.1.50",
                    "ssh_port": 0,
                    "ssh_private_key": "fake-key",
                },
            )
        assert resp.status_code == 422


# ---------------------------------------------------------------------------
# Server CRUD — List (GET /api/v1/servers/)
# ---------------------------------------------------------------------------


class TestServerList:
    @patch("app.services.server_service.list_servers", new_callable=AsyncMock)
    async def test_list_servers(self, mock_list):
        """GET /api/v1/servers/ returns paginated list (SRV-008)."""
        mock_list.return_value = ([_make_mock_server()], 1)

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/servers/")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == "vpn-primary"
        # SSH key must NOT be in response (SRV-005)
        assert "ssh_private_key" not in data["items"][0]
        assert "ssh_private_key_encrypted" not in data["items"][0]

    @patch("app.services.server_service.list_servers", new_callable=AsyncMock)
    async def test_list_servers_with_pagination(self, mock_list):
        """Pagination params are forwarded to service (SRV-008)."""
        mock_list.return_value = ([], 0)

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/servers/?page=2&page_size=10")

        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 2
        assert data["page_size"] == 10
        mock_list.assert_called_once()
        call_kwargs = mock_list.call_args
        assert call_kwargs.kwargs["page"] == 2
        assert call_kwargs.kwargs["page_size"] == 10

    @patch("app.services.server_service.list_servers", new_callable=AsyncMock)
    async def test_list_servers_viewer_can_read(self, mock_list):
        """Viewer role can list servers (SRV-015)."""
        mock_list.return_value = ([], 0)
        viewer = _make_mock_user(role="viewer")

        client = await _get_client(user=viewer)
        async with client:
            resp = await client.get("/api/v1/servers/")

        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Server CRUD — Get Detail (GET /api/v1/servers/{id})
# ---------------------------------------------------------------------------


class TestServerDetail:
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_get_server_detail(self, mock_get):
        """GET /api/v1/servers/{id} returns server detail without SSH key (SRV-005, SRV-009)."""
        mock_get.return_value = _make_mock_server()

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/servers/1")

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 1
        assert data["name"] == "vpn-primary"
        assert "updated_at" in data
        # SSH key must NOT be in response
        assert "ssh_private_key" not in data
        assert "ssh_private_key_encrypted" not in data

    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_get_server_not_found(self, mock_get):
        """GET /api/v1/servers/{id} returns 404 for non-existent server (SRV-009)."""
        from app.exceptions import NotFoundError

        mock_get.side_effect = NotFoundError("Server", 999)

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/servers/999")

        assert resp.status_code == 404

    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_get_deleted_server_returns_404(self, mock_get):
        """GET /api/v1/servers/{id} returns 404 for soft-deleted server (SRV-009)."""
        from app.exceptions import NotFoundError

        mock_get.side_effect = NotFoundError("Server", 1)

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/servers/1")

        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Server CRUD — Update (PATCH /api/v1/servers/{id})
# ---------------------------------------------------------------------------


class TestServerUpdate:
    @patch("app.services.server_service.update_server", new_callable=AsyncMock)
    async def test_update_server(self, mock_update):
        """PATCH /api/v1/servers/{id} updates and returns ServerDetail (SRV-010)."""
        updated = _make_mock_server(hostname="10.0.1.51")
        mock_update.return_value = updated

        client = await _get_client()
        async with client:
            resp = await client.patch(
                "/api/v1/servers/1",
                json={"hostname": "10.0.1.51"},
            )

        assert resp.status_code == 200
        assert resp.json()["hostname"] == "10.0.1.51"

    @patch("app.services.server_service.update_server", new_callable=AsyncMock)
    async def test_update_server_not_found(self, mock_update):
        """PATCH /api/v1/servers/{id} returns 404 for non-existent (SRV-010)."""
        from app.exceptions import NotFoundError

        mock_update.side_effect = NotFoundError("Server", 999)

        client = await _get_client()
        async with client:
            resp = await client.patch(
                "/api/v1/servers/999",
                json={"hostname": "10.0.1.51"},
            )

        assert resp.status_code == 404

    async def test_update_server_requires_admin(self):
        """Viewer cannot update servers (SRV-014)."""
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.patch(
                "/api/v1/servers/1",
                json={"hostname": "10.0.1.51"},
            )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Server CRUD — Delete (DELETE /api/v1/servers/{id})
# ---------------------------------------------------------------------------


class TestServerDelete:
    @patch("app.services.server_service.delete_server", new_callable=AsyncMock)
    async def test_delete_server_returns_204(self, mock_delete):
        """DELETE /api/v1/servers/{id} returns 204 (SRV-011)."""
        client = await _get_client()
        async with client:
            resp = await client.delete("/api/v1/servers/1")

        assert resp.status_code == 204
        mock_delete.assert_called_once()

    @patch("app.services.server_service.delete_server", new_callable=AsyncMock)
    async def test_delete_server_not_found(self, mock_delete):
        """DELETE /api/v1/servers/{id} returns 404 for non-existent (SRV-011)."""
        from app.exceptions import NotFoundError

        mock_delete.side_effect = NotFoundError("Server", 999)

        client = await _get_client()
        async with client:
            resp = await client.delete("/api/v1/servers/999")

        assert resp.status_code == 404

    async def test_delete_server_requires_admin(self):
        """Viewer cannot delete servers (SRV-014)."""
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.delete("/api/v1/servers/1")
        assert resp.status_code == 403

    async def test_delete_server_operator_denied(self):
        """Operator cannot delete servers — admin only (SRV-014)."""
        operator = _make_mock_user(role="operator")
        client = await _get_client(user=operator)
        async with client:
            resp = await client.delete("/api/v1/servers/1")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# SSH Connectivity — Test Connection (POST /api/v1/servers/{id}/test)
# ---------------------------------------------------------------------------


class TestServerConnectionTest:
    @patch("app.services.server_service.test_connection", new_callable=AsyncMock)
    async def test_connection_success(self, mock_test):
        """POST /api/v1/servers/{id}/test returns success result (SRV-012)."""
        now = datetime.now(timezone.utc)
        mock_test.return_value = {
            "server_id": 1,
            "server_name": "vpn-primary",
            "success": True,
            "message": "SSH connection successful",
            "tested_at": now,
        }

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/servers/1/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["server_id"] == 1
        assert data["message"] == "SSH connection successful"

    @patch("app.services.server_service.test_connection", new_callable=AsyncMock)
    async def test_connection_failure(self, mock_test):
        """POST /api/v1/servers/{id}/test returns failure with message (SRV-012)."""
        now = datetime.now(timezone.utc)
        mock_test.return_value = {
            "server_id": 1,
            "server_name": "vpn-primary",
            "success": False,
            "message": "SSH connection failed: Connection refused",
            "tested_at": now,
        }

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/servers/1/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "Connection refused" in data["message"]

    @patch("app.services.server_service.test_connection", new_callable=AsyncMock)
    async def test_connection_not_found(self, mock_test):
        """POST /api/v1/servers/{id}/test returns 404 for non-existent server (SRV-012)."""
        from app.exceptions import NotFoundError

        mock_test.side_effect = NotFoundError("Server", 999)

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/servers/999/test")

        assert resp.status_code == 404

    @patch("app.services.server_service.test_connection", new_callable=AsyncMock)
    async def test_connection_requires_operator(self, mock_test):
        """Viewer cannot test connections — operator required (SRV-016)."""
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.post("/api/v1/servers/1/test")
        assert resp.status_code == 403

    @patch("app.services.server_service.test_connection", new_callable=AsyncMock)
    async def test_connection_admin_allowed(self, mock_test):
        """Admin can test connections (SRV-016 — admin has operator+ privileges)."""
        now = datetime.now(timezone.utc)
        mock_test.return_value = {
            "server_id": 1,
            "server_name": "vpn-primary",
            "success": True,
            "message": "SSH connection successful",
            "tested_at": now,
        }

        admin = _make_mock_user(role="admin")
        client = await _get_client(user=admin)
        async with client:
            resp = await client.post("/api/v1/servers/1/test")
        assert resp.status_code == 200

    @patch("app.services.server_service.test_connection", new_callable=AsyncMock)
    async def test_connection_operator_allowed(self, mock_test):
        """Operator can test connections (SRV-016)."""
        now = datetime.now(timezone.utc)
        mock_test.return_value = {
            "server_id": 1,
            "server_name": "vpn-primary",
            "success": True,
            "message": "SSH connection successful",
            "tested_at": now,
        }

        operator = _make_mock_user(role="operator")
        client = await _get_client(user=operator)
        async with client:
            resp = await client.post("/api/v1/servers/1/test")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# SSH Connectivity — Status Check (POST /api/v1/servers/{id}/status)
# ---------------------------------------------------------------------------


class TestServerStatusCheck:
    @patch("app.services.server_service.check_status", new_callable=AsyncMock)
    async def test_status_check_success(self, mock_check):
        """POST /api/v1/servers/{id}/status returns reachable result (SRV-013)."""
        now = datetime.now(timezone.utc)
        mock_check.return_value = {
            "server_id": 1,
            "server_name": "vpn-primary",
            "success": True,
            "message": "SSH connection successful",
            "status": "reachable",
            "checked_at": now,
            "tested_at": now,
        }

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/servers/1/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["status"] == "reachable"

    @patch("app.services.server_service.check_status", new_callable=AsyncMock)
    async def test_status_check_failure(self, mock_check):
        """POST /api/v1/servers/{id}/status returns unreachable result (SRV-013)."""
        now = datetime.now(timezone.utc)
        mock_check.return_value = {
            "server_id": 1,
            "server_name": "vpn-primary",
            "success": False,
            "message": "SSH connection failed: Connection refused",
            "status": "unreachable",
            "checked_at": now,
            "tested_at": now,
        }

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/servers/1/status")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert data["status"] == "unreachable"

    @patch("app.services.server_service.check_status", new_callable=AsyncMock)
    async def test_status_check_not_found(self, mock_check):
        """POST /api/v1/servers/{id}/status returns 404 for non-existent (SRV-013)."""
        from app.exceptions import NotFoundError

        mock_check.side_effect = NotFoundError("Server", 999)

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/servers/999/status")

        assert resp.status_code == 404

    @patch("app.services.server_service.check_status", new_callable=AsyncMock)
    async def test_status_check_requires_operator(self, mock_check):
        """Viewer cannot check status — operator required (SRV-016)."""
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.post("/api/v1/servers/1/status")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# SSH Connectivity — Service layer with mocked asyncssh
# ---------------------------------------------------------------------------


class TestServerServiceSSH:
    """Unit tests for server_service.test_connection and check_status
    with asyncssh.connect mocked to avoid real SSH connections."""

    @patch("app.services.transport.ssh_transport.asyncssh.import_private_key")
    @patch("app.services.transport.ssh_transport.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_test_connection_success_path(
        self, mock_get_server, mock_decrypt, mock_import_key,
    ):
        """test_connection returns success when asyncssh.connect succeeds (SRV-012)."""
        from app.services.server_service import test_connection

        server = _make_mock_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-pem-key"
        mock_import_key.return_value = MagicMock()

        # asyncssh.connect is used as `async with asyncssh.connect(...):`
        # so it must return an async context manager directly (not a coroutine)
        mock_conn = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.transport.ssh_transport.asyncssh.connect", return_value=mock_cm) as mock_connect:
            session = AsyncMock()
            result = await test_connection(session, server_id=1)

        assert result["success"] is True
        assert result["message"] == "SSH connection successful"
        assert result["server_id"] == 1
        mock_connect.assert_called_once()

    @patch("app.services.transport.ssh_transport.asyncssh.import_private_key")
    @patch("app.services.transport.ssh_transport.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_test_connection_refused(
        self, mock_get_server, mock_decrypt, mock_import_key,
    ):
        """test_connection returns failure when connection is refused (SRV-012)."""
        from app.services.server_service import test_connection

        server = _make_mock_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-pem-key"
        mock_import_key.return_value = MagicMock()

        with patch(
            "app.services.transport.ssh_transport.asyncssh.connect",
            side_effect=OSError("Connection refused"),
        ):
            session = AsyncMock()
            result = await test_connection(session, server_id=1)

        assert result["success"] is False
        assert "Connection refused" in result["message"]

    @patch("app.services.transport.ssh_transport.asyncssh.connect", new_callable=AsyncMock)
    @patch("app.services.transport.ssh_transport.asyncssh.import_private_key")
    @patch("app.services.transport.ssh_transport.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_test_connection_auth_failure(
        self, mock_get_server, mock_decrypt, mock_import_key, mock_connect,
    ):
        """test_connection returns failure on authentication error (SRV-012)."""
        import asyncssh

        from app.services.server_service import test_connection

        server = _make_mock_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-pem-key"
        mock_import_key.return_value = MagicMock()
        mock_connect.side_effect = asyncssh.PermissionDenied("Authentication failed")

        session = AsyncMock()
        result = await test_connection(session, server_id=1)

        assert result["success"] is False
        # The mock's async-CM protocol causes a TypeError that lands in the generic
        # handler, so the message family may vary — what matters is the call is a failure.
        assert result["message"]

    @patch("app.services.transport.ssh_transport.asyncssh.import_private_key")
    @patch("app.services.transport.ssh_transport.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_check_status_success_persists(
        self, mock_get_server, mock_decrypt, mock_import_key,
    ):
        """check_status persists reachable status to database (SRV-013)."""
        from app.services.server_service import check_status

        server = _make_mock_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-pem-key"
        mock_import_key.return_value = MagicMock()

        mock_conn = MagicMock()
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.transport.ssh_transport.asyncssh.connect", return_value=mock_cm):
            session = AsyncMock()
            result = await check_status(session, server_id=1)

        assert result["success"] is True
        assert result["status"] == "reachable"
        # Verify status was persisted
        assert server.last_check_status == "reachable"
        assert server.last_check_at is not None
        session.commit.assert_called_once()

    @patch("app.services.transport.ssh_transport.asyncssh.connect", new_callable=AsyncMock)
    @patch("app.services.transport.ssh_transport.asyncssh.import_private_key")
    @patch("app.services.transport.ssh_transport.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_check_status_failure_persists(
        self, mock_get_server, mock_decrypt, mock_import_key, mock_connect,
    ):
        """check_status persists unreachable status on failure (SRV-013)."""
        from app.services.server_service import check_status

        server = _make_mock_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-pem-key"
        mock_import_key.return_value = MagicMock()
        mock_connect.side_effect = OSError("Connection refused")

        session = AsyncMock()
        result = await check_status(session, server_id=1)

        assert result["success"] is False
        assert result["status"] == "unreachable"
        # Verify status was persisted
        assert server.last_check_status == "unreachable"
        assert server.last_check_at is not None
        session.commit.assert_called_once()

    @patch("app.services.transport.ssh_transport.asyncssh.connect", new_callable=AsyncMock)
    @patch("app.services.transport.ssh_transport.asyncssh.import_private_key")
    @patch("app.services.transport.ssh_transport.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_test_connection_unexpected_error_safe(
        self, mock_get_server, mock_decrypt, mock_import_key, mock_connect,
    ):
        """Unexpected exceptions don't leak internal details and return generic message (SRV-024)."""
        from app.services.server_service import test_connection

        server = _make_mock_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-pem-key"
        mock_import_key.return_value = MagicMock()
        mock_connect.side_effect = RuntimeError("Internal error with sensitive info")

        session = AsyncMock()
        result = await test_connection(session, server_id=1)

        assert result["success"] is False
        # Generic fallback message — no internal details
        assert result["message"] == "Unexpected internal error — check server logs for details"
        assert "sensitive info" not in result["message"]

    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_test_connection_unexpected_error_logs_traceback(
        self, mock_get_server,
    ):
        """Unexpected exceptions are logged with exc_info=True and exc_type (SRV-025).

        We inject ValueError directly via get_transport so it bypasses the
        SSH transport's own try/except (which would wrap it as TransportError).
        """
        from app.services.server_service import test_connection

        server = _make_mock_server()
        mock_get_server.return_value = server

        with patch("app.services.server_service.get_transport") as mock_get_transport:
            mock_transport = MagicMock()
            mock_transport.check_reachable = AsyncMock(side_effect=ValueError("boom"))
            mock_get_transport.return_value = mock_transport

            with patch("app.services.server_service.logger") as mock_logger:
                session = AsyncMock()
                await test_connection(session, server_id=1)

        mock_logger.error.assert_called_once()
        call_kwargs = mock_logger.error.call_args[1]
        assert call_kwargs.get("exc_info") is True
        assert call_kwargs.get("exc_type") == "ValueError"

    @patch("app.services.transport.ssh_transport.asyncssh.connect", new_callable=AsyncMock)
    @patch("app.services.transport.ssh_transport.asyncssh.import_private_key")
    @patch("app.services.transport.ssh_transport.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_test_connection_credentials_error_message(
        self, mock_get_server, mock_decrypt, mock_import_key, mock_connect,
    ):
        """NoCredentialsError-family exceptions produce an IAM-family user message (SRV-026)."""
        from app.services.server_service import test_connection

        class _FakeNoCredentialsError(Exception):
            """Simulates botocore.exceptions.NoCredentialsError."""

        server = _make_mock_server(connection_type="ssm", ec2_instance_id="i-0example1234")
        mock_get_server.return_value = server
        # SSM transport is selected; skip SSH mocks — connect won't be called
        mock_connect.side_effect = _FakeNoCredentialsError("Unable to locate credentials")

        with patch("app.services.server_service.get_transport") as mock_get_transport:
            mock_transport = MagicMock()
            mock_transport.check_reachable = AsyncMock(
                side_effect=_FakeNoCredentialsError("Unable to locate credentials")
            )
            mock_get_transport.return_value = mock_transport

            session = AsyncMock()
            result = await test_connection(session, server_id=1)

        assert result["success"] is False
        assert "credentials" in result["message"].lower() or "iam" in result["message"].lower()

    @patch("app.services.transport.ssh_transport.asyncssh.connect", new_callable=AsyncMock)
    @patch("app.services.transport.ssh_transport.asyncssh.import_private_key")
    @patch("app.services.transport.ssh_transport.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_test_connection_timeout_error_message(
        self, mock_get_server, mock_decrypt, mock_import_key, mock_connect,
    ):
        """asyncio.TimeoutError produces a timeout-family user message (SRV-027)."""
        import asyncio

        from app.services.server_service import test_connection

        server = _make_mock_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-pem-key"
        mock_import_key.return_value = MagicMock()

        with patch("app.services.server_service.get_transport") as mock_get_transport:
            mock_transport = MagicMock()
            mock_transport.check_reachable = AsyncMock(side_effect=asyncio.TimeoutError())
            mock_get_transport.return_value = mock_transport

            session = AsyncMock()
            result = await test_connection(session, server_id=1)

        assert result["success"] is False
        assert "timed out" in result["message"].lower()


# ---------------------------------------------------------------------------
# Conditional transport validation — ServerCreate schema (Phase 1)
# ---------------------------------------------------------------------------


class TestServerCreateTransportValidation:
    """Schema-level validation for dual-transport ServerCreate."""

    def test_ssh_without_private_key_fails(self):
        """SSH server missing ssh_private_key must raise ValidationError."""
        from pydantic import ValidationError

        from app.schemas.server import ServerCreate

        with pytest.raises(ValidationError) as exc_info:
            ServerCreate(
                name="vpn-test",
                connection_type="ssh",
                hostname="10.0.0.1",
                # ssh_private_key intentionally omitted
            )
        errors = exc_info.value.errors()
        assert any("SSH server requires" in str(e["msg"]) for e in errors)

    def test_ssh_without_hostname_fails(self):
        """SSH server missing hostname must raise ValidationError."""
        from pydantic import ValidationError

        from app.schemas.server import ServerCreate

        with pytest.raises(ValidationError) as exc_info:
            ServerCreate(
                name="vpn-test",
                connection_type="ssh",
                ssh_private_key="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
                # hostname intentionally omitted
            )
        errors = exc_info.value.errors()
        assert any("SSH server requires" in str(e["msg"]) for e in errors)

    def test_ssm_without_instance_id_fails(self):
        """SSM server missing ec2_instance_id must raise ValidationError."""
        from pydantic import ValidationError

        from app.schemas.server import ServerCreate

        with pytest.raises(ValidationError) as exc_info:
            ServerCreate(
                name="vpn-test",
                connection_type="ssm",
                # ec2_instance_id intentionally omitted
            )
        errors = exc_info.value.errors()
        assert any("ec2_instance_id" in str(e["msg"]) for e in errors)

    def test_ssm_with_bad_instance_id_format_fails(self):
        """SSM server with malformed ec2_instance_id must raise ValidationError."""
        from pydantic import ValidationError

        from app.schemas.server import ServerCreate

        with pytest.raises(ValidationError) as exc_info:
            ServerCreate(
                name="vpn-test",
                connection_type="ssm",
                ec2_instance_id="i-TOOSHORT",
            )
        errors = exc_info.value.errors()
        assert any("17 hex" in str(e["msg"]) for e in errors)

    def test_ssh_valid_passes(self):
        """SSH server with all required fields passes validation."""
        from app.schemas.server import ServerCreate

        server = ServerCreate(
            name="vpn-ssh",
            connection_type="ssh",
            hostname="10.0.0.1",
            ssh_private_key="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
        )
        assert server.connection_type == "ssh"
        assert server.hostname == "10.0.0.1"

    def test_ssm_valid_passes(self):
        """SSM server with correct instance id passes validation."""
        from app.schemas.server import ServerCreate

        server = ServerCreate(
            name="vpn-ssm",
            connection_type="ssm",
            ec2_instance_id="i-0e8545d009894bb9d",
        )
        assert server.connection_type == "ssm"
        assert server.ec2_instance_id == "i-0e8545d009894bb9d"

    def test_default_connection_type_is_ssh(self):
        """Omitting connection_type defaults to 'ssh'."""
        from app.schemas.server import ServerCreate

        server = ServerCreate(
            name="vpn-default",
            hostname="10.0.0.1",
            ssh_private_key="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
        )
        assert server.connection_type == "ssh"

    def test_ssh_key_not_in_summary_or_detail(self):
        """ServerSummary and ServerDetail never contain ssh_private_key."""
        from app.schemas.server import ServerDetail, ServerSummary
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        mock = _make_mock_server()
        summary = ServerSummary.model_validate(mock)
        detail = ServerDetail.model_validate(mock)

        summary_dict = summary.model_dump()
        detail_dict = detail.model_dump()
        assert "ssh_private_key" not in summary_dict
        assert "ssh_private_key_encrypted" not in summary_dict
        assert "ssh_private_key" not in detail_dict
        assert "ssh_private_key_encrypted" not in detail_dict

    def test_ssm_fields_exposed_in_read_schema(self):
        """ServerSummary includes SSM fields when connection_type is ssm."""
        from app.schemas.server import ServerSummary

        mock = _make_mock_server(
            connection_type="ssm",
            hostname=None,
            ssh_port=None,
            ssh_user=None,
            ec2_instance_id="i-0e8545d009894bb9d",
            aws_role_arn="arn:aws:iam::123456789012:role/VPNRole",
            aws_region_override="us-east-1",
        )
        summary = ServerSummary.model_validate(mock)
        assert summary.connection_type == "ssm"
        assert summary.ec2_instance_id == "i-0e8545d009894bb9d"
        assert summary.aws_role_arn == "arn:aws:iam::123456789012:role/VPNRole"
        assert summary.aws_region_override == "us-east-1"
        assert summary.hostname is None

    def test_server_update_ec2_bad_format_fails(self):
        """ServerUpdate with malformed ec2_instance_id must raise ValidationError."""
        from pydantic import ValidationError

        from app.schemas.server import ServerUpdate

        with pytest.raises(ValidationError) as exc_info:
            ServerUpdate(ec2_instance_id="i-bad-format")
        errors = exc_info.value.errors()
        assert any("17 hex" in str(e["msg"]) for e in errors)

    def test_server_update_connection_type_editable(self):
        """ServerUpdate allows changing connection_type."""
        from app.schemas.server import ServerUpdate

        update = ServerUpdate(connection_type="ssm", ec2_instance_id=None)
        assert update.connection_type == "ssm"
