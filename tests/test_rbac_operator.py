"""Tests for operator RBAC on existing endpoints.

Verifies:
- Operator can POST/PATCH/DELETE tunnels, routes, iptables
- Viewer cannot POST/PATCH/DELETE (gets 403)
- Admin retains full access
- Operator CANNOT access user management endpoints
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.db.models import User


def _make_mock_user(role: str = "admin", user_id: int = 1) -> User:
    user = MagicMock(spec=User)
    user.id = user_id
    user.sub = f"test-{role}-sub"
    user.email = f"{role}@test.com"
    user.display_name = f"Test {role.capitalize()}"
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


# ---------------------------------------------------------------------------
# Tunnel write operations — operator access
# ---------------------------------------------------------------------------

class TestOperatorTunnelAccess:
    """Operator can create, update, delete tunnels."""

    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.create_tunnel", new_callable=AsyncMock)
    async def test_operator_can_create_tunnel(self, mock_create, mock_get_tunnel):
        now = datetime.now(timezone.utc)
        mock_tunnel = MagicMock()
        mock_tunnel.id = 1
        mock_tunnel.name = "test-tunnel"
        mock_tunnel.description = None
        mock_tunnel.peer_ip = "203.0.113.1"
        mock_tunnel.local_cidrs = ["10.0.0.0/24"]
        mock_tunnel.remote_cidrs = ["192.168.1.0/24"]
        mock_tunnel.ike_version = "2"
        mock_tunnel.ike_proposals = None
        mock_tunnel.esp_proposals = None
        mock_tunnel.dpd_action = "restart"
        mock_tunnel.dpd_delay = 30
        mock_tunnel.dpd_timeout = 150
        mock_tunnel.status = "active"
        mock_tunnel.sync_status = "synced"
        mock_tunnel.sync_error = None
        mock_tunnel.created_by = 3
        mock_tunnel.created_at = now
        mock_tunnel.updated_at = now
        mock_tunnel.deleted_at = None
        mock_tunnel.routes = []
        mock_tunnel.iptables_rules = []
        mock_tunnel.creator = None
        mock_create.return_value = mock_tunnel
        mock_get_tunnel.return_value = mock_tunnel

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.post(
                "/api/v1/tunnels/",
                json={
                    "name": "test-tunnel",
                    "peer_ip": "203.0.113.1",
                    "local_cidrs": ["10.0.0.0/24"],
                    "remote_cidrs": ["192.168.1.0/24"],
                    "psk": "supersecret123",
                },
            )
        assert resp.status_code == 201

    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.update_tunnel", new_callable=AsyncMock)
    async def test_operator_can_update_tunnel(self, mock_update, mock_get_tunnel):
        now = datetime.now(timezone.utc)
        mock_tunnel = MagicMock()
        mock_tunnel.id = 1
        mock_tunnel.name = "updated-tunnel"
        mock_tunnel.description = None
        mock_tunnel.peer_ip = "203.0.113.1"
        mock_tunnel.local_cidrs = ["10.0.0.0/24"]
        mock_tunnel.remote_cidrs = ["192.168.1.0/24"]
        mock_tunnel.ike_version = "2"
        mock_tunnel.ike_proposals = None
        mock_tunnel.esp_proposals = None
        mock_tunnel.dpd_action = "restart"
        mock_tunnel.dpd_delay = 30
        mock_tunnel.dpd_timeout = 150
        mock_tunnel.status = "active"
        mock_tunnel.sync_status = "synced"
        mock_tunnel.sync_error = None
        mock_tunnel.created_by = 3
        mock_tunnel.created_at = now
        mock_tunnel.updated_at = now
        mock_tunnel.deleted_at = None
        mock_tunnel.routes = []
        mock_tunnel.iptables_rules = []
        mock_tunnel.creator = None
        mock_update.return_value = mock_tunnel
        mock_get_tunnel.return_value = mock_tunnel

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.patch(
                "/api/v1/tunnels/1",
                json={"name": "updated-tunnel"},
            )
        assert resp.status_code == 200

    @patch("app.services.tunnel_service.delete_tunnel", new_callable=AsyncMock)
    async def test_operator_can_delete_tunnel(self, mock_delete):
        mock_delete.return_value = None

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.delete("/api/v1/tunnels/1")
        assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Route write operations — operator access
# ---------------------------------------------------------------------------

class TestOperatorRouteAccess:
    """Operator can create, delete, retry routes."""

    @patch("app.services.route_service.create_route", new_callable=AsyncMock)
    async def test_operator_can_create_route(self, mock_create):
        mock_route = MagicMock()
        mock_op = MagicMock()
        mock_op.id = "00000000-0000-0000-0000-000000000001"
        mock_op.status = "pending"
        mock_create.return_value = (mock_route, mock_op)

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.post(
                "/api/v1/routes/?tunnel_id=1",
                json={"cidr": "10.0.1.0/24"},
            )
        assert resp.status_code == 202

    @patch("app.services.route_service.delete_route", new_callable=AsyncMock)
    async def test_operator_can_delete_route(self, mock_delete):
        mock_op = MagicMock()
        mock_op.id = "00000000-0000-0000-0000-000000000001"
        mock_op.status = "pending"
        mock_delete.return_value = mock_op

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.delete("/api/v1/routes/1")
        assert resp.status_code == 202

    @patch("app.services.route_service.retry_route", new_callable=AsyncMock)
    async def test_operator_can_retry_route(self, mock_retry):
        mock_op = MagicMock()
        mock_op.id = "00000000-0000-0000-0000-000000000001"
        mock_op.status = "pending"
        mock_retry.return_value = mock_op

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.post("/api/v1/routes/1/retry")
        assert resp.status_code == 202


# ---------------------------------------------------------------------------
# IPTables write operations — operator access
# ---------------------------------------------------------------------------

class TestOperatorIPTablesAccess:
    """Operator can create, update, delete, retry iptables rules."""

    @patch("app.services.iptables_service.create_rule", new_callable=AsyncMock)
    async def test_operator_can_create_iptables(self, mock_create):
        now = datetime.now(timezone.utc)
        mock_rule = MagicMock()
        mock_rule.id = 1
        mock_rule.tunnel_id = 1
        mock_rule.chain = "FORWARD"
        mock_rule.protocol = "tcp"
        mock_rule.source_cidr = "10.0.0.0/24"
        mock_rule.dest_cidr = "192.168.1.0/24"
        mock_rule.sport = None
        mock_rule.dport = 443
        mock_rule.action = "ACCEPT"
        mock_rule.state_match = None
        mock_rule.comment = "test rule"
        mock_rule.position = None
        mock_rule.sync_status = "synced"
        mock_rule.sync_error = None
        mock_rule.created_by = 3
        mock_rule.created_at = now
        mock_rule.updated_at = now
        mock_create.return_value = mock_rule

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.post(
                "/api/v1/iptables/?tunnel_id=1",
                json={
                    "chain": "FORWARD",
                    "protocol": "tcp",
                    "dest_cidr": "192.168.1.0/24",
                    "dport": 443,
                    "action": "ACCEPT",
                },
            )
        assert resp.status_code == 201

    @patch("app.services.iptables_service.update_rule", new_callable=AsyncMock)
    async def test_operator_can_update_iptables(self, mock_update):
        now = datetime.now(timezone.utc)
        mock_rule = MagicMock()
        mock_rule.id = 1
        mock_rule.tunnel_id = 1
        mock_rule.chain = "FORWARD"
        mock_rule.protocol = "tcp"
        mock_rule.source_cidr = None
        mock_rule.dest_cidr = "192.168.1.0/24"
        mock_rule.sport = None
        mock_rule.dport = 8080
        mock_rule.action = "ACCEPT"
        mock_rule.state_match = None
        mock_rule.comment = "updated"
        mock_rule.position = None
        mock_rule.sync_status = "synced"
        mock_rule.sync_error = None
        mock_rule.created_at = now
        mock_rule.updated_at = now
        mock_update.return_value = mock_rule

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.patch(
                "/api/v1/iptables/1",
                json={"dport": 8080},
            )
        assert resp.status_code == 200

    @patch("app.services.iptables_service.delete_rule", new_callable=AsyncMock)
    async def test_operator_can_delete_iptables(self, mock_delete):
        mock_delete.return_value = None

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.delete("/api/v1/iptables/1")
        assert resp.status_code == 204

    @patch("app.services.iptables_service.retry_rule", new_callable=AsyncMock)
    async def test_operator_can_retry_iptables(self, mock_retry):
        now = datetime.now(timezone.utc)
        mock_rule = MagicMock()
        mock_rule.id = 1
        mock_rule.tunnel_id = 1
        mock_rule.chain = "FORWARD"
        mock_rule.protocol = "tcp"
        mock_rule.source_cidr = None
        mock_rule.dest_cidr = None
        mock_rule.sport = None
        mock_rule.dport = 443
        mock_rule.action = "ACCEPT"
        mock_rule.state_match = None
        mock_rule.comment = None
        mock_rule.position = None
        mock_rule.sync_status = "synced"
        mock_rule.sync_error = None
        mock_rule.created_at = now
        mock_rule.updated_at = now
        mock_retry.return_value = mock_rule

        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.post("/api/v1/iptables/1/retry")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Viewer cannot write — 403 on all write endpoints
# ---------------------------------------------------------------------------

class TestViewerCannotWrite:
    """Viewer should get 403 on all POST/PATCH/DELETE endpoints."""

    async def test_viewer_cannot_create_tunnel(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.post(
                "/api/v1/tunnels/",
                json={
                    "name": "test",
                    "peer_ip": "1.2.3.4",
                    "local_cidrs": ["10.0.0.0/24"],
                    "remote_cidrs": ["10.1.0.0/24"],
                    "psk": "secret123456",
                },
            )
        assert resp.status_code == 403

    async def test_viewer_cannot_update_tunnel(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.patch(
                "/api/v1/tunnels/1",
                json={"name": "new-name"},
            )
        assert resp.status_code == 403

    async def test_viewer_cannot_delete_tunnel(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.delete("/api/v1/tunnels/1")
        assert resp.status_code == 403

    async def test_viewer_cannot_create_route(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.post(
                "/api/v1/routes/?tunnel_id=1",
                json={"cidr": "10.0.1.0/24"},
            )
        assert resp.status_code == 403

    async def test_viewer_cannot_delete_route(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.delete("/api/v1/routes/1")
        assert resp.status_code == 403

    async def test_viewer_cannot_create_iptables(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.post(
                "/api/v1/iptables/?tunnel_id=1",
                json={
                    "chain": "FORWARD",
                    "protocol": "tcp",
                    "dport": 443,
                    "action": "ACCEPT",
                },
            )
        assert resp.status_code == 403

    async def test_viewer_cannot_update_iptables(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.patch(
                "/api/v1/iptables/1",
                json={"dport": 8080},
            )
        assert resp.status_code == 403

    async def test_viewer_cannot_delete_iptables(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.delete("/api/v1/iptables/1")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Operator cannot access user management
# ---------------------------------------------------------------------------

class TestOperatorCannotAccessUsers:
    """Operator should get 403 on user management endpoints."""

    async def test_operator_cannot_list_users(self):
        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.get("/api/v1/users/")
        assert resp.status_code == 403

    async def test_operator_cannot_get_user(self):
        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.get("/api/v1/users/1")
        assert resp.status_code == 403

    async def test_operator_cannot_update_user(self):
        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.patch(
                "/api/v1/users/1",
                json={"role": "viewer"},
            )
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Admin retains full access (sanity check)
# ---------------------------------------------------------------------------

class TestAdminFullAccess:
    """Admin should still have full access to write operations."""

    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.create_tunnel", new_callable=AsyncMock)
    async def test_admin_can_create_tunnel(self, mock_create, mock_get_tunnel):
        now = datetime.now(timezone.utc)
        mock_tunnel = MagicMock()
        mock_tunnel.id = 1
        mock_tunnel.name = "test-tunnel"
        mock_tunnel.description = None
        mock_tunnel.peer_ip = "203.0.113.1"
        mock_tunnel.local_cidrs = ["10.0.0.0/24"]
        mock_tunnel.remote_cidrs = ["192.168.1.0/24"]
        mock_tunnel.ike_version = "2"
        mock_tunnel.ike_proposals = None
        mock_tunnel.esp_proposals = None
        mock_tunnel.dpd_action = "restart"
        mock_tunnel.dpd_delay = 30
        mock_tunnel.dpd_timeout = 150
        mock_tunnel.status = "active"
        mock_tunnel.sync_status = "synced"
        mock_tunnel.sync_error = None
        mock_tunnel.created_by = 1
        mock_tunnel.created_at = now
        mock_tunnel.updated_at = now
        mock_tunnel.deleted_at = None
        mock_tunnel.routes = []
        mock_tunnel.iptables_rules = []
        mock_tunnel.creator = None
        mock_create.return_value = mock_tunnel
        mock_get_tunnel.return_value = mock_tunnel

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.post(
                "/api/v1/tunnels/",
                json={
                    "name": "test-tunnel",
                    "peer_ip": "203.0.113.1",
                    "local_cidrs": ["10.0.0.0/24"],
                    "remote_cidrs": ["192.168.1.0/24"],
                    "psk": "supersecret123",
                },
            )
        assert resp.status_code == 201
