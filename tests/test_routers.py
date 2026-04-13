"""Tests for API routers — tunnels, routes, dashboard, health, operations."""
from __future__ import annotations

import uuid
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


# ---------------------------------------------------------------------------
# Health endpoints
# ---------------------------------------------------------------------------


class TestHealthRouter:
    async def test_health_liveness(self):
        client = await _get_client()
        async with client:
            resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ok"

    @patch("app.routers.health.ssm.check_connectivity", new_callable=AsyncMock, return_value=True)
    @patch("app.routers.health.s3.check_connectivity", new_callable=AsyncMock, return_value=True)
    async def test_health_readiness_all_ok(self, mock_s3, mock_ssm):
        client = await _get_client()
        async with client:
            # Mock the DB execute for SELECT 1
            with patch("app.routers.health.get_db") as mock_get_db:
                mock_session = AsyncMock()
                mock_session.execute.return_value = MagicMock()

                async def _override():
                    yield mock_session

                from app.main import app
                from app.db.session import get_db
                app.dependency_overrides[get_db] = _override

                resp = await client.get("/health/ready")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert data["checks"]["s3"] == "ok"
        assert data["checks"]["ssm"] == "ok"


# ---------------------------------------------------------------------------
# Tunnel router — list
# ---------------------------------------------------------------------------


class TestTunnelRouter:
    @patch("app.services.tunnel_service.list_tunnels", new_callable=AsyncMock)
    async def test_list_tunnels(self, mock_list):
        now = datetime.now(timezone.utc)
        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "test-tunnel"
        tunnel.peer_ip = "203.0.113.1"
        tunnel.status = "active"
        tunnel.sync_status = "synced"
        tunnel.sync_error = None
        tunnel.routes = []
        tunnel.iptables_rules = []
        tunnel.created_at = now
        mock_list.return_value = ([tunnel], 1)

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/tunnels/")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["items"][0]["name"] == "test-tunnel"
        assert data["items"][0]["route_count"] == 0

    @patch("app.services.tunnel_service.list_tunnels", new_callable=AsyncMock)
    async def test_list_tunnels_with_pagination(self, mock_list):
        mock_list.return_value = ([], 0)

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/tunnels/?page=2&page_size=10")

        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 2
        assert data["page_size"] == 10
        mock_list.assert_called_once()
        call_kwargs = mock_list.call_args
        assert call_kwargs.kwargs["page"] == 2
        assert call_kwargs.kwargs["page_size"] == 10

    @patch("app.services.tunnel_service.create_tunnel", new_callable=AsyncMock)
    async def test_create_tunnel_returns_201(self, mock_create):
        now = datetime.now(timezone.utc)
        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "new-tunnel"
        tunnel.description = None
        tunnel.peer_ip = "203.0.113.1"
        tunnel.local_cidrs = ["10.0.0.0/24"]
        tunnel.remote_cidrs = ["192.168.1.0/24"]
        tunnel.psk = "vpn/psk"
        tunnel.ike_version = "2"
        tunnel.ike_proposals = None
        tunnel.esp_proposals = None
        tunnel.dpd_action = "restart"
        tunnel.dpd_delay = 30
        tunnel.dpd_timeout = 150
        tunnel.status = "active"
        tunnel.sync_status = "synced"
        tunnel.sync_error = None
        tunnel.routes = []
        tunnel.iptables_rules = []
        tunnel.creator = None
        tunnel.created_at = now
        tunnel.updated_at = now
        mock_create.return_value = tunnel

        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/tunnels/",
                json={
                    "name": "new-tunnel",
                    "peer_ip": "203.0.113.1",
                    "local_cidrs": ["10.0.0.0/24"],
                    "remote_cidrs": ["192.168.1.0/24"],
                    "psk": "vpn/psk",
                },
            )

        assert resp.status_code == 201
        assert resp.json()["name"] == "new-tunnel"

    @patch("app.services.tunnel_service.delete_tunnel", new_callable=AsyncMock)
    async def test_delete_tunnel_returns_204(self, mock_delete):
        client = await _get_client()
        async with client:
            resp = await client.delete("/api/v1/tunnels/1")

        assert resp.status_code == 204
        mock_delete.assert_called_once()


# ---------------------------------------------------------------------------
# Tunnel router — viewer cannot write
# ---------------------------------------------------------------------------


class TestTunnelRouterAuth:
    @patch("app.services.tunnel_service.list_tunnels", new_callable=AsyncMock)
    async def test_viewer_can_list(self, mock_list):
        mock_list.return_value = ([], 0)
        viewer = _make_mock_user(role="viewer")

        client = await _get_client(user=viewer)
        async with client:
            resp = await client.get("/api/v1/tunnels/")

        assert resp.status_code == 200

    async def test_viewer_cannot_create(self):
        viewer = _make_mock_user(role="viewer")

        client = await _get_client(user=viewer)
        async with client:
            resp = await client.post(
                "/api/v1/tunnels/",
                json={
                    "name": "test",
                    "peer_ip": "1.2.3.4",
                    "local_cidrs": ["10.0.0.0/24"],
                    "remote_cidrs": ["192.168.0.0/24"],
                    "psk": "vpn/psk",
                },
            )

        # Should be 403 from require_admin
        assert resp.status_code == 403

    async def test_viewer_cannot_delete(self):
        viewer = _make_mock_user(role="viewer")

        client = await _get_client(user=viewer)
        async with client:
            resp = await client.delete("/api/v1/tunnels/1")

        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Route router
# ---------------------------------------------------------------------------


class TestRouteRouter:
    @patch("app.services.route_service.list_routes", new_callable=AsyncMock)
    async def test_list_routes(self, mock_list):
        mock_list.return_value = []

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/routes/")

        assert resp.status_code == 200
        assert resp.json() == []

    @patch("app.services.route_service.create_route", new_callable=AsyncMock)
    async def test_create_route_returns_202(self, mock_create):
        route = MagicMock()
        operation = MagicMock()
        operation.id = uuid.uuid4()
        operation.status = "pending"
        mock_create.return_value = (route, operation)

        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/routes/?tunnel_id=1",
                json={"cidr": "172.16.0.0/16"},
            )

        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"
        assert "poll_url" in data

    @patch("app.services.route_service.delete_route", new_callable=AsyncMock)
    async def test_delete_route_returns_202(self, mock_delete):
        operation = MagicMock()
        operation.id = uuid.uuid4()
        operation.status = "pending"
        mock_delete.return_value = operation

        client = await _get_client()
        async with client:
            resp = await client.delete("/api/v1/routes/1")

        assert resp.status_code == 202
