"""Tests for API routers — tunnels, routes, dashboard, health, operations."""
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

    @patch("app.routers.health.execute_on_all_servers", new_callable=AsyncMock)
    async def test_health_readiness_all_ok(self, mock_fan_out):
        from app.utils.fan_out import FanOutResult, ServerResult

        mock_fan_out.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        from app.main import app
        from app.db.session import get_db

        async def _override():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=MagicMock())
            yield db

        app.dependency_overrides[get_db] = _override

        transport = __import__("httpx").ASGITransport(app=app)
        async with __import__("httpx").AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health/ready")

        app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "ok"
        assert "s3" not in data["checks"]
        assert data["checks"]["ssh"] == "ok"


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

    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.create_tunnel", new_callable=AsyncMock)
    async def test_create_tunnel_returns_201(self, mock_create, mock_get_tunnel):
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
        tunnel.local_id = None
        tunnel.remote_id = None
        tunnel.start_action = "trap"
        tunnel.ike_lifetime = 86400
        tunnel.status = "active"
        tunnel.sync_status = "synced"
        tunnel.sync_error = None
        tunnel.routes = []
        tunnel.iptables_rules = []
        tunnel.creator = None
        tunnel.created_at = now
        tunnel.updated_at = now
        mock_create.return_value = tunnel
        mock_get_tunnel.return_value = tunnel

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

    async def test_route_write_endpoints_are_routable(self):
        """Route write endpoints exist and require authentication (not 405/404)."""
        from unittest.mock import patch as _patch

        from app.exceptions import ValidationError as _VE

        # Patch the service so we don't hit AWS or DB
        with _patch(
            "app.services.route_service.create_route",
            side_effect=_VE("feature disabled"),
        ), _patch(
            "app.services.route_service.delete_route",
            side_effect=_VE("not found"),
        ), _patch(
            "app.services.route_service.retry_route",
            side_effect=_VE("not failed"),
        ):
            client = await _get_client()
            async with client:
                create = await client.post("/api/v1/routes/", params={"tunnel_id": 1}, json={"cidr": "172.16.0.0/16"})
                delete = await client.delete("/api/v1/routes/1")
                retry = await client.post("/api/v1/routes/1/retry")
                nested = await client.post("/api/v1/tunnels/1/routes", json={"cidr": "172.16.0.0/16"})

        # Routes exist — should NOT be 405 (Method Not Allowed) or 404 (Not Found)
        assert create.status_code not in (404, 405)
        assert delete.status_code not in (404, 405)
        assert retry.status_code not in (404, 405)
        assert nested.status_code not in (404, 405)


# ---------------------------------------------------------------------------
# Tunnel router — GET /api/v1/tunnels/status/live
# ---------------------------------------------------------------------------


class TestLiveStatusRouter:
    @patch("app.services.tunnel_service.get_all_tunnels_live_status", new_callable=AsyncMock)
    async def test_live_status_returns_ok(self, mock_service):
        from datetime import datetime, timezone

        mock_service.return_value = {
            "tunnels": [],
            "summary": {"total": 0, "up": 0, "down": 0, "partial": 0, "unknown": 0},
            "checked_at": datetime.now(timezone.utc),
            "server_errors": {},
        }

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/tunnels/status/live")

        assert resp.status_code == 200
        data = resp.json()
        assert "tunnels" in data
        assert "summary" in data
        assert "checked_at" in data
        assert "server_errors" in data
        mock_service.assert_awaited_once()

    @patch("app.services.tunnel_service.get_all_tunnels_live_status", new_callable=AsyncMock)
    async def test_live_status_viewer_role_allowed(self, mock_service):
        from datetime import datetime, timezone

        mock_service.return_value = {
            "tunnels": [],
            "summary": {"total": 0, "up": 0, "down": 0, "partial": 0, "unknown": 0},
            "checked_at": datetime.now(timezone.utc),
            "server_errors": {},
        }

        client = await _get_client(user=_make_mock_user(role="viewer"))
        async with client:
            resp = await client.get("/api/v1/tunnels/status/live")

        assert resp.status_code == 200

    @patch("app.services.tunnel_service.get_all_tunnels_live_status", new_callable=AsyncMock)
    async def test_live_status_response_shape(self, mock_service):
        """Verify the response includes per-tunnel rows with expected keys."""
        from datetime import datetime, timezone

        mock_service.return_value = {
            "tunnels": [
                {
                    "tunnel_id": 1,
                    "name": "prod-vpn",
                    "overall": "UP",
                    "per_server": [
                        {
                            "server_id": 1,
                            "server_name": "vpn-1",
                            "state": "UP",
                            "success": True,
                            "error": None,
                        }
                    ],
                }
            ],
            "summary": {"total": 1, "up": 1, "down": 0, "partial": 0, "unknown": 0},
            "checked_at": datetime.now(timezone.utc),
            "server_errors": {},
        }

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/tunnels/status/live")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["tunnels"]) == 1
        row = data["tunnels"][0]
        assert row["name"] == "prod-vpn"
        assert row["overall"] == "UP"
        assert len(row["per_server"]) == 1
        assert data["summary"]["up"] == 1


# ---------------------------------------------------------------------------
# Reconciler status endpoint
# ---------------------------------------------------------------------------


class TestReconcilerRouter:
    async def test_reconciler_status_empty_state(self):
        """When reconciler has not run yet, returns config fields with empty lists."""
        with (
            patch("app.services.reconciler._state", {}),
            patch("app.services.reconciler._last_run_at", None),
        ):
            client = await _get_client()
            async with client:
                resp = await client.get("/api/v1/reconciler/status")

        assert resp.status_code == 200
        data = resp.json()
        assert "enabled" in data
        assert "interval_seconds" in data
        assert "max_attempts" in data
        assert data["last_run_at"] is None
        assert data["retrying"] == []
        assert data["maxed"] == []

    async def test_reconciler_status_viewer_role_allowed(self):
        with (
            patch("app.services.reconciler._state", {}),
            patch("app.services.reconciler._last_run_at", None),
        ):
            client = await _get_client(user=_make_mock_user(role="viewer"))
            async with client:
                resp = await client.get("/api/v1/reconciler/status")

        assert resp.status_code == 200

    async def test_reconciler_status_with_state(self):
        """Tunnels in state appear in retrying/maxed based on attempt count."""
        from datetime import datetime, timezone
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        # Mock DB to return a tunnel name for id=1
        # Note: MagicMock(name=...) sets the mock display name, not an attribute.
        # Set attributes explicitly to get a proper Row-like object.
        mock_row = MagicMock()
        mock_row.id = 1
        mock_row.name = "acme-vpn"
        mock_db = AsyncMock()
        mock_result = MagicMock()
        mock_result.all.return_value = [mock_row]
        mock_db.execute = AsyncMock(return_value=mock_result)

        async def _override_get_db():
            yield mock_db

        async def _override_get_current_user():
            return _make_mock_user()

        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides[get_current_user] = _override_get_current_user

        last_run = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)

        try:
            with (
                patch("app.services.reconciler._state", {1: 2}),
                patch("app.services.reconciler._last_run_at", last_run),
            ):
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    resp = await client.get("/api/v1/reconciler/status")
        finally:
            app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["last_run_at"] is not None
        # 2 attempts < default max_attempts(5) → retrying
        assert len(data["retrying"]) == 1
        assert data["retrying"][0]["tunnel_name"] == "acme-vpn"
        assert data["retrying"][0]["attempts"] == 2
        assert data["maxed"] == []
