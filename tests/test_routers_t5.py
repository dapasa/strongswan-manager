"""Tests for T5 routers — iptables, audit, operations, auth."""
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
    user.last_login_at = None
    user.created_at = datetime.now(timezone.utc)
    return user


async def _get_client(user: MagicMock | None = None) -> httpx.AsyncClient:
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
# IPTables router
# ---------------------------------------------------------------------------


class TestIPTablesRouter:
    @patch("app.services.iptables_service.list_rules", new_callable=AsyncMock)
    async def test_list_rules(self, mock_list):
        mock_list.return_value = []

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/iptables/")

        assert resp.status_code == 200
        assert resp.json() == []

    @patch("app.services.iptables_service.list_rules", new_callable=AsyncMock)
    async def test_list_rules_with_tunnel_filter(self, mock_list):
        mock_list.return_value = []

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/iptables/?tunnel_id=5")

        assert resp.status_code == 200
        mock_list.assert_called_once()
        call_kwargs = mock_list.call_args
        assert call_kwargs.kwargs.get("tunnel_id") == 5 or call_kwargs[1].get("tunnel_id") == 5

    @patch("app.services.iptables_service.get_rule", new_callable=AsyncMock)
    async def test_get_rule_detail(self, mock_get):
        now = datetime.now(timezone.utc)
        rule = MagicMock()
        rule.id = 1
        rule.tunnel_id = 10
        rule.chain = "FORWARD"
        rule.protocol = "tcp"
        rule.source_cidr = "10.0.0.0/24"
        rule.dest_cidr = None
        rule.sport = None
        rule.dport = 443
        rule.action = "ACCEPT"
        rule.state_match = None
        rule.comment = None
        rule.position = None
        rule.sync_status = "synced"
        rule.sync_error = None
        rule.created_by = 1
        rule.created_at = now
        rule.updated_at = now
        mock_get.return_value = rule

        client = await _get_client()
        async with client:
            resp = await client.get("/api/v1/iptables/1")

        assert resp.status_code == 200
        data = resp.json()
        assert data["chain"] == "FORWARD"
        assert data["dport"] == 443
        assert "command_preview" in data
        assert "iptables -A FORWARD" in data["command_preview"]

    @patch("app.services.iptables_service.create_rule", new_callable=AsyncMock)
    async def test_create_rule_returns_201(self, mock_create):
        now = datetime.now(timezone.utc)
        rule = MagicMock()
        rule.id = 1
        rule.tunnel_id = 5
        rule.chain = "FORWARD"
        rule.protocol = "tcp"
        rule.source_cidr = None
        rule.dest_cidr = None
        rule.sport = None
        rule.dport = 80
        rule.action = "ACCEPT"
        rule.state_match = None
        rule.comment = None
        rule.position = None
        rule.sync_status = "synced"
        rule.sync_error = None
        rule.created_by = 1
        rule.created_at = now
        rule.updated_at = now
        mock_create.return_value = rule

        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/iptables/?tunnel_id=5",
                json={
                    "chain": "FORWARD",
                    "protocol": "tcp",
                    "dport": 80,
                    "action": "ACCEPT",
                },
            )

        assert resp.status_code == 201
        assert resp.json()["dport"] == 80

    @patch("app.services.iptables_service.delete_rule", new_callable=AsyncMock)
    async def test_delete_rule_returns_204(self, mock_delete):
        client = await _get_client()
        async with client:
            resp = await client.delete("/api/v1/iptables/1")

        assert resp.status_code == 204
        mock_delete.assert_called_once()

    @patch("app.services.iptables_service.update_rule", new_callable=AsyncMock)
    async def test_update_rule(self, mock_update):
        now = datetime.now(timezone.utc)
        rule = MagicMock()
        rule.id = 1
        rule.tunnel_id = 5
        rule.chain = "INPUT"
        rule.protocol = "tcp"
        rule.source_cidr = None
        rule.dest_cidr = None
        rule.sport = None
        rule.dport = 8080
        rule.action = "ACCEPT"
        rule.state_match = None
        rule.comment = None
        rule.position = None
        rule.sync_status = "synced"
        rule.sync_error = None
        rule.created_by = 1
        rule.created_at = now
        rule.updated_at = now
        mock_update.return_value = rule

        client = await _get_client()
        async with client:
            resp = await client.patch(
                "/api/v1/iptables/1",
                json={"chain": "INPUT", "dport": 8080},
            )

        assert resp.status_code == 200
        assert resp.json()["chain"] == "INPUT"

    async def test_viewer_cannot_create_rule(self):
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.post(
                "/api/v1/iptables/?tunnel_id=1",
                json={"chain": "FORWARD", "protocol": "tcp", "action": "ACCEPT"},
            )
        assert resp.status_code == 403

    async def test_viewer_cannot_delete_rule(self):
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.delete("/api/v1/iptables/1")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Auth router
# ---------------------------------------------------------------------------


class TestAuthRouter:
    async def test_get_me(self):
        user = _make_mock_user()
        client = await _get_client(user=user)
        async with client:
            resp = await client.get("/api/v1/auth/me")

        assert resp.status_code == 200
        data = resp.json()
        assert data["email"] == "admin@test.com"
        assert data["role"] == "admin"

    async def test_get_me_viewer(self):
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.get("/api/v1/auth/me")

        assert resp.status_code == 200
        assert resp.json()["role"] == "viewer"


# ---------------------------------------------------------------------------
# Operations router
# ---------------------------------------------------------------------------


class TestOperationsRouter:
    @patch("app.routers.operations.get_operation", new_callable=AsyncMock)
    async def test_poll_operation(self, mock_get):
        now = datetime.now(timezone.utc)
        op_id = uuid.uuid4()
        operation = MagicMock()
        operation.id = op_id
        operation.entity_type = "route"
        operation.entity_id = 42
        operation.operation = "create"
        operation.status = "completed"
        operation.started_at = now
        operation.completed_at = now
        operation.result = {"cidr": "10.0.0.0/24"}
        operation.error_message = None
        operation.created_at = now
        mock_get.return_value = operation

        client = await _get_client()
        async with client:
            resp = await client.get(f"/api/v1/operations/{op_id}")

        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "completed"
        assert data["entity_type"] == "route"


# ---------------------------------------------------------------------------
# Middleware — exception handling
# ---------------------------------------------------------------------------


class TestMiddleware:
    async def test_not_found_returns_404(self):
        from app.exceptions import NotFoundError

        with patch(
            "app.services.tunnel_service.get_tunnel",
            new_callable=AsyncMock,
            side_effect=NotFoundError("Tunnel", 999),
        ):
            client = await _get_client()
            async with client:
                resp = await client.get("/api/v1/tunnels/999")

        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    async def test_conflict_returns_409(self):
        from app.exceptions import ConflictError

        with patch(
            "app.services.tunnel_service.create_tunnel",
            new_callable=AsyncMock,
            side_effect=ConflictError("Tunnel 'test' already exists"),
        ):
            client = await _get_client()
            async with client:
                resp = await client.post(
                    "/api/v1/tunnels/",
                    json={
                        "name": "test",
                        "peer_ip": "1.2.3.4",
                        "local_cidrs": ["10.0.0.0/24"],
                        "remote_cidrs": ["192.168.0.0/24"],
                        "psk_secret_name": "vpn/psk",
                    },
                )

        assert resp.status_code == 409

    async def test_infrastructure_error_returns_502(self):
        from app.exceptions import InfrastructureError

        with patch(
            "app.services.tunnel_service.get_tunnel",
            new_callable=AsyncMock,
            side_effect=InfrastructureError(service="SSM", message="Connection failed"),
        ):
            client = await _get_client()
            async with client:
                resp = await client.get("/api/v1/tunnels/1")

        assert resp.status_code == 502
