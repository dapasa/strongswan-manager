"""Tests for POST /api/v1/tunnels/{tunnel_id}/rotate-psk and rotate_psk service.

Covers:
- Generated PSK path (no body / psk omitted)
- Provided PSK path (psk in body)
- PSK validation — min_length=1
- psk_rotated_at set on the tunnel
- Audit entry uses action='rotate_psk' without the PSK value
- Response carries Cache-Control: no-store
- PSK does not appear in any structured log call
- Push failure → sync_status partial/failed; DB keeps new PSK
- Role enforcement: viewer → 403, operator/admin → allowed
- 404 for non-existent tunnel
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.db.models import User
from app.exceptions import NotFoundError
from app.utils.fan_out import FanOutResult, ServerResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_user(role: str = "operator", user_id: int = 10) -> MagicMock:
    user = MagicMock(spec=User)
    user.id = user_id
    user.role = role
    user.is_active = True
    user.sub = f"test-{role}-sub"
    user.email = f"{role}@test.com"
    return user


def _make_mock_tunnel(*, psk_rotated_at: datetime | None = None) -> MagicMock:
    now = datetime.now(timezone.utc)
    t = MagicMock()
    t.id = 42
    t.name = "acme-vpn"
    t.peer_ip = "203.0.113.5"
    t.local_cidrs = ["10.0.0.0/24"]
    t.remote_cidrs = ["192.168.10.0/24"]
    t.ike_version = "2"
    t.ike_proposals = None
    t.esp_proposals = None
    t.dpd_action = "restart"
    t.dpd_delay = 30
    t.dpd_timeout = 150
    t.local_id = None
    t.remote_id = None
    t.start_action = "trap"
    t.ike_lifetime = 86400
    t.status = "active"
    t.sync_status = "synced"
    t.sync_error = None
    t.sync_details = None
    t.psk_encrypted = "dGVzdA=="
    t.psk_rotated_at = psk_rotated_at or now
    t.created_at = now
    t.updated_at = now
    t.creator = None
    t.routes = []
    t.iptables_rules = []
    return t


async def _get_client(user: MagicMock | None = None):
    """Build an httpx.AsyncClient with mocked auth and DB."""
    import httpx

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
# Router-level tests
# ---------------------------------------------------------------------------


class TestRotatePskEndpoint:
    """POST /api/v1/tunnels/{tunnel_id}/rotate-psk"""

    @patch("app.services.tunnel_service.rotate_psk", new_callable=AsyncMock)
    async def test_generated_psk_path(self, mock_rotate):
        """Omitting psk in body → service called with psk=None → PSK generated."""
        now = datetime.now(timezone.utc)
        mock_tunnel = _make_mock_tunnel(psk_rotated_at=now)
        mock_rotate.return_value = (mock_tunnel, "GENERATED-PSK-VALUE")

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/tunnels/42/rotate-psk", json={})

        assert resp.status_code == 200
        body = resp.json()
        assert body["tunnel_id"] == 42
        assert body["psk"] == "GENERATED-PSK-VALUE"
        assert body["sync_status"] == "synced"
        # Service was called with psk=None (generate)
        mock_rotate.assert_called_once()
        _, kwargs = mock_rotate.call_args
        assert kwargs["psk"] is None

    @patch("app.services.tunnel_service.rotate_psk", new_callable=AsyncMock)
    async def test_provided_psk_path(self, mock_rotate):
        """Providing psk in body → service called with that value."""
        now = datetime.now(timezone.utc)
        mock_tunnel = _make_mock_tunnel(psk_rotated_at=now)
        mock_rotate.return_value = (mock_tunnel, "my-custom-psk-value")

        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/tunnels/42/rotate-psk",
                json={"psk": "my-custom-psk-value"},
            )

        assert resp.status_code == 200
        assert resp.json()["psk"] == "my-custom-psk-value"
        _, kwargs = mock_rotate.call_args
        assert kwargs["psk"] == "my-custom-psk-value"

    async def test_psk_validation_empty_string(self):
        """psk='' fails validation — min_length=1."""
        client = await _get_client()
        async with client:
            resp = await client.post(
                "/api/v1/tunnels/42/rotate-psk",
                json={"psk": ""},
            )
        assert resp.status_code == 422

    @patch("app.services.tunnel_service.rotate_psk", new_callable=AsyncMock)
    async def test_psk_rotated_at_in_response(self, mock_rotate):
        """psk_rotated_at is present in the response."""
        now = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)
        mock_tunnel = _make_mock_tunnel(psk_rotated_at=now)
        mock_rotate.return_value = (mock_tunnel, "some-psk")

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/tunnels/42/rotate-psk", json={})

        assert resp.status_code == 200
        assert "psk_rotated_at" in resp.json()
        # Datetime is returned as an ISO string
        assert resp.json()["psk_rotated_at"] is not None

    @patch("app.services.tunnel_service.rotate_psk", new_callable=AsyncMock)
    async def test_response_cache_control_no_store(self, mock_rotate):
        """Response carries Cache-Control: no-store."""
        mock_tunnel = _make_mock_tunnel()
        mock_rotate.return_value = (mock_tunnel, "psk-value")

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/tunnels/42/rotate-psk", json={})

        assert resp.status_code == 200
        assert resp.headers.get("cache-control") == "no-store"

    async def test_viewer_role_forbidden(self):
        """Viewer cannot rotate PSK — 403."""
        viewer = _make_mock_user(role="viewer")
        client = await _get_client(user=viewer)
        async with client:
            resp = await client.post("/api/v1/tunnels/42/rotate-psk", json={})
        assert resp.status_code == 403

    @patch("app.services.tunnel_service.rotate_psk", new_callable=AsyncMock)
    async def test_operator_role_allowed(self, mock_rotate):
        """Operator can rotate PSK."""
        mock_tunnel = _make_mock_tunnel()
        mock_rotate.return_value = (mock_tunnel, "psk-value")

        operator = _make_mock_user(role="operator")
        client = await _get_client(user=operator)
        async with client:
            resp = await client.post("/api/v1/tunnels/42/rotate-psk", json={})

        assert resp.status_code == 200

    @patch("app.services.tunnel_service.rotate_psk", new_callable=AsyncMock)
    async def test_tunnel_not_found_returns_404(self, mock_rotate):
        """NotFoundError from service → 404."""
        mock_rotate.side_effect = NotFoundError("Tunnel", 999)

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/tunnels/999/rotate-psk", json={})

        assert resp.status_code == 404

    @patch("app.services.tunnel_service.rotate_psk", new_callable=AsyncMock)
    async def test_push_failure_reflected_in_response(self, mock_rotate):
        """When push fails, sync_status in response is 'failed'."""
        mock_tunnel = _make_mock_tunnel()
        mock_tunnel.sync_status = "failed"
        mock_tunnel.sync_details = {"servers": [{"server_id": 1, "success": False}]}
        mock_rotate.return_value = (mock_tunnel, "new-psk")

        client = await _get_client()
        async with client:
            resp = await client.post("/api/v1/tunnels/42/rotate-psk", json={})

        assert resp.status_code == 200
        body = resp.json()
        assert body["sync_status"] == "failed"
        assert body["psk"] == "new-psk"  # PSK still returned even on failure


# ---------------------------------------------------------------------------
# Service-level tests
# ---------------------------------------------------------------------------


class TestRotatePskService:
    """Direct tests for rotate_psk service function."""

    def _make_session(self, tunnel: MagicMock) -> AsyncMock:
        """Return an AsyncSession mock wired to return the given tunnel."""
        session = AsyncMock()
        # get_tunnel calls session.execute → scalar_one_or_none
        result_mock = MagicMock()
        result_mock.scalar_one_or_none.return_value = tunnel
        session.execute.return_value = result_mock
        return session

    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_psk_rotated_at_set_on_rotation(
        self, mock_audit, mock_lock, mock_encrypt, mock_sync
    ):
        """rotate_psk sets psk_rotated_at on the tunnel."""
        from app.services.tunnel_service import rotate_psk

        now = datetime.now(timezone.utc)
        tunnel = _make_mock_tunnel(psk_rotated_at=now)
        tunnel.psk_rotated_at = None  # reset so we can verify it's set

        session = self._make_session(tunnel)
        mock_encrypt.return_value = "new-encrypted-blob"
        mock_sync.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        user = _make_mock_user()
        _, returned_psk = await rotate_psk(session, 42, psk="explicit-psk", user=user)

        assert tunnel.psk_rotated_at is not None
        assert returned_psk == "explicit-psk"

    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_generated_psk_format(self, mock_audit, mock_lock, mock_encrypt, mock_sync):
        """When psk=None, the generated PSK is URL-safe base64 (no problematic chars)."""
        import re

        from app.services.tunnel_service import rotate_psk

        tunnel = _make_mock_tunnel()
        session = self._make_session(tunnel)
        mock_encrypt.return_value = "enc-blob"
        mock_sync.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        user = _make_mock_user()
        _, generated_psk = await rotate_psk(session, 42, psk=None, user=user)

        # URL-safe base64: A-Za-z0-9, '-', '_' only
        assert re.fullmatch(r"[A-Za-z0-9\-_]+", generated_psk)
        assert len(generated_psk) >= 40  # ~48 chars from 36 bytes

    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_audit_action_is_rotate_psk(self, mock_audit, mock_lock, mock_encrypt, mock_sync):
        """Audit log uses action='rotate_psk'."""
        from app.services.tunnel_service import rotate_psk

        tunnel = _make_mock_tunnel()
        session = self._make_session(tunnel)
        mock_encrypt.return_value = "enc-blob"
        mock_sync.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        user = _make_mock_user()
        await rotate_psk(session, 42, psk="my-psk", user=user)

        mock_audit.assert_called_once()
        _, kwargs = mock_audit.call_args
        assert kwargs["action"] == "rotate_psk"
        assert kwargs["entity_type"] == "tunnel"

    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_audit_new_state_has_no_psk(self, mock_audit, mock_lock, mock_encrypt, mock_sync):
        """Audit log new_state does not contain the PSK value."""
        from app.services.tunnel_service import rotate_psk

        secret_psk = "ultra-secret-do-not-log-me"
        tunnel = _make_mock_tunnel()
        session = self._make_session(tunnel)
        mock_encrypt.return_value = "enc-blob"
        mock_sync.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        user = _make_mock_user()
        await rotate_psk(session, 42, psk=secret_psk, user=user)

        _, kwargs = mock_audit.call_args
        new_state_str = str(kwargs.get("new_state", ""))
        assert secret_psk not in new_state_str

    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_psk_not_in_structured_logs(self, mock_audit, mock_lock, mock_encrypt, mock_sync):
        """PSK value does not appear in any structured log call."""
        import app.services.tunnel_service as svc
        from app.services.tunnel_service import rotate_psk

        secret_psk = "MUST-NOT-APPEAR-IN-LOGS-9f3k2"
        tunnel = _make_mock_tunnel()
        session = self._make_session(tunnel)
        mock_encrypt.return_value = "enc-blob"
        mock_sync.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        user = _make_mock_user()
        with patch.object(svc, "logger") as mock_logger:
            await rotate_psk(session, 42, psk=secret_psk, user=user)

            all_calls = (
                mock_logger.info.call_args_list
                + mock_logger.error.call_args_list
                + mock_logger.warning.call_args_list
            )
            for call_obj in all_calls:
                assert secret_psk not in str(call_obj), (
                    f"PSK appeared in log call: {call_obj}"
                )

    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_push_failure_sets_failed_sync_status(
        self, mock_audit, mock_lock, mock_encrypt, mock_sync
    ):
        """When sync_tunnel_config returns a failure, sync_status is 'failed' or 'partial'."""
        from app.services.tunnel_service import rotate_psk

        tunnel = _make_mock_tunnel()
        session = self._make_session(tunnel)
        mock_encrypt.return_value = "enc-blob"
        mock_sync.return_value = FanOutResult(
            total=2, succeeded=0, failed=2,
            servers=[
                ServerResult(server_id=1, server_name="vpn-1", success=False, error="timeout"),
                ServerResult(server_id=2, server_name="vpn-2", success=False, error="timeout"),
            ],
        )

        user = _make_mock_user()
        result_tunnel, new_psk = await rotate_psk(session, 42, psk="my-psk", user=user)

        # DB still holds new encrypted PSK (no rollback at service level)
        assert tunnel.psk_encrypted == "enc-blob"
        # sync_status reflects failure
        assert result_tunnel.sync_status in ("failed", "partial")
        # PSK is still returned
        assert new_psk == "my-psk"

    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_partial_push_failure(self, mock_audit, mock_lock, mock_encrypt, mock_sync):
        """Partial push failure (1 of 2 servers) → sync_status is 'partial'."""
        from app.services.tunnel_service import rotate_psk

        tunnel = _make_mock_tunnel()
        session = self._make_session(tunnel)
        mock_encrypt.return_value = "enc-blob"
        mock_sync.return_value = FanOutResult(
            total=2, succeeded=1, failed=1,
            servers=[
                ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok"),
                ServerResult(server_id=2, server_name="vpn-2", success=False, error="timeout"),
            ],
        )

        user = _make_mock_user()
        result_tunnel, _ = await rotate_psk(session, 42, psk="my-psk", user=user)

        assert result_tunnel.sync_status == "partial"
