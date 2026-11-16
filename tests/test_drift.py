"""Tests for drift_service.detect_server_drift and GET /{server_id}/drift endpoint."""
from __future__ import annotations

import hashlib
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

TUNNEL_NAME = "test-tunnel"
TUNNEL_ID = 42
SERVER_ID = 7

FAKE_PSK = "fake-psk"
FAKE_CONF_CONTENT = "conn test-tunnel { ... }"
FAKE_SECRETS_CONTENT = ": PSK fake-psk"


def _sha256(s: str) -> str:
    return hashlib.sha256(s.encode()).hexdigest()


def _make_mock_server(engine: str = "swanctl") -> MagicMock:
    server = MagicMock()
    server.id = SERVER_ID
    server.name = "vpn-dev-01"
    server.ipsec_engine = engine
    return server


def _make_mock_tunnel(name: str = TUNNEL_NAME, tid: int = TUNNEL_ID) -> MagicMock:
    tunnel = MagicMock()
    tunnel.id = tid
    tunnel.name = name
    tunnel.psk_encrypted = "encrypted-psk"
    tunnel.deleted_at = None
    return tunnel


def _make_mock_session(tunnels: list) -> AsyncMock:
    session = AsyncMock()
    scalars_mock = MagicMock()
    scalars_mock.all.return_value = tunnels
    result_mock = MagicMock()
    result_mock.scalars.return_value = scalars_mock
    session.execute.return_value = result_mock
    return session


def _make_transport(*stdout_per_call: str) -> AsyncMock:
    """Return a mock transport whose execute() yields stdout_per_call in order."""
    transport = AsyncMock()
    side_effects = []
    for stdout in stdout_per_call:
        r = MagicMock()
        r.stdout = stdout
        side_effects.append(r)
    transport.execute.side_effect = side_effects
    return transport


def _swanctl_conf_path(name: str = TUNNEL_NAME) -> str:
    return f"/etc/swanctl/conf.d/{name}.conf"


def _stroke_conf_path(name: str = TUNNEL_NAME) -> str:
    return f"/opt/strongswan/config/connections/{name}.conf"


def _stroke_secrets_path(name: str = TUNNEL_NAME) -> str:
    return f"/etc/ipsec.d/secrets/{name}.secrets"


# ---------------------------------------------------------------------------
# Unit tests — detect_server_drift
# ---------------------------------------------------------------------------

_COMMON_PATCHES = [
    patch("app.services.drift_service.get_server", new_callable=AsyncMock),
    patch("app.services.drift_service.kms.decrypt_psk", new_callable=AsyncMock),
    patch("app.services.drift_service.get_transport"),
    patch("app.services.drift_service.render_swanctl_conf"),
    patch("app.services.drift_service.render_connection_conf"),
    patch("app.services.drift_service.render_secrets_file"),
]


@pytest.mark.asyncio
class TestDetectServerDriftSwanctl:
    """Swanctl-engine drift detection (single .conf file per tunnel)."""

    async def test_in_sync(self):
        from app.services import drift_service

        expected_hash = _sha256(FAKE_CONF_CONTENT)
        conf_path = _swanctl_conf_path()
        sha256_line = f"{expected_hash}  {conf_path}"
        # call 1: sha256sum; call 2: ls /etc/swanctl/conf.d
        transport = _make_transport(sha256_line, f"{TUNNEL_NAME}.conf")

        server = _make_mock_server("swanctl")
        tunnel = _make_mock_tunnel()
        session = _make_mock_session([tunnel])

        with (
            patch("app.services.drift_service.get_server", new_callable=AsyncMock, return_value=server),
            patch("app.services.drift_service.kms.decrypt_psk", new_callable=AsyncMock, return_value=FAKE_PSK),
            patch("app.services.drift_service.get_transport", return_value=transport),
            patch("app.services.drift_service.render_swanctl_conf", return_value=FAKE_CONF_CONTENT),
        ):
            result = await drift_service.detect_server_drift(session, SERVER_ID)

        assert len(result["tunnels"]) == 1
        assert result["tunnels"][0]["status"] == "in_sync"
        assert result["orphan_files"] == []

    async def test_drifted(self):
        from app.services import drift_service

        wrong_hash = "a" * 64
        conf_path = _swanctl_conf_path()
        sha256_line = f"{wrong_hash}  {conf_path}"
        transport = _make_transport(sha256_line, f"{TUNNEL_NAME}.conf")

        server = _make_mock_server("swanctl")
        tunnel = _make_mock_tunnel()
        session = _make_mock_session([tunnel])

        with (
            patch("app.services.drift_service.get_server", new_callable=AsyncMock, return_value=server),
            patch("app.services.drift_service.kms.decrypt_psk", new_callable=AsyncMock, return_value=FAKE_PSK),
            patch("app.services.drift_service.get_transport", return_value=transport),
            patch("app.services.drift_service.render_swanctl_conf", return_value=FAKE_CONF_CONTENT),
        ):
            result = await drift_service.detect_server_drift(session, SERVER_ID)

        assert result["tunnels"][0]["status"] == "drifted"

    async def test_missing_on_node(self):
        from app.services import drift_service

        # sha256sum returns nothing (file absent); ls also empty
        transport = _make_transport("", "")

        server = _make_mock_server("swanctl")
        tunnel = _make_mock_tunnel()
        session = _make_mock_session([tunnel])

        with (
            patch("app.services.drift_service.get_server", new_callable=AsyncMock, return_value=server),
            patch("app.services.drift_service.kms.decrypt_psk", new_callable=AsyncMock, return_value=FAKE_PSK),
            patch("app.services.drift_service.get_transport", return_value=transport),
            patch("app.services.drift_service.render_swanctl_conf", return_value=FAKE_CONF_CONTENT),
        ):
            result = await drift_service.detect_server_drift(session, SERVER_ID)

        assert result["tunnels"][0]["status"] == "missing_on_node"

    async def test_orphan_files_detected(self):
        from app.services import drift_service

        expected_hash = _sha256(FAKE_CONF_CONTENT)
        conf_path = _swanctl_conf_path()
        sha256_line = f"{expected_hash}  {conf_path}"
        # ls returns both the known tunnel and an orphan
        ls_output = f"{TUNNEL_NAME}.conf\norphan-tunnel.conf"
        transport = _make_transport(sha256_line, ls_output)

        server = _make_mock_server("swanctl")
        tunnel = _make_mock_tunnel()
        session = _make_mock_session([tunnel])

        with (
            patch("app.services.drift_service.get_server", new_callable=AsyncMock, return_value=server),
            patch("app.services.drift_service.kms.decrypt_psk", new_callable=AsyncMock, return_value=FAKE_PSK),
            patch("app.services.drift_service.get_transport", return_value=transport),
            patch("app.services.drift_service.render_swanctl_conf", return_value=FAKE_CONF_CONTENT),
        ):
            result = await drift_service.detect_server_drift(session, SERVER_ID)

        assert result["orphan_files"] == ["/etc/swanctl/conf.d/orphan-tunnel.conf"]

    async def test_tunnel_id_filter(self):
        """When tunnel_id is supplied, only that tunnel appears in results."""
        from app.services import drift_service

        expected_hash = _sha256(FAKE_CONF_CONTENT)
        conf_path = _swanctl_conf_path()
        sha256_line = f"{expected_hash}  {conf_path}"
        transport = _make_transport(sha256_line, f"{TUNNEL_NAME}.conf")

        server = _make_mock_server("swanctl")
        tunnel = _make_mock_tunnel()
        # Session returns only the filtered tunnel (mimicking the WHERE clause)
        session = _make_mock_session([tunnel])

        with (
            patch("app.services.drift_service.get_server", new_callable=AsyncMock, return_value=server),
            patch("app.services.drift_service.kms.decrypt_psk", new_callable=AsyncMock, return_value=FAKE_PSK),
            patch("app.services.drift_service.get_transport", return_value=transport),
            patch("app.services.drift_service.render_swanctl_conf", return_value=FAKE_CONF_CONTENT),
        ):
            result = await drift_service.detect_server_drift(session, SERVER_ID, tunnel_id=TUNNEL_ID)

        assert len(result["tunnels"]) == 1
        assert result["tunnels"][0]["tunnel_id"] == TUNNEL_ID


@pytest.mark.asyncio
class TestDetectServerDriftStroke:
    """Stroke-engine drift detection (two files: .conf + .secrets per tunnel)."""

    async def test_stroke_engine_checks_two_files(self):
        """Stroke engine checks both .conf and .secrets; both in-sync → in_sync."""
        from app.services import drift_service

        conf_path = _stroke_conf_path()
        secrets_path = _stroke_secrets_path()
        expected_conf_hash = _sha256(FAKE_CONF_CONTENT)
        expected_secrets_hash = _sha256(FAKE_SECRETS_CONTENT)

        sha256_output = (
            f"{expected_conf_hash}  {conf_path}\n"
            f"{expected_secrets_hash}  {secrets_path}"
        )
        # ls for /opt/strongswan/config/connections, ls for /etc/ipsec.d/secrets
        transport = _make_transport(sha256_output, f"{TUNNEL_NAME}.conf", f"{TUNNEL_NAME}.secrets")

        server = _make_mock_server("stroke")
        tunnel = _make_mock_tunnel()
        session = _make_mock_session([tunnel])

        with (
            patch("app.services.drift_service.get_server", new_callable=AsyncMock, return_value=server),
            patch("app.services.drift_service.kms.decrypt_psk", new_callable=AsyncMock, return_value=FAKE_PSK),
            patch("app.services.drift_service.get_transport", return_value=transport),
            patch("app.services.drift_service.render_connection_conf", return_value=FAKE_CONF_CONTENT),
            patch("app.services.drift_service.render_secrets_file", return_value=FAKE_SECRETS_CONTENT),
        ):
            result = await drift_service.detect_server_drift(session, SERVER_ID)

        t = result["tunnels"][0]
        assert t["status"] == "in_sync"
        # Both paths must appear in expected_hashes
        assert conf_path in t["expected_hashes"]
        assert secrets_path in t["expected_hashes"]


# ---------------------------------------------------------------------------
# Endpoint tests — GET /api/v1/servers/{server_id}/drift
# ---------------------------------------------------------------------------

def _make_mock_user(role: str = "viewer") -> MagicMock:
    user = MagicMock()
    user.id = 1
    user.sub = "test-sub"
    user.email = "test@test.com"
    user.display_name = "Test User"
    user.role = role
    user.is_active = True
    return user


async def _get_client(role: str = "viewer") -> httpx.AsyncClient:
    from app.auth.dependencies import get_current_user
    from app.db.session import get_db
    from app.main import app

    mock_user = _make_mock_user(role)

    async def _override_get_db():
        yield AsyncMock()

    async def _override_get_current_user():
        return mock_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
class TestDriftEndpoint:
    async def test_drift_endpoint_returns_report(self):
        """GET /{server_id}/drift returns a ServerDriftReport-shaped JSON on success."""
        from datetime import datetime, timezone

        fake_result = {
            "server_id": SERVER_ID,
            "server_name": "vpn-dev-01",
            "tunnels": [
                {
                    "tunnel_id": TUNNEL_ID,
                    "tunnel_name": TUNNEL_NAME,
                    "status": "in_sync",
                    "expected_hashes": {_swanctl_conf_path(): _sha256(FAKE_CONF_CONTENT)},
                    "actual_hashes": {_swanctl_conf_path(): _sha256(FAKE_CONF_CONTENT)},
                }
            ],
            "orphan_files": [],
            "checked_at": datetime.now(timezone.utc),
        }

        with patch("app.services.drift_service.detect_server_drift", new_callable=AsyncMock, return_value=fake_result):
            client = await _get_client("viewer")
            async with client:
                resp = await client.get(f"/api/v1/servers/{SERVER_ID}/drift")

        assert resp.status_code == 200
        body = resp.json()
        assert body["server_id"] == SERVER_ID
        assert body["tunnels"][0]["status"] == "in_sync"
        assert body["orphan_files"] == []

    async def test_drift_endpoint_viewer_can_access(self):
        """Viewer role (minimum required) gets 200, not 403."""
        from datetime import datetime, timezone

        fake_result = {
            "server_id": SERVER_ID,
            "server_name": "vpn-dev-01",
            "tunnels": [],
            "orphan_files": [],
            "checked_at": datetime.now(timezone.utc),
        }

        with patch("app.services.drift_service.detect_server_drift", new_callable=AsyncMock, return_value=fake_result):
            client = await _get_client("viewer")
            async with client:
                resp = await client.get(f"/api/v1/servers/{SERVER_ID}/drift")

        assert resp.status_code == 200
