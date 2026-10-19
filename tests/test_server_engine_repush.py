"""Tests for the engine-change tunnel repush logic in update_server.

Covers:
    - Real ipsec_engine change triggers repush + new-engine reload + old-engine cleanup
    - Same ipsec_engine value does NOT trigger repush
    - Other field change (name, hostname) does NOT trigger repush
    - PSKs are never logged
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from app.utils.fan_out import ServerResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(
    id: int = 1,
    name: str = "vpn-primary",
    ipsec_engine: str = "stroke",
) -> MagicMock:
    srv = MagicMock()
    srv.id = id
    srv.name = name
    srv.hostname = "10.0.1.50"
    srv.ssh_port = 22
    srv.ssh_user = "admin"
    srv.ssh_private_key_encrypted = b"ENCRYPTED"
    srv.is_active = True
    srv.deleted_at = None
    srv.ipsec_engine = ipsec_engine
    srv.connection_type = "ssh"
    srv.updated_at = None
    srv.created_at = None
    srv.last_check_at = None
    srv.last_check_status = None
    srv.ec2_instance_id = None
    srv.created_by = 1
    return srv


def _make_tunnel(name: str = "t1") -> MagicMock:
    t = MagicMock()
    t.id = 1
    t.name = name
    t.description = None
    t.peer_ip = "203.0.113.1"
    t.local_cidrs = ["10.0.0.0/24"]
    t.remote_cidrs = ["192.168.1.0/24"]
    t.ike_version = "2"
    t.ike_proposals = "aes256-sha256-modp2048"
    t.esp_proposals = "aes256-sha256-modp2048"
    t.dpd_action = "restart"
    t.dpd_delay = 30
    t.dpd_timeout = 150
    t.local_id = None
    t.ike_lifetime = 86400
    t.status = "active"
    t.sync_status = "synced"
    t.sync_error = None
    t.sync_details = None
    t.psk_secret_name = f"secrets/{name}.secrets"
    t.created_by = 1
    t.deleted_at = None
    t.routes = []
    t.iptables_rules = []
    return t


def _make_session(tunnels: list | None = None) -> AsyncMock:
    session = AsyncMock()

    # First execute call (name uniqueness check): scalar_one_or_none → None (no conflict)
    name_check = MagicMock()
    name_check.scalar_one_or_none.return_value = None

    # Second execute call (Tunnel query for repush): scalars().all() → tunnels
    tunnels_result = MagicMock()
    tunnels_result.scalars.return_value.all.return_value = tunnels or []

    session.execute = AsyncMock(side_effect=[name_check, tunnels_result])
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.flush = AsyncMock()
    return session


# ---------------------------------------------------------------------------
# Tests: engine change triggers repush
# ---------------------------------------------------------------------------


class TestEngineChangeTriggersRepush:
    """When ipsec_engine changes, update_server must re-push tunnels with the new engine."""

    @pytest.mark.asyncio
    @patch("app.services.server_service._repush_tunnels_on_engine_change", new_callable=AsyncMock)
    @patch("app.services.server_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.server_service.audit")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_stroke_to_swanctl_triggers_repush(
        self, mock_get_server, mock_audit, mock_lock, mock_repush
    ):
        """PATCH ipsec_engine stroke→swanctl must acquire lock and call repush."""
        from app.services.server_service import update_server
        from app.schemas.server import ServerUpdate

        server = _make_server(ipsec_engine="stroke")
        mock_get_server.return_value = server
        mock_audit.log_action = AsyncMock()

        session = _make_session(tunnels=[])

        data = ServerUpdate(ipsec_engine="swanctl")
        await update_server(session, server.id, data=data, user=MagicMock(id=1), request=None)

        mock_lock.assert_called_once()
        mock_repush.assert_called_once()
        # Repush called with the server (now engine=swanctl) and old_engine="stroke"
        args, kwargs = mock_repush.call_args
        assert args[0] is server
        assert args[1] == "stroke"

    @pytest.mark.asyncio
    @patch("app.services.server_service._repush_tunnels_on_engine_change", new_callable=AsyncMock)
    @patch("app.services.server_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.server_service.audit")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_swanctl_to_stroke_triggers_repush(
        self, mock_get_server, mock_audit, mock_lock, mock_repush
    ):
        """PATCH ipsec_engine swanctl→stroke must acquire lock and call repush."""
        from app.services.server_service import update_server
        from app.schemas.server import ServerUpdate

        server = _make_server(ipsec_engine="swanctl")
        mock_get_server.return_value = server
        mock_audit.log_action = AsyncMock()

        session = _make_session(tunnels=[])

        data = ServerUpdate(ipsec_engine="stroke")
        await update_server(session, server.id, data=data, user=MagicMock(id=1), request=None)

        mock_lock.assert_called_once()
        mock_repush.assert_called_once()
        args, kwargs = mock_repush.call_args
        assert args[0] is server
        assert args[1] == "swanctl"


# ---------------------------------------------------------------------------
# Tests: same engine value — NO repush
# ---------------------------------------------------------------------------


class TestSameEngineNoRepush:
    """Sending the current engine value must not trigger a repush."""

    @pytest.mark.asyncio
    @patch("app.services.server_service._repush_tunnels_on_engine_change", new_callable=AsyncMock)
    @patch("app.services.server_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.server_service.audit")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_same_stroke_engine_no_repush(
        self, mock_get_server, mock_audit, mock_lock, mock_repush
    ):
        from app.services.server_service import update_server
        from app.schemas.server import ServerUpdate

        server = _make_server(ipsec_engine="stroke")
        mock_get_server.return_value = server
        mock_audit.log_action = AsyncMock()

        session = AsyncMock()
        name_check = MagicMock()
        name_check.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=name_check)
        session.commit = AsyncMock()
        session.refresh = AsyncMock()

        data = ServerUpdate(ipsec_engine="stroke")
        await update_server(session, server.id, data=data, user=MagicMock(id=1), request=None)

        mock_lock.assert_not_called()
        mock_repush.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.services.server_service._repush_tunnels_on_engine_change", new_callable=AsyncMock)
    @patch("app.services.server_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.server_service.audit")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_same_swanctl_engine_no_repush(
        self, mock_get_server, mock_audit, mock_lock, mock_repush
    ):
        from app.services.server_service import update_server
        from app.schemas.server import ServerUpdate

        server = _make_server(ipsec_engine="swanctl")
        mock_get_server.return_value = server
        mock_audit.log_action = AsyncMock()

        session = AsyncMock()
        name_check = MagicMock()
        name_check.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=name_check)
        session.commit = AsyncMock()
        session.refresh = AsyncMock()

        data = ServerUpdate(ipsec_engine="swanctl")
        await update_server(session, server.id, data=data, user=MagicMock(id=1), request=None)

        mock_lock.assert_not_called()
        mock_repush.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: unrelated field changes — NO repush
# ---------------------------------------------------------------------------


class TestOtherFieldNoRepush:
    """Changing hostname, port, or name must NOT trigger a repush."""

    @pytest.mark.asyncio
    @patch("app.services.server_service._repush_tunnels_on_engine_change", new_callable=AsyncMock)
    @patch("app.services.server_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.server_service.audit")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    async def test_hostname_change_no_repush(
        self, mock_get_server, mock_audit, mock_lock, mock_repush
    ):
        from app.services.server_service import update_server
        from app.schemas.server import ServerUpdate

        server = _make_server(ipsec_engine="stroke")
        mock_get_server.return_value = server
        mock_audit.log_action = AsyncMock()

        session = AsyncMock()
        name_check = MagicMock()
        name_check.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=name_check)
        session.commit = AsyncMock()
        session.refresh = AsyncMock()

        data = ServerUpdate(hostname="10.0.2.99")
        await update_server(session, server.id, data=data, user=MagicMock(id=1), request=None)

        mock_lock.assert_not_called()
        mock_repush.assert_not_called()


# ---------------------------------------------------------------------------
# Tests: _repush_tunnels_on_engine_change internals
# ---------------------------------------------------------------------------


class TestRepushTunnelsOnEngineChange:
    """Unit tests for _repush_tunnels_on_engine_change."""

    def _make_session_with_tunnels(self, tunnels: list) -> AsyncMock:
        session = AsyncMock()
        tunnels_result = MagicMock()
        tunnels_result.scalars.return_value.all.return_value = tunnels
        session.execute = AsyncMock(return_value=tunnels_result)
        return session

    @pytest.mark.asyncio
    @patch("app.services.server_service.sftp_push_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.server_service.get_transport")
    @patch("app.services.server_service.s3", create=True)
    async def test_stroke_to_swanctl_pushes_and_cleans_old_stroke_files(
        self, mock_s3_module, mock_get_transport, mock_push
    ):
        """stroke→swanctl: push swanctl config AND delete old stroke conf + old stroke secrets."""
        from app.services.server_service import _repush_tunnels_on_engine_change

        server = _make_server(ipsec_engine="swanctl")  # new engine already set
        tunnel = _make_tunnel("t1")

        # S3 returns stroke-format secrets: peer_ip left_ip : PSK "secret123"
        s3_content = '203.0.113.1 10.0.0.1 : PSK "secret123"\n'

        mock_transport = AsyncMock()
        mock_get_transport.return_value = mock_transport

        push_result = ServerResult(server_id=server.id, server_name=server.name, success=True)
        mock_push.return_value = push_result

        session = self._make_session_with_tunnels([tunnel])

        import app.services.ipsec_config as ic
        with patch.object(ic, "render_connection_conf", return_value="conn t1\n"), \
             patch.object(ic, "render_secrets_file", return_value="secrets\n"), \
             patch.object(ic, "render_swanctl_conf", return_value="swanctl\n"), \
             patch("app.services.s3") as s3_patch:
            s3_patch.download_file = AsyncMock(return_value=s3_content)
            await _repush_tunnels_on_engine_change(server, "stroke", session)

        # push was called for the tunnel
        mock_push.assert_called_once()
        push_call_args = mock_push.call_args
        assert push_call_args[0][0] is server
        assert push_call_args[0][1] == "t1"

        # Both old stroke conf and old stroke secrets were deleted (2 calls)
        assert mock_transport.delete_file.call_count == 2
        deleted_paths = [c[0][0] for c in mock_transport.delete_file.call_args_list]
        # One path is the old stroke conf, one is the stroke secrets file
        assert all("t1" in p for p in deleted_paths)
        # None of the deleted paths should be the NEW swanctl conf path
        assert not any("/etc/swanctl/conf.d" in p for p in deleted_paths)

    @pytest.mark.asyncio
    @patch("app.services.server_service.sftp_push_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.server_service.get_transport")
    async def test_swanctl_to_stroke_deletes_old_swanctl_conf(
        self, mock_get_transport, mock_push
    ):
        """swanctl→stroke: push stroke config AND delete old swanctl conf file."""
        from app.services.server_service import _repush_tunnels_on_engine_change

        server = _make_server(ipsec_engine="stroke")  # new engine already set
        tunnel = _make_tunnel("t2")

        s3_content = '203.0.113.1 10.0.0.1 : PSK "another_secret"\n'
        push_result = ServerResult(server_id=server.id, server_name=server.name, success=True)
        mock_push.return_value = push_result

        mock_transport = AsyncMock()
        mock_get_transport.return_value = mock_transport

        session = self._make_session_with_tunnels([tunnel])

        import app.services.ipsec_config as ic
        with patch.object(ic, "render_connection_conf", return_value="conn t2\n"), \
             patch.object(ic, "render_secrets_file", return_value="secrets\n"), \
             patch.object(ic, "render_swanctl_conf", return_value="swanctl\n"), \
             patch("app.services.s3") as s3_patch:
            s3_patch.download_file = AsyncMock(return_value=s3_content)
            await _repush_tunnels_on_engine_change(server, "swanctl", session)

        mock_push.assert_called_once()
        # get_transport IS called to delete the old swanctl conf file
        mock_get_transport.assert_called_once_with(server)
        # delete_file called exactly once for the old swanctl conf
        mock_transport.delete_file.assert_called_once()
        deleted_path = mock_transport.delete_file.call_args[0][0]
        assert "t2" in deleted_path
        # Deleted path must be the old swanctl conf dir, not the new stroke conf dir
        assert "/etc/swanctl/conf.d" in deleted_path or "swanctl" in deleted_path.lower()
        # Must NOT delete the new stroke conf path
        assert "/opt/strongswan/config/connections" not in deleted_path

    @pytest.mark.asyncio
    @patch("app.services.server_service.sftp_push_tunnel_config", new_callable=AsyncMock)
    async def test_push_failure_logged_continues(self, mock_push):
        """A push failure for one tunnel must be logged but not abort other tunnels."""
        from app.services.server_service import _repush_tunnels_on_engine_change

        server = _make_server(ipsec_engine="swanctl")
        tunnel1 = _make_tunnel("t1")
        tunnel2 = _make_tunnel("t2")

        s3_content = '203.0.113.1 10.0.0.1 : PSK "sec"\n'

        # tunnel1 fails, tunnel2 succeeds
        mock_push.side_effect = [
            ServerResult(server_id=server.id, server_name=server.name, success=False, error="timeout"),
            ServerResult(server_id=server.id, server_name=server.name, success=True),
        ]

        session = self._make_session_with_tunnels([tunnel1, tunnel2])

        import app.services.ipsec_config as ic
        with patch.object(ic, "render_connection_conf", return_value="conf\n"), \
             patch.object(ic, "render_secrets_file", return_value="secrets\n"), \
             patch.object(ic, "render_swanctl_conf", return_value="swanctl\n"), \
             patch("app.services.s3") as s3_patch, \
             patch("app.services.server_service.get_transport"):
            s3_patch.download_file = AsyncMock(return_value=s3_content)
            # Must NOT raise
            await _repush_tunnels_on_engine_change(server, "stroke", session)

        # Both tunnels were attempted
        assert mock_push.call_count == 2

    @pytest.mark.asyncio
    async def test_no_tunnels_is_noop(self):
        """No active tunnels: repush logs and returns without error."""
        from app.services.server_service import _repush_tunnels_on_engine_change

        server = _make_server(ipsec_engine="swanctl")
        session = self._make_session_with_tunnels([])

        # Must not raise and must not call push
        with patch("app.services.server_service.sftp_push_tunnel_config") as mock_push:
            await _repush_tunnels_on_engine_change(server, "stroke", session)
            mock_push.assert_not_called()

    @pytest.mark.asyncio
    @patch("app.services.server_service.sftp_push_tunnel_config", new_callable=AsyncMock)
    async def test_psk_not_logged(self, mock_push):
        """The PSK value must never appear in log calls."""
        from app.services.server_service import _repush_tunnels_on_engine_change

        server = _make_server(ipsec_engine="swanctl")
        tunnel = _make_tunnel("t1")
        secret_psk = "TOPSECRETPSK42"
        s3_content = f'203.0.113.1 10.0.0.1 : PSK "{secret_psk}"\n'

        mock_push.return_value = ServerResult(
            server_id=server.id, server_name=server.name, success=True
        )

        session = self._make_session_with_tunnels([tunnel])

        import app.services.ipsec_config as ic
        with patch.object(ic, "render_connection_conf", return_value="conf\n"), \
             patch.object(ic, "render_secrets_file", return_value="secrets\n") as mock_rsf, \
             patch.object(ic, "render_swanctl_conf", return_value="swanctl\n"), \
             patch("app.services.s3") as s3_patch, \
             patch("app.services.server_service.get_transport"), \
             patch("app.services.server_service.logger") as mock_logger:
            s3_patch.download_file = AsyncMock(return_value=s3_content)
            await _repush_tunnels_on_engine_change(server, "stroke", session)

        # Collect all log call kwargs and args as strings
        all_log_text = str(mock_logger.mock_calls)
        assert secret_psk not in all_log_text, "PSK must never appear in log calls"
