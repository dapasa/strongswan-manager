"""Tests for SSH fan-out infrastructure — Phases 7.1–7.7 of tunnel-ssh-migration.

Covers:
    7.1  execute_command() — success, SSH error, timeout, non-zero exit
    7.2  execute_on_all_servers() — all succeed, partial, all fail, zero servers
    7.3  FanOutResult aggregation helpers
    7.4  delete_tunnel() blocking logic
    7.5  retry_tunnel_sync() allowed statuses
    7.6  tunnel status aggregation (_aggregate_tunnel_states)
    7.7  Health endpoint SSH check
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.exceptions import InfrastructureError
from app.utils.fan_out import FanOutResult, ServerResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(id: int = 1, name: str = "vpn-1") -> MagicMock:
    srv = MagicMock()
    srv.id = id
    srv.name = name
    srv.hostname = "10.0.0.1"
    srv.ssh_port = 22
    srv.ssh_user = "admin"
    srv.ssh_private_key_encrypted = b"ENCRYPTED"
    srv.is_active = True
    srv.deleted_at = None
    return srv


def _make_fan_out(total: int, succeeded: int) -> FanOutResult:
    failed = total - succeeded
    servers = []
    for i in range(succeeded):
        servers.append(ServerResult(server_id=i + 1, server_name=f"vpn-{i+1}", success=True, output="ok"))
    for i in range(failed):
        servers.append(ServerResult(server_id=succeeded + i + 1, server_name=f"vpn-{succeeded+i+1}", success=False, error="Connection refused"))
    return FanOutResult(total=total, succeeded=succeeded, failed=failed, servers=servers)


# ---------------------------------------------------------------------------
# 7.1  execute_command()
# ---------------------------------------------------------------------------


class TestExecuteCommand:
    """Unit tests for server_service.execute_command()."""

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    @patch("app.services.server_service.get_settings")
    async def test_success(self, mock_settings, mock_get_server, mock_decrypt, mock_import_key):
        """execute_command returns success=True with stdout on clean run."""
        from app.services.server_service import execute_command

        mock_settings.return_value = MagicMock(ssh_command_timeout=30)
        server = _make_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        mock_run_result = MagicMock()
        mock_run_result.exit_status = 0
        mock_run_result.stdout = "command output\n"
        mock_run_result.stderr = ""

        mock_conn = MagicMock()
        mock_conn.run = AsyncMock(return_value=mock_run_result)
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_cm):
            session = AsyncMock()
            result = await execute_command(session, server_id=1, commands=["echo ok"])

        assert result.success is True
        assert result.output == "command output\n"
        assert result.server_id == 1
        assert result.server_name == "vpn-1"
        assert result.error == ""

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    @patch("app.services.server_service.get_settings")
    async def test_ssh_connection_error(self, mock_settings, mock_get_server, mock_decrypt, mock_import_key):
        """execute_command returns success=False with error message on SSH error."""
        import asyncssh

        from app.services.server_service import execute_command

        mock_settings.return_value = MagicMock(ssh_command_timeout=30)
        server = _make_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        with patch(
            "app.services.server_service.asyncssh.connect",
            side_effect=asyncssh.ConnectionLost("Connection lost"),
        ):
            session = AsyncMock()
            result = await execute_command(session, server_id=1, commands=["echo ok"])

        assert result.success is False
        assert "SSH error" in result.error
        assert result.server_id == 1

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    @patch("app.services.server_service.get_settings")
    async def test_nonzero_exit_status(self, mock_settings, mock_get_server, mock_decrypt, mock_import_key):
        """execute_command returns success=False when command exits non-zero."""
        from app.services.server_service import execute_command

        mock_settings.return_value = MagicMock(ssh_command_timeout=30)
        server = _make_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        mock_run_result = MagicMock()
        mock_run_result.exit_status = 1
        mock_run_result.stdout = ""
        mock_run_result.stderr = "command failed"

        mock_conn = MagicMock()
        mock_conn.run = AsyncMock(return_value=mock_run_result)
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_cm):
            session = AsyncMock()
            result = await execute_command(session, server_id=1, commands=["bad-command"])

        assert result.success is False
        assert "status 1" in result.error
        assert "command failed" in result.error

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_server", new_callable=AsyncMock)
    @patch("app.services.server_service.get_settings")
    async def test_command_timeout(self, mock_settings, mock_get_server, mock_decrypt, mock_import_key):
        """execute_command returns success=False with 'timed out' on asyncio.TimeoutError."""
        from app.services.server_service import execute_command

        mock_settings.return_value = MagicMock(ssh_command_timeout=30)
        server = _make_server()
        mock_get_server.return_value = server
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        mock_conn = MagicMock()
        mock_conn.run = AsyncMock(side_effect=asyncio.TimeoutError())
        mock_cm = MagicMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_conn)
        mock_cm.__aexit__ = AsyncMock(return_value=False)

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_cm):
            with patch("asyncio.wait_for", side_effect=asyncio.TimeoutError()):
                session = AsyncMock()
                result = await execute_command(session, server_id=1, commands=["sleep 60"])

        assert result.success is False
        assert "timed out" in result.error.lower()


# ---------------------------------------------------------------------------
# 7.2  execute_on_all_servers()
# ---------------------------------------------------------------------------


class TestExecuteOnAllServers:
    """Unit tests for server_service.execute_on_all_servers()."""

    @patch("app.services.server_service.execute_command", new_callable=AsyncMock)
    async def test_all_succeed(self, mock_exec):
        """All servers succeed → FanOutResult.is_success == True."""
        from app.services.server_service import execute_on_all_servers

        servers = [_make_server(1, "vpn-1"), _make_server(2, "vpn-2")]
        mock_exec.side_effect = [
            ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok"),
            ServerResult(server_id=2, server_name="vpn-2", success=True, output="ok"),
        ]

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = servers
        session.execute = AsyncMock(return_value=mock_result)

        result = await execute_on_all_servers(session, ["echo ok"])

        assert result.is_success is True
        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0

    @patch("app.services.server_service.execute_command", new_callable=AsyncMock)
    async def test_partial_failure(self, mock_exec):
        """One server fails → FanOutResult.is_partial == True, counts correct."""
        from app.services.server_service import execute_on_all_servers

        servers = [_make_server(1, "vpn-1"), _make_server(2, "vpn-2"), _make_server(3, "vpn-3")]
        mock_exec.side_effect = [
            ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok"),
            ServerResult(server_id=2, server_name="vpn-2", success=False, error="Connection refused"),
            ServerResult(server_id=3, server_name="vpn-3", success=True, output="ok"),
        ]

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = servers
        session.execute = AsyncMock(return_value=mock_result)

        result = await execute_on_all_servers(session, ["echo ok"])

        assert result.is_partial is True
        assert result.succeeded == 2
        assert result.failed == 1
        assert result.total == 3

    @patch("app.services.server_service.execute_command", new_callable=AsyncMock)
    async def test_all_fail(self, mock_exec):
        """All servers fail → FanOutResult.is_total_failure == True."""
        from app.services.server_service import execute_on_all_servers

        servers = [_make_server(1, "vpn-1"), _make_server(2, "vpn-2")]
        mock_exec.side_effect = [
            ServerResult(server_id=1, server_name="vpn-1", success=False, error="refused"),
            ServerResult(server_id=2, server_name="vpn-2", success=False, error="refused"),
        ]

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = servers
        session.execute = AsyncMock(return_value=mock_result)

        result = await execute_on_all_servers(session, ["echo ok"])

        assert result.is_total_failure is True
        assert result.succeeded == 0
        assert result.failed == 2

    async def test_zero_servers_raises(self):
        """Zero active servers → raises InfrastructureError."""
        from app.services.server_service import execute_on_all_servers

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=mock_result)

        with pytest.raises(InfrastructureError) as exc_info:
            await execute_on_all_servers(session, ["echo ok"])

        assert "No active servers" in exc_info.value.message


# ---------------------------------------------------------------------------
# 7.3  FanOutResult aggregation helpers
# ---------------------------------------------------------------------------


class TestFanOutResultAggregation:
    """Unit tests for FanOutResult.to_sync_status, to_sync_details, to_sync_error."""

    def test_to_sync_status_synced(self):
        result = _make_fan_out(total=3, succeeded=3)
        assert result.to_sync_status() == "synced"

    def test_to_sync_status_partial(self):
        result = _make_fan_out(total=3, succeeded=2)
        assert result.to_sync_status() == "partial"

    def test_to_sync_status_failed(self):
        result = _make_fan_out(total=3, succeeded=0)
        assert result.to_sync_status() == "failed"

    def test_to_sync_details_structure(self):
        result = _make_fan_out(total=2, succeeded=1)
        details = result.to_sync_details()

        assert details["total"] == 2
        assert details["succeeded"] == 1
        assert details["failed"] == 1
        assert len(details["servers"]) == 2

        # Check success entry
        success_entry = next(s for s in details["servers"] if s["success"])
        assert success_entry["server_id"] is not None
        assert success_entry["server_name"] is not None
        assert "error" in success_entry

        # Check failure entry
        fail_entry = next(s for s in details["servers"] if not s["success"])
        assert fail_entry["error"] is not None

    def test_to_sync_error_returns_none_on_success(self):
        result = _make_fan_out(total=2, succeeded=2)
        assert result.to_sync_error() is None

    def test_to_sync_error_returns_summary_on_failure(self):
        result = _make_fan_out(total=3, succeeded=1)
        error = result.to_sync_error()
        assert error is not None
        assert "2 of 3" in error

    def test_to_sync_error_total_failure(self):
        result = _make_fan_out(total=3, succeeded=0)
        error = result.to_sync_error()
        assert error is not None
        assert "3 of 3" in error

    def test_is_partial_requires_both_success_and_failure(self):
        assert _make_fan_out(3, 2).is_partial is True
        assert _make_fan_out(3, 3).is_partial is False
        assert _make_fan_out(3, 0).is_partial is False

    def test_is_total_failure_only_when_zero_succeeded(self):
        assert _make_fan_out(3, 0).is_total_failure is True
        assert _make_fan_out(3, 1).is_total_failure is False

    def test_is_success_only_when_zero_failed(self):
        assert _make_fan_out(3, 3).is_success is True
        assert _make_fan_out(3, 2).is_success is False


# ---------------------------------------------------------------------------
# 7.4  delete_tunnel() blocking logic
# ---------------------------------------------------------------------------


class TestDeleteTunnelBlocking:
    """Tests for the blocking delete semantic in tunnel_service.delete_tunnel()."""

    @patch("app.services.tunnel_service.ipsec_config.remove_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._cleanup_tunnel_iptables", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_delete_succeeds_all_servers_confirm(
        self, mock_get_tunnel, mock_lock, mock_audit, mock_cleanup, mock_remove
    ):
        """Tunnel is soft-deleted when all servers confirm removal."""
        from app.services.tunnel_service import delete_tunnel

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "test-tunnel"
        tunnel.routes = []
        tunnel.iptables_rules = []
        tunnel.deleted_at = None
        mock_get_tunnel.return_value = tunnel
        mock_remove.return_value = _make_fan_out(total=2, succeeded=2)

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        await delete_tunnel(session, 1, user=user)

        # Tunnel must be soft-deleted
        assert tunnel.deleted_at is not None
        session.commit.assert_called_once()

    @patch("app.services.tunnel_service.ipsec_config.remove_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._cleanup_tunnel_iptables", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_delete_blocked_partial_server_failure(
        self, mock_get_tunnel, mock_lock, mock_audit, mock_cleanup, mock_remove
    ):
        """Delete is blocked and InfrastructureError raised when any server fails."""
        from app.services.tunnel_service import delete_tunnel

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "test-tunnel"
        tunnel.routes = []
        tunnel.iptables_rules = []
        tunnel.deleted_at = None
        mock_get_tunnel.return_value = tunnel
        mock_remove.return_value = _make_fan_out(total=3, succeeded=2)  # 1 failure

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        with pytest.raises(InfrastructureError) as exc_info:
            await delete_tunnel(session, 1, user=user)

        # Tunnel must NOT be soft-deleted
        assert tunnel.deleted_at is None
        assert "aborted" in exc_info.value.message.lower()

    @patch("app.services.tunnel_service.ipsec_config.remove_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._cleanup_tunnel_iptables", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_delete_blocked_all_servers_fail(
        self, mock_get_tunnel, mock_lock, mock_audit, mock_cleanup, mock_remove
    ):
        """Delete is blocked when all servers fail."""
        from app.services.tunnel_service import delete_tunnel

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "test-tunnel"
        tunnel.routes = []
        tunnel.iptables_rules = []
        tunnel.deleted_at = None
        mock_get_tunnel.return_value = tunnel
        mock_remove.return_value = _make_fan_out(total=2, succeeded=0)

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        with pytest.raises(InfrastructureError):
            await delete_tunnel(session, 1, user=user)

        assert tunnel.deleted_at is None

    @patch("app.services.tunnel_service.ipsec_config.remove_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._cleanup_tunnel_iptables", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_iptables_cascade_called_before_ssh_sync(
        self, mock_get_tunnel, mock_lock, mock_audit, mock_cleanup, mock_remove
    ):
        """Iptables cascade is called before SSH fan-out remove."""
        from app.services.tunnel_service import delete_tunnel

        call_order = []
        mock_cleanup.side_effect = lambda *a, **kw: call_order.append("iptables") or None
        mock_remove.side_effect = lambda *a, **kw: call_order.append("ssh") or _make_fan_out(2, 2)

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "test-tunnel"
        tunnel.routes = []
        tunnel.iptables_rules = []
        tunnel.deleted_at = None
        mock_get_tunnel.return_value = tunnel

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        await delete_tunnel(session, 1, user=user)

        assert call_order.index("iptables") < call_order.index("ssh")


# ---------------------------------------------------------------------------
# 7.5  retry_tunnel_sync() allowed statuses
# ---------------------------------------------------------------------------


class TestRetryTunnelSync:
    """Tests for retry_tunnel_sync() status guard."""

    @patch("app.services.tunnel_service.sftp_push_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.s3.upload_file", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_retry_allowed_when_failed(
        self, mock_get_tunnel, mock_lock, mock_audit, mock_upload, mock_fan_out
    ):
        """Retry is allowed when sync_status == 'failed'."""
        from app.services.tunnel_service import retry_tunnel_sync

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "test-tunnel"
        tunnel.sync_status = "failed"
        tunnel.local_cidrs = ["10.0.0.0/24"]
        tunnel.remote_cidrs = ["192.168.1.0/24"]
        tunnel.peer_ip = "1.2.3.4"
        tunnel.ike_version = "2"
        tunnel.ike_proposals = None
        tunnel.esp_proposals = None
        tunnel.dpd_action = "restart"
        tunnel.dpd_delay = 30
        tunnel.dpd_timeout = 150
        mock_get_tunnel.return_value = tunnel
        mock_fan_out.return_value = _make_fan_out(2, 2)

        session = AsyncMock()
        user = MagicMock()

        result = await retry_tunnel_sync(session, 1, user=user)
        assert result.sync_status == "synced"

    @patch("app.services.tunnel_service.sftp_push_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.s3.upload_file", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_retry_allowed_when_partial(
        self, mock_get_tunnel, mock_lock, mock_audit, mock_upload, mock_fan_out
    ):
        """Retry is allowed when sync_status == 'partial'."""
        from app.services.tunnel_service import retry_tunnel_sync

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "test-tunnel"
        tunnel.sync_status = "partial"
        tunnel.local_cidrs = ["10.0.0.0/24"]
        tunnel.remote_cidrs = ["192.168.1.0/24"]
        tunnel.peer_ip = "1.2.3.4"
        tunnel.ike_version = "2"
        tunnel.ike_proposals = None
        tunnel.esp_proposals = None
        tunnel.dpd_action = "restart"
        tunnel.dpd_delay = 30
        tunnel.dpd_timeout = 150
        mock_get_tunnel.return_value = tunnel
        mock_fan_out.return_value = _make_fan_out(2, 2)

        session = AsyncMock()
        user = MagicMock()

        result = await retry_tunnel_sync(session, 1, user=user)
        assert result.sync_status == "synced"

    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_retry_not_allowed_when_synced(self, mock_get_tunnel):
        """Retry raises ConflictError when sync_status == 'synced'."""
        from app.exceptions import ConflictError
        from app.services.tunnel_service import retry_tunnel_sync

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.sync_status = "synced"
        mock_get_tunnel.return_value = tunnel

        session = AsyncMock()
        user = MagicMock()

        with pytest.raises(ConflictError):
            await retry_tunnel_sync(session, 1, user=user)

    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_retry_not_allowed_when_pending(self, mock_get_tunnel):
        """Retry raises ConflictError when sync_status == 'pending'."""
        from app.exceptions import ConflictError
        from app.services.tunnel_service import retry_tunnel_sync

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.sync_status = "pending"
        mock_get_tunnel.return_value = tunnel

        session = AsyncMock()
        user = MagicMock()

        with pytest.raises(ConflictError):
            await retry_tunnel_sync(session, 1, user=user)


# ---------------------------------------------------------------------------
# 7.6  Tunnel status aggregation (_aggregate_tunnel_states)
# ---------------------------------------------------------------------------


class TestAggregateTunnelStates:
    """Unit tests for _aggregate_tunnel_states() and _parse_tunnel_state()."""

    def test_all_up_returns_up(self):
        from app.services.tunnel_service import _aggregate_tunnel_states

        assert _aggregate_tunnel_states(["UP", "UP", "UP"]) == "UP"

    def test_mixed_up_down_returns_partial(self):
        from app.services.tunnel_service import _aggregate_tunnel_states

        assert _aggregate_tunnel_states(["UP", "DOWN", "DOWN"]) == "PARTIAL"

    def test_mixed_up_unknown_returns_partial(self):
        from app.services.tunnel_service import _aggregate_tunnel_states

        assert _aggregate_tunnel_states(["UP", "UNKNOWN"]) == "PARTIAL"

    def test_all_down_returns_down(self):
        from app.services.tunnel_service import _aggregate_tunnel_states

        assert _aggregate_tunnel_states(["DOWN", "DOWN"]) == "DOWN"

    def test_all_unknown_returns_unknown(self):
        from app.services.tunnel_service import _aggregate_tunnel_states

        assert _aggregate_tunnel_states(["UNKNOWN", "UNKNOWN"]) == "UNKNOWN"

    def test_empty_states_returns_unknown(self):
        from app.services.tunnel_service import _aggregate_tunnel_states

        assert _aggregate_tunnel_states([]) == "UNKNOWN"

    def test_down_and_unknown_returns_down(self):
        from app.services.tunnel_service import _aggregate_tunnel_states

        assert _aggregate_tunnel_states(["DOWN", "UNKNOWN"]) == "DOWN"

    def test_parse_tunnel_state_established(self):
        from app.services.tunnel_service import _parse_tunnel_state

        output = "vpn-tunnel[1]: ESTABLISHED 2 minutes ago\n  vpn-tunnel{1}:  INSTALLED"
        assert _parse_tunnel_state("vpn-tunnel", output) == "UP"

    def test_parse_tunnel_state_down(self):
        from app.services.tunnel_service import _parse_tunnel_state

        output = "vpn-tunnel: no match found\nvpn-tunnel: down"
        assert _parse_tunnel_state("vpn-tunnel", output) == "DOWN"

    def test_parse_tunnel_state_unknown_when_empty(self):
        from app.services.tunnel_service import _parse_tunnel_state

        assert _parse_tunnel_state("vpn-tunnel", "") == "UNKNOWN"

    def test_parse_tunnel_state_unknown_when_not_found(self):
        from app.services.tunnel_service import _parse_tunnel_state

        output = "other-tunnel: ESTABLISHED\nanother-tunnel: INSTALLED"
        assert _parse_tunnel_state("vpn-tunnel", output) == "UNKNOWN"

    @patch("app.services.tunnel_service.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_get_tunnel_status_all_established(self, mock_get_tunnel, mock_fan_out):
        """get_tunnel_status returns state=UP when all servers report ESTABLISHED."""
        from app.services.tunnel_service import get_tunnel_status

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "vpn-tunnel"
        mock_get_tunnel.return_value = tunnel

        mock_fan_out.return_value = FanOutResult(
            total=2,
            succeeded=2,
            failed=0,
            servers=[
                ServerResult(1, "vpn-1", True, output="vpn-tunnel: ESTABLISHED"),
                ServerResult(2, "vpn-2", True, output="vpn-tunnel: ESTABLISHED"),
            ],
        )

        session = AsyncMock()
        result = await get_tunnel_status(session, 1)

        assert result["state"] == "UP"
        assert len(result["per_server"]) == 2

    @patch("app.services.tunnel_service.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_get_tunnel_status_all_down(self, mock_get_tunnel, mock_fan_out):
        """get_tunnel_status returns state=DOWN when all servers report DOWN."""
        from app.services.tunnel_service import get_tunnel_status

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "vpn-tunnel"
        mock_get_tunnel.return_value = tunnel

        mock_fan_out.return_value = FanOutResult(
            total=2,
            succeeded=2,
            failed=0,
            servers=[
                ServerResult(1, "vpn-1", True, output="vpn-tunnel: not found"),
                ServerResult(2, "vpn-2", True, output="vpn-tunnel: not found"),
            ],
        )

        session = AsyncMock()
        result = await get_tunnel_status(session, 1)

        assert result["state"] == "DOWN"


# ---------------------------------------------------------------------------
# 7.7  Health endpoint SSH check
# ---------------------------------------------------------------------------


class TestHealthEndpointSSH:
    """Integration-style tests for the /health/ready endpoint SSH check."""

    def _build_fan_out(self, total: int, succeeded: int) -> FanOutResult:
        return _make_fan_out(total, succeeded)

    @patch("app.routers.health.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.routers.health.s3.check_connectivity", new_callable=AsyncMock)
    async def test_all_servers_reachable_healthy(self, mock_s3, mock_fan_out):
        """All servers reachable → ssh=ok → overall status=ok (if db+s3 ok)."""
        import httpx

        from app.main import app

        mock_s3.return_value = True
        mock_fan_out.return_value = self._build_fan_out(total=2, succeeded=2)

        async def _override_get_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=MagicMock())
            yield db

        from app.db.session import get_db
        app.dependency_overrides[get_db] = _override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health/ready")

        app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["ssh"] == "ok"
        assert data["status"] == "ok"

    @patch("app.routers.health.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.routers.health.s3.check_connectivity", new_callable=AsyncMock)
    async def test_partial_servers_degraded(self, mock_s3, mock_fan_out):
        """Some servers unreachable → ssh=degraded → status=not_ready."""
        import httpx

        from app.main import app

        mock_s3.return_value = True
        mock_fan_out.return_value = self._build_fan_out(total=3, succeeded=2)

        async def _override_get_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=MagicMock())
            yield db

        from app.db.session import get_db
        app.dependency_overrides[get_db] = _override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health/ready")

        app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["ssh"] == "degraded"
        assert data["status"] == "not_ready"

    @patch("app.routers.health.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.routers.health.s3.check_connectivity", new_callable=AsyncMock)
    async def test_all_servers_fail_unhealthy(self, mock_s3, mock_fan_out):
        """All servers unreachable → ssh=failed → status=not_ready."""
        import httpx

        from app.main import app

        mock_s3.return_value = True
        mock_fan_out.return_value = self._build_fan_out(total=2, succeeded=0)

        async def _override_get_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=MagicMock())
            yield db

        from app.db.session import get_db
        app.dependency_overrides[get_db] = _override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health/ready")

        app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["ssh"] == "failed"
        assert data["status"] == "not_ready"

    @patch("app.routers.health.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.routers.health.s3.check_connectivity", new_callable=AsyncMock)
    async def test_no_servers_registered_warn(self, mock_s3, mock_fan_out):
        """No servers registered → ssh=warn (not a hard failure)."""
        import httpx

        from app.main import app

        mock_s3.return_value = True
        mock_fan_out.side_effect = InfrastructureError(
            service="SSH", message="No active servers registered"
        )

        async def _override_get_db():
            db = AsyncMock()
            db.execute = AsyncMock(return_value=MagicMock())
            yield db

        from app.db.session import get_db
        app.dependency_overrides[get_db] = _override_get_db

        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get("/health/ready")

        app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["checks"]["ssh"] == "warn"
        # With warn, not all checks are "ok", so status is not_ready
        assert data["status"] == "not_ready"
