"""Phase 4 — Mixed-fleet fan-out tests.

Verifies that execute_on_all_servers, sftp_push_on_all_servers,
sftp_delete_on_all_servers, and sftp_rename_on_all_servers work correctly
when the server fleet contains a mix of SSH and SSM servers.

Each server must obtain its own transport (SSH for SSH servers, SSM for SSM
servers).  The fan-out must succeed end-to-end and the per-server transports
must not bleed into each other.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.transport.base import CommandResult, TransportError, TransportErrorKind
from app.utils.fan_out import FanOutResult, ServerResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ssh_server(id: int = 1, name: str = "ssh-node") -> MagicMock:
    srv = MagicMock()
    srv.id = id
    srv.name = name
    srv.connection_type = "ssh"
    srv.hostname = "10.0.0.1"
    srv.ssh_port = 22
    srv.ssh_user = "admin"
    srv.ssh_private_key_encrypted = b"ENCRYPTED"
    srv.ec2_instance_id = None
    srv.aws_role_arn = None
    srv.aws_region_override = None
    srv.is_active = True
    srv.deleted_at = None
    return srv


def _make_ssm_server(id: int = 2, name: str = "ssm-node") -> MagicMock:
    srv = MagicMock()
    srv.id = id
    srv.name = name
    srv.connection_type = "ssm"
    srv.hostname = None
    srv.ssh_port = None
    srv.ssh_user = None
    srv.ssh_private_key_encrypted = None
    srv.ec2_instance_id = "i-0e8545d009894bb9d"
    srv.aws_role_arn = "arn:aws:iam::123456789012:role/vpn-role"
    srv.aws_region_override = None
    srv.is_active = True
    srv.deleted_at = None
    return srv


def _ok_cmd_result() -> CommandResult:
    return CommandResult(stdout="ok", stderr="", exit_code=0)


# ---------------------------------------------------------------------------
# Mixed-fleet execute_on_all_servers
# ---------------------------------------------------------------------------


class TestMixedFleetExecuteOnAllServers:
    """execute_on_all_servers with one SSH server + one SSM server."""

    @pytest.mark.asyncio
    @patch("app.services.server_service.get_settings")
    async def test_mixed_fleet_both_succeed(self, mock_settings):
        """Both SSH and SSM transports succeed — FanOutResult shows 2/2 succeeded."""
        from app.services.server_service import execute_on_all_servers

        mock_settings.return_value = MagicMock(ssh_command_timeout=30)

        ssh_server = _make_ssh_server(id=1, name="ssh-node")
        ssm_server = _make_ssm_server(id=2, name="ssm-node")

        # Track which transport was used per server
        used_transports: dict[int, str] = {}

        def _fake_get_transport(server):
            t = MagicMock()
            t.execute = AsyncMock(return_value=_ok_cmd_result())
            used_transports[server.id] = server.connection_type
            return t

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [ssh_server, ssm_server]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("app.services.server_service.get_server", new_callable=AsyncMock) as mock_get_server, \
             patch("app.services.server_service.get_transport", side_effect=_fake_get_transport):

            # execute_command loads the server via get_server — wire it
            mock_get_server.side_effect = lambda _session, server_id: (
                ssh_server if server_id == 1 else ssm_server
            )

            result = await execute_on_all_servers(
                mock_session, ["echo ok"]
            )

        assert isinstance(result, FanOutResult)
        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0
        # Verify each server used its own transport type
        assert used_transports[1] == "ssh"
        assert used_transports[2] == "ssm"

    @pytest.mark.asyncio
    @patch("app.services.server_service.get_settings")
    async def test_mixed_fleet_ssm_fails_ssh_succeeds(self, mock_settings):
        """SSM transport fails — SSH still succeeds. FanOutResult shows partial failure."""
        from app.services.server_service import execute_on_all_servers

        mock_settings.return_value = MagicMock(ssh_command_timeout=30)

        ssh_server = _make_ssh_server(id=1, name="ssh-node")
        ssm_server = _make_ssm_server(id=2, name="ssm-node")

        def _fake_get_transport(server):
            t = MagicMock()
            if server.connection_type == "ssm":
                t.execute = AsyncMock(
                    side_effect=TransportError(
                        "SSM agent offline",
                        kind=TransportErrorKind.NODE_UNREACHABLE,
                    )
                )
            else:
                t.execute = AsyncMock(return_value=_ok_cmd_result())
            return t

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [ssh_server, ssm_server]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("app.services.server_service.get_server", new_callable=AsyncMock) as mock_get_server, \
             patch("app.services.server_service.get_transport", side_effect=_fake_get_transport):

            mock_get_server.side_effect = lambda _session, server_id: (
                ssh_server if server_id == 1 else ssm_server
            )

            result = await execute_on_all_servers(mock_session, ["echo ok"])

        assert result.total == 2
        assert result.succeeded == 1
        assert result.failed == 1
        assert result.is_partial
        # SSH server succeeded
        ssh_result = next(r for r in result.servers if r.server_id == 1)
        assert ssh_result.success is True
        # SSM server failed with transport error in the message
        ssm_result = next(r for r in result.servers if r.server_id == 2)
        assert ssm_result.success is False
        assert "SSM agent offline" in ssm_result.error or "Transport error" in ssm_result.error


# ---------------------------------------------------------------------------
# Mixed-fleet sftp_push_on_all_servers
# ---------------------------------------------------------------------------


class TestMixedFleetSftpPush:
    """sftp_push_on_all_servers with SSH + SSM servers in the fleet."""

    @pytest.mark.asyncio
    @patch("app.services.server_service.get_settings")
    async def test_push_mixed_fleet_both_succeed(self, mock_settings):
        """Config push succeeds on both SSH and SSM transports."""
        from app.services.server_service import sftp_push_on_all_servers

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/etc/swanctl/conf.d",
            vpn_secrets_dir="/etc/swanctl/secrets",
        )

        ssh_server = _make_ssh_server(id=1, name="ssh-node")
        ssm_server = _make_ssm_server(id=2, name="ssm-node")

        used_transports: dict[int, str] = {}

        def _fake_get_transport(server):
            t = MagicMock()
            t.write_file = AsyncMock()
            t.execute = AsyncMock(return_value=_ok_cmd_result())
            used_transports[server.id] = server.connection_type
            return t

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [ssh_server, ssm_server]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("app.services.server_service.get_transport", side_effect=_fake_get_transport):
            result = await sftp_push_on_all_servers(
                mock_session,
                name="vpn-tunnel-1",
                conf_content="conn vpn-tunnel-1 {}",
                secrets_content=": PSK secret",
            )

        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0
        assert used_transports[1] == "ssh"
        assert used_transports[2] == "ssm"


# ---------------------------------------------------------------------------
# Mixed-fleet sftp_delete_on_all_servers
# ---------------------------------------------------------------------------


class TestMixedFleetSftpDelete:
    """sftp_delete_on_all_servers with SSH + SSM servers in the fleet."""

    @pytest.mark.asyncio
    @patch("app.services.server_service.get_settings")
    async def test_delete_mixed_fleet_both_succeed(self, mock_settings):
        """Config delete succeeds on both SSH and SSM transports."""
        from app.services.server_service import sftp_delete_on_all_servers

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/etc/swanctl/conf.d",
            vpn_secrets_dir="/etc/swanctl/secrets",
        )

        ssh_server = _make_ssh_server(id=1, name="ssh-node")
        ssm_server = _make_ssm_server(id=2, name="ssm-node")

        used_transports: dict[int, str] = {}

        def _fake_get_transport(server):
            t = MagicMock()
            t.delete_file = AsyncMock()
            t.execute = AsyncMock(return_value=_ok_cmd_result())
            used_transports[server.id] = server.connection_type
            return t

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [ssh_server, ssm_server]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("app.services.server_service.get_transport", side_effect=_fake_get_transport):
            result = await sftp_delete_on_all_servers(
                mock_session,
                name="vpn-tunnel-1",
            )

        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0
        assert used_transports[1] == "ssh"
        assert used_transports[2] == "ssm"


# ---------------------------------------------------------------------------
# Mixed-fleet sftp_rename_on_all_servers
# ---------------------------------------------------------------------------


class TestMixedFleetSftpRename:
    """sftp_rename_on_all_servers with SSH + SSM servers in the fleet."""

    @pytest.mark.asyncio
    @patch("app.services.server_service.get_settings")
    async def test_rename_mixed_fleet_both_succeed(self, mock_settings):
        """Config rename (delete-old + push-new) succeeds on both transports."""
        from app.services.server_service import sftp_rename_on_all_servers

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/etc/swanctl/conf.d",
            vpn_secrets_dir="/etc/swanctl/secrets",
        )

        ssh_server = _make_ssh_server(id=1, name="ssh-node")
        ssm_server = _make_ssm_server(id=2, name="ssm-node")

        used_transports: dict[int, str] = {}

        def _fake_get_transport(server):
            t = MagicMock()
            t.delete_file = AsyncMock()
            t.write_file = AsyncMock()
            t.execute = AsyncMock(return_value=_ok_cmd_result())
            used_transports[server.id] = server.connection_type
            return t

        mock_session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [ssh_server, ssm_server]
        mock_session.execute = AsyncMock(return_value=mock_result)

        with patch("app.services.server_service.get_transport", side_effect=_fake_get_transport):
            result = await sftp_rename_on_all_servers(
                mock_session,
                old_name="vpn-tunnel-1",
                new_name="vpn-tunnel-renamed",
                conf_content="conn vpn-tunnel-renamed {}",
                secrets_content=": PSK secret",
            )

        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0
        assert used_transports[1] == "ssh"
        assert used_transports[2] == "ssm"


# ---------------------------------------------------------------------------
# create_server — SSM path
# ---------------------------------------------------------------------------


class TestCreateServerSSM:
    """create_server correctly handles SSM servers without touching SSH key logic."""

    @pytest.mark.asyncio
    async def test_create_ssm_server_no_ssh_key(self):
        """SSM server creation succeeds without an SSH key."""
        from app.services.server_service import create_server

        # ServerCreate-like object for an SSM server
        data = MagicMock()
        data.name = "ssm-vpn-1"
        data.connection_type = "ssm"
        data.ec2_instance_id = "i-0e8545d009894bb9d"
        data.aws_role_arn = "arn:aws:iam::123456789012:role/vpn-role"
        data.aws_region_override = None
        data.description = "SSM-managed VPN node"
        data.ssh_private_key = None  # No key for SSM

        user = MagicMock()
        user.id = 1

        session = AsyncMock()
        # name uniqueness check returns no conflict
        existing_result = MagicMock()
        existing_result.scalar_one_or_none.return_value = None
        # flush + commit
        session.execute = AsyncMock(return_value=existing_result)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()

        with patch("app.services.server_service.audit") as mock_audit:
            mock_audit.log_action = AsyncMock()
            # Should NOT raise even though ssh_private_key is None
            server = await create_server(session, data=data, user=user, request=None)

        session.add.assert_called_once()
        added_server = session.add.call_args[0][0]
        assert added_server.connection_type == "ssm"
        assert added_server.ec2_instance_id == "i-0e8545d009894bb9d"
        assert added_server.ssh_private_key_encrypted is None
        assert added_server.hostname is None

    @pytest.mark.asyncio
    async def test_create_ssm_server_does_not_call_validate_ssh_key(self):
        """SSM server creation must not call validate_ssh_private_key."""
        from app.services.server_service import create_server

        data = MagicMock()
        data.name = "ssm-vpn-2"
        data.connection_type = "ssm"
        data.ec2_instance_id = "i-0e8545d009894bb9d"
        data.aws_role_arn = None
        data.aws_region_override = None
        data.description = None
        data.ssh_private_key = None

        user = MagicMock()
        user.id = 1

        session = AsyncMock()
        existing_result = MagicMock()
        existing_result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=existing_result)
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()

        with patch("app.services.server_service.validate_ssh_private_key") as mock_validate, \
             patch("app.services.server_service.audit") as mock_audit:
            mock_audit.log_action = AsyncMock()
            await create_server(session, data=data, user=user, request=None)

        # Must NOT be called for SSM servers
        mock_validate.assert_not_called()


# ---------------------------------------------------------------------------
# SSM server test_connection / check_status via service
# ---------------------------------------------------------------------------


class TestSSMServerConnectivity:
    """test_connection and check_status return SSM-appropriate messages."""

    @pytest.mark.asyncio
    async def test_test_connection_ssm_success(self):
        """test_connection returns 'SSM connection successful' for SSM server."""
        from app.services.server_service import test_connection

        ssm_server = _make_ssm_server(id=10, name="ssm-primary")
        # check_reachable must not raise
        mock_transport = MagicMock()
        mock_transport.check_reachable = AsyncMock(return_value=True)

        session = AsyncMock()

        with patch("app.services.server_service.get_server", new_callable=AsyncMock, return_value=ssm_server), \
             patch("app.services.server_service.get_transport", return_value=mock_transport):
            result = await test_connection(session, server_id=10)

        assert result["success"] is True
        assert "SSM" in result["message"]
        assert "successful" in result["message"]

    @pytest.mark.asyncio
    async def test_test_connection_ssm_failure(self):
        """test_connection returns 'SSM connection failed' on TransportError."""
        from app.services.server_service import test_connection

        ssm_server = _make_ssm_server(id=10, name="ssm-primary")
        mock_transport = MagicMock()
        mock_transport.check_reachable = AsyncMock(
            side_effect=TransportError(
                "Instance not registered with SSM",
                kind=TransportErrorKind.NODE_UNREACHABLE,
            )
        )

        session = AsyncMock()

        with patch("app.services.server_service.get_server", new_callable=AsyncMock, return_value=ssm_server), \
             patch("app.services.server_service.get_transport", return_value=mock_transport):
            result = await test_connection(session, server_id=10)

        assert result["success"] is False
        assert "SSM" in result["message"]
        assert "failed" in result["message"]

    @pytest.mark.asyncio
    async def test_check_status_ssm_reachable(self):
        """check_status returns 'reachable' with SSM message for SSM server."""
        from app.services.server_service import check_status

        ssm_server = _make_ssm_server(id=10, name="ssm-primary")
        mock_transport = MagicMock()
        mock_transport.check_reachable = AsyncMock(return_value=True)

        session = AsyncMock()

        with patch("app.services.server_service.get_server", new_callable=AsyncMock, return_value=ssm_server), \
             patch("app.services.server_service.get_transport", return_value=mock_transport):
            result = await check_status(session, server_id=10)

        assert result["success"] is True
        assert result["status"] == "reachable"
        assert "SSM" in result["message"]
