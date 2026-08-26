"""Tests for SSH-based tunnel config push/delete/rename functions.

Covers:
    sftp_push_tunnel_config — success, secrets=None, SSH command failure, swanctl non-zero
    sftp_delete_tunnel_config — success, file-not-found is idempotent (rm -f)
    sftp_push_on_all_servers — all succeed, partial failure
    sftp_delete_on_all_servers — all succeed
    sftp_rename_on_all_servers — success (delete old + push new)

All file writes use sudo tee via conn.run() — no SFTP client is used.
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

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


def _make_run_result(exit_status: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    r = MagicMock()
    r.exit_status = exit_status
    r.stdout = stdout
    r.stderr = stderr
    return r


def _build_conn_mock(run_side_effect=None, run_return_value=None):
    """Build SSH connection context manager mock.

    All file operations and swanctl go through conn.run().

    Args:
        run_side_effect: If provided, used as side_effect for conn.run (list of results or exception).
        run_return_value: If provided (and no side_effect), returned for every conn.run call.

    Returns:
        (mock_conn_cm, mock_conn)
    """
    mock_conn = MagicMock()
    if run_side_effect is not None:
        mock_conn.run = AsyncMock(side_effect=run_side_effect)
    else:
        result = run_return_value if run_return_value is not None else _make_run_result()
        mock_conn.run = AsyncMock(return_value=result)

    mock_conn_cm = MagicMock()
    mock_conn_cm.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn_cm.__aexit__ = AsyncMock(return_value=False)

    return mock_conn_cm, mock_conn


# ---------------------------------------------------------------------------
# sftp_push_tunnel_config
# ---------------------------------------------------------------------------


class TestSftpPushTunnelConfig:
    """Unit tests for server_service.sftp_push_tunnel_config()."""

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_success_writes_conf_and_secrets(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """Success path: mkdir, tee, chmod for conf + secrets, then swanctl."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        # With secrets: mkdir conf, tee conf, chmod conf, mkdir secrets, tee secrets, chmod secrets, swanctl
        ok = _make_run_result()
        mock_conn_cm, mock_conn = _build_conn_mock(
            run_side_effect=[ok, ok, ok, ok, ok, ok, ok]
        )

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_push_tunnel_config(
                server,
                name="my-tunnel",
                conf_content="conn my-tunnel\n",
                secrets_content="10.0.0.1 : PSK secret\n",
            )

        assert result.success is True
        assert result.server_id == 1
        assert result.server_name == "vpn-1"
        assert mock_conn.run.call_count == 7

        # Verify the exact commands sent (order matters)
        calls = [c.args[0] for c in mock_conn.run.call_args_list]
        assert calls[0] == "sudo mkdir -p /opt/strongswan/config/connections"
        assert calls[1] == "sudo tee /opt/strongswan/config/connections/my-tunnel.conf"
        assert calls[2] == "sudo chmod 644 /opt/strongswan/config/connections/my-tunnel.conf"
        assert calls[3] == "sudo mkdir -p /opt/strongswan/config/secrets"
        assert calls[4] == "sudo tee /opt/strongswan/config/secrets/my-tunnel.secrets"
        assert calls[5] == "sudo chmod 640 /opt/strongswan/config/secrets/my-tunnel.secrets"
        assert calls[6] == "sudo /usr/sbin/swanctl --load-all"

        # Verify file content was piped via input=
        tee_conf_call = mock_conn.run.call_args_list[1]
        assert tee_conf_call.kwargs.get("input") == "conn my-tunnel\n"
        tee_secrets_call = mock_conn.run.call_args_list[4]
        assert tee_secrets_call.kwargs.get("input") == "10.0.0.1 : PSK secret\n"

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_secrets_none_skips_secrets_write(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """secrets_content=None: only conf is written (mkdir + tee + chmod), then swanctl."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        # Without secrets: mkdir conf, tee conf, chmod conf, swanctl
        ok = _make_run_result()
        mock_conn_cm, mock_conn = _build_conn_mock(
            run_side_effect=[ok, ok, ok, ok]
        )

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_push_tunnel_config(
                server,
                name="my-tunnel",
                conf_content="conn my-tunnel\n",
                secrets_content=None,
            )

        assert result.success is True
        assert mock_conn.run.call_count == 4

        calls = [c.args[0] for c in mock_conn.run.call_args_list]
        assert calls[0] == "sudo mkdir -p /opt/strongswan/config/connections"
        assert calls[1] == "sudo tee /opt/strongswan/config/connections/my-tunnel.conf"
        assert calls[2] == "sudo chmod 644 /opt/strongswan/config/connections/my-tunnel.conf"
        assert calls[3] == "sudo /usr/sbin/swanctl --load-all"

        # No secrets-related commands
        assert not any("secrets" in c for c in calls)

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_tee_failure_returns_failure(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """If tee (sudo write) fails with non-zero exit, return ServerResult(success=False)."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        ok = _make_run_result()
        fail = _make_run_result(exit_status=1, stderr="Permission denied")
        # mkdir ok, tee fails
        mock_conn_cm, mock_conn = _build_conn_mock(run_side_effect=[ok, fail])

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_push_tunnel_config(
                server,
                name="my-tunnel",
                conf_content="conn my-tunnel\n",
                secrets_content="secret\n",
            )

        assert result.success is False
        assert "tee conf file failed" in result.error
        assert "Permission denied" in result.error

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_swanctl_nonzero_exit_returns_failure(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """swanctl --load-all exits non-zero → ServerResult(success=False)."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        ok = _make_run_result()
        swanctl_fail = _make_run_result(exit_status=1, stderr="swanctl failed")
        # mkdir, tee, chmod, mkdir, tee, chmod all ok — swanctl fails
        mock_conn_cm, mock_conn = _build_conn_mock(
            run_side_effect=[ok, ok, ok, ok, ok, ok, swanctl_fail]
        )

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_push_tunnel_config(
                server,
                name="my-tunnel",
                conf_content="conn my-tunnel\n",
                secrets_content="secret\n",
            )

        assert result.success is False
        assert "status 1" in result.error
        assert "swanctl failed" in result.error


# ---------------------------------------------------------------------------
# sftp_delete_tunnel_config
# ---------------------------------------------------------------------------


class TestSftpDeleteTunnelConfig:
    """Unit tests for server_service.sftp_delete_tunnel_config()."""

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_success_removes_both_files_and_reloads(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """Success: rm -f .conf, rm -f .secrets, then swanctl --load-all."""
        from app.services.server_service import sftp_delete_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        ok = _make_run_result()
        mock_conn_cm, mock_conn = _build_conn_mock(run_side_effect=[ok, ok, ok])

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_delete_tunnel_config(server, name="my-tunnel")

        assert result.success is True
        assert result.server_id == 1
        assert result.server_name == "vpn-1"
        assert mock_conn.run.call_count == 3

        calls = [c.args[0] for c in mock_conn.run.call_args_list]
        assert calls[0] == "sudo rm -f /opt/strongswan/config/connections/my-tunnel.conf"
        assert calls[1] == "sudo rm -f /opt/strongswan/config/secrets/my-tunnel.secrets"
        assert calls[2] == "sudo /usr/sbin/swanctl --load-all"

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_rm_f_is_idempotent_when_file_missing(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """sudo rm -f always exits 0 even when files don't exist — result is still success."""
        from app.services.server_service import sftp_delete_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        # rm -f exits 0 even when file doesn't exist — same mock as success
        ok = _make_run_result(exit_status=0)
        mock_conn_cm, mock_conn = _build_conn_mock(run_side_effect=[ok, ok, ok])

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_delete_tunnel_config(server, name="my-tunnel")

        assert result.success is True
        # swanctl still ran
        calls = [c.args[0] for c in mock_conn.run.call_args_list]
        assert calls[-1] == "sudo /usr/sbin/swanctl --load-all"


# ---------------------------------------------------------------------------
# sftp_push_on_all_servers
# ---------------------------------------------------------------------------


class TestSftpPushOnAllServers:
    """Unit tests for server_service.sftp_push_on_all_servers()."""

    @patch("app.services.server_service.sftp_push_tunnel_config", new_callable=AsyncMock)
    async def test_all_succeed(self, mock_push):
        """All servers succeed → FanOutResult.is_success == True."""
        from app.services.server_service import sftp_push_on_all_servers

        servers = [_make_server(1, "vpn-1"), _make_server(2, "vpn-2")]
        mock_push.side_effect = [
            ServerResult(server_id=1, server_name="vpn-1", success=True),
            ServerResult(server_id=2, server_name="vpn-2", success=True),
        ]

        session = AsyncMock()
        mock_db_result = MagicMock()
        mock_db_result.scalars.return_value.all.return_value = servers
        session.execute = AsyncMock(return_value=mock_db_result)

        result = await sftp_push_on_all_servers(
            session,
            name="my-tunnel",
            conf_content="conf\n",
            secrets_content="secret\n",
        )

        assert result.is_success is True
        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0
        assert mock_push.call_count == 2

    @patch("app.services.server_service.sftp_push_tunnel_config", new_callable=AsyncMock)
    async def test_partial_failure(self, mock_push):
        """One server fails → FanOutResult.is_partial == True, counts correct."""
        from app.services.server_service import sftp_push_on_all_servers

        servers = [_make_server(1, "vpn-1"), _make_server(2, "vpn-2"), _make_server(3, "vpn-3")]
        mock_push.side_effect = [
            ServerResult(server_id=1, server_name="vpn-1", success=True),
            ServerResult(server_id=2, server_name="vpn-2", success=False, error="Connection refused"),
            ServerResult(server_id=3, server_name="vpn-3", success=True),
        ]

        session = AsyncMock()
        mock_db_result = MagicMock()
        mock_db_result.scalars.return_value.all.return_value = servers
        session.execute = AsyncMock(return_value=mock_db_result)

        result = await sftp_push_on_all_servers(
            session,
            name="my-tunnel",
            conf_content="conf\n",
            secrets_content="secret\n",
        )

        assert result.is_partial is True
        assert result.total == 3
        assert result.succeeded == 2
        assert result.failed == 1

    async def test_zero_servers_raises(self):
        """Zero active servers → raises InfrastructureError."""
        from app.exceptions import InfrastructureError
        from app.services.server_service import sftp_push_on_all_servers

        session = AsyncMock()
        mock_db_result = MagicMock()
        mock_db_result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=mock_db_result)

        with pytest.raises(InfrastructureError) as exc_info:
            await sftp_push_on_all_servers(
                session,
                name="my-tunnel",
                conf_content="conf\n",
                secrets_content="secret\n",
            )

        assert "No active servers" in exc_info.value.message


# ---------------------------------------------------------------------------
# sftp_delete_on_all_servers
# ---------------------------------------------------------------------------


class TestSftpDeleteOnAllServers:
    """Unit tests for server_service.sftp_delete_on_all_servers()."""

    @patch("app.services.server_service.sftp_delete_tunnel_config", new_callable=AsyncMock)
    async def test_all_succeed(self, mock_delete):
        """All servers succeed → FanOutResult.is_success == True."""
        from app.services.server_service import sftp_delete_on_all_servers

        servers = [_make_server(1, "vpn-1"), _make_server(2, "vpn-2")]
        mock_delete.side_effect = [
            ServerResult(server_id=1, server_name="vpn-1", success=True),
            ServerResult(server_id=2, server_name="vpn-2", success=True),
        ]

        session = AsyncMock()
        mock_db_result = MagicMock()
        mock_db_result.scalars.return_value.all.return_value = servers
        session.execute = AsyncMock(return_value=mock_db_result)

        result = await sftp_delete_on_all_servers(session, name="my-tunnel")

        assert result.is_success is True
        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0
        assert mock_delete.call_count == 2

    async def test_zero_servers_raises(self):
        """Zero active servers → raises InfrastructureError."""
        from app.exceptions import InfrastructureError
        from app.services.server_service import sftp_delete_on_all_servers

        session = AsyncMock()
        mock_db_result = MagicMock()
        mock_db_result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=mock_db_result)

        with pytest.raises(InfrastructureError) as exc_info:
            await sftp_delete_on_all_servers(session, name="my-tunnel")

        assert "No active servers" in exc_info.value.message


# ---------------------------------------------------------------------------
# sftp_rename_on_all_servers
# ---------------------------------------------------------------------------


class TestSftpRenameOnAllServers:
    """Unit tests for server_service.sftp_rename_on_all_servers()."""

    @patch("app.services.server_service._sftp_rename_on_server", new_callable=AsyncMock)
    async def test_success_calls_rename_per_server(self, mock_rename):
        """All servers succeed: _sftp_rename_on_server called per server, FanOutResult all_succeeded."""
        from app.services.server_service import sftp_rename_on_all_servers

        servers = [_make_server(1, "vpn-1"), _make_server(2, "vpn-2")]
        mock_rename.side_effect = [
            ServerResult(server_id=1, server_name="vpn-1", success=True),
            ServerResult(server_id=2, server_name="vpn-2", success=True),
        ]

        session = AsyncMock()
        mock_db_result = MagicMock()
        mock_db_result.scalars.return_value.all.return_value = servers
        session.execute = AsyncMock(return_value=mock_db_result)

        result = await sftp_rename_on_all_servers(
            session,
            old_name="old-tunnel",
            new_name="new-tunnel",
            conf_content="new conf\n",
            secrets_content="new secret\n",
        )

        assert result.is_success is True
        assert result.total == 2
        assert result.succeeded == 2
        assert result.failed == 0
        assert mock_rename.call_count == 2

    async def test_zero_servers_raises(self):
        """Zero active servers → raises InfrastructureError."""
        from app.exceptions import InfrastructureError
        from app.services.server_service import sftp_rename_on_all_servers

        session = AsyncMock()
        mock_db_result = MagicMock()
        mock_db_result.scalars.return_value.all.return_value = []
        session.execute = AsyncMock(return_value=mock_db_result)

        with pytest.raises(InfrastructureError) as exc_info:
            await sftp_rename_on_all_servers(
                session,
                old_name="old-tunnel",
                new_name="new-tunnel",
                conf_content="conf\n",
                secrets_content="secret\n",
            )

        assert "No active servers" in exc_info.value.message
