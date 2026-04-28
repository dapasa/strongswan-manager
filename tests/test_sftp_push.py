"""Tests for SFTP-based tunnel config push/delete/rename functions.

Covers:
    sftp_push_tunnel_config — success, secrets=None, SFTPError, swanctl non-zero
    sftp_delete_tunnel_config — success, SFTPNoSuchFile is idempotent
    sftp_push_on_all_servers — all succeed, partial failure
    sftp_delete_on_all_servers — all succeed
    sftp_rename_on_all_servers — success (delete old + push new)
"""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, call, patch

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


def _build_sftp_conn_mocks(
    run_result: MagicMock | None = None,
    sftp_open_side_effect=None,
    sftp_remove_side_effect=None,
):
    """Build nested async context manager mocks for SSH + SFTP.

    Returns:
        (mock_connect_cm, mock_conn, mock_sftp)
    """
    if run_result is None:
        run_result = _make_run_result()

    # Mock file handle returned by sftp.open(...)
    mock_file = MagicMock()
    mock_file.write = AsyncMock()
    mock_file_cm = MagicMock()
    mock_file_cm.__aenter__ = AsyncMock(return_value=mock_file)
    mock_file_cm.__aexit__ = AsyncMock(return_value=False)

    # Mock SFTP client
    mock_sftp = MagicMock()
    mock_sftp.makedirs = AsyncMock()
    mock_sftp.chmod = AsyncMock()
    mock_sftp.remove = AsyncMock()
    if sftp_open_side_effect is not None:
        mock_sftp.open = AsyncMock(side_effect=sftp_open_side_effect)
    else:
        mock_sftp.open = AsyncMock(return_value=mock_file_cm)
    if sftp_remove_side_effect is not None:
        mock_sftp.remove = AsyncMock(side_effect=sftp_remove_side_effect)

    mock_sftp_cm = MagicMock()
    mock_sftp_cm.__aenter__ = AsyncMock(return_value=mock_sftp)
    mock_sftp_cm.__aexit__ = AsyncMock(return_value=False)

    # Mock SSH connection
    mock_conn = MagicMock()
    mock_conn.run = AsyncMock(return_value=run_result)
    mock_conn.start_sftp_client = AsyncMock(return_value=mock_sftp_cm)

    mock_conn_cm = MagicMock()
    mock_conn_cm.__aenter__ = AsyncMock(return_value=mock_conn)
    mock_conn_cm.__aexit__ = AsyncMock(return_value=False)

    return mock_conn_cm, mock_conn, mock_sftp


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
        """Success path: makedirs, open+write for conf, open+write for secrets, chmod, swanctl."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        mock_conn_cm, mock_conn, mock_sftp = _build_sftp_conn_mocks()

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

        # makedirs called for both conf and secrets dirs
        assert mock_sftp.makedirs.call_count == 2
        mock_sftp.makedirs.assert_any_call(
            "/opt/strongswan/config/connections", exist_ok=True
        )
        mock_sftp.makedirs.assert_any_call(
            "/opt/strongswan/config/secrets", exist_ok=True
        )

        # chmod called for both files
        assert mock_sftp.chmod.call_count == 2
        mock_sftp.chmod.assert_any_call(
            "/opt/strongswan/config/connections/my-tunnel.conf", 0o644
        )
        mock_sftp.chmod.assert_any_call(
            "/opt/strongswan/config/secrets/my-tunnel.secrets", 0o640
        )

        # swanctl --load-all was called
        mock_conn.run.assert_called_once_with("sudo /usr/sbin/swanctl --load-all")

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_secrets_none_skips_secrets_write(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """secrets_content=None: only conf is written, secrets dir and chmod skipped."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        mock_conn_cm, mock_conn, mock_sftp = _build_sftp_conn_mocks()

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_push_tunnel_config(
                server,
                name="my-tunnel",
                conf_content="conn my-tunnel\n",
                secrets_content=None,
            )

        assert result.success is True

        # makedirs only called once — for conf dir only
        mock_sftp.makedirs.assert_called_once_with(
            "/opt/strongswan/config/connections", exist_ok=True
        )

        # chmod only called once — for conf file only
        mock_sftp.chmod.assert_called_once_with(
            "/opt/strongswan/config/connections/my-tunnel.conf", 0o644
        )

        # swanctl still executed
        mock_conn.run.assert_called_once_with("sudo /usr/sbin/swanctl --load-all")

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_sftp_error_on_write_returns_failure(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """SFTPError during file write returns ServerResult(success=False)."""
        import asyncssh

        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()

        # open() raises SFTPError
        mock_conn_cm, mock_conn, mock_sftp = _build_sftp_conn_mocks(
            sftp_open_side_effect=asyncssh.SFTPError(asyncssh.FX_FAILURE, "Permission denied")
        )

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_push_tunnel_config(
                server,
                name="my-tunnel",
                conf_content="conn my-tunnel\n",
                secrets_content="secret\n",
            )

        assert result.success is False
        assert "SFTP error" in result.error

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
        run_result = _make_run_result(exit_status=1, stderr="swanctl failed")
        mock_conn_cm, mock_conn, mock_sftp = _build_sftp_conn_mocks(run_result=run_result)

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
        """Success: removes .conf and .secrets, runs swanctl --load-all."""
        from app.services.server_service import sftp_delete_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        mock_conn_cm, mock_conn, mock_sftp = _build_sftp_conn_mocks()

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_delete_tunnel_config(server, name="my-tunnel")

        assert result.success is True
        assert result.server_id == 1
        assert result.server_name == "vpn-1"

        # Both files removed
        assert mock_sftp.remove.call_count == 2
        mock_sftp.remove.assert_any_call(
            "/opt/strongswan/config/connections/my-tunnel.conf"
        )
        mock_sftp.remove.assert_any_call(
            "/opt/strongswan/config/secrets/my-tunnel.secrets"
        )

        mock_conn.run.assert_called_once_with("sudo /usr/sbin/swanctl --load-all")

    @patch("app.services.server_service.asyncssh.import_private_key")
    @patch("app.services.server_service.decrypt_ssh_key")
    @patch("app.services.server_service.get_settings")
    async def test_sftp_no_such_file_treated_as_success(
        self, mock_settings, mock_decrypt, mock_import_key
    ):
        """SFTPNoSuchFile during remove is swallowed — result is still success."""
        import asyncssh

        from app.services.server_service import sftp_delete_tunnel_config

        mock_settings.return_value = MagicMock(
            ssh_command_timeout=30,
            vpn_conf_dir="/opt/strongswan/config/connections",
            vpn_secrets_dir="/opt/strongswan/config/secrets",
        )
        mock_decrypt.return_value = "raw-key"
        mock_import_key.return_value = MagicMock()

        server = _make_server()
        mock_conn_cm, mock_conn, mock_sftp = _build_sftp_conn_mocks(
            sftp_remove_side_effect=asyncssh.SFTPNoSuchFile("No such file")
        )

        with patch("app.services.server_service.asyncssh.connect", return_value=mock_conn_cm):
            result = await sftp_delete_tunnel_config(server, name="my-tunnel")

        assert result.success is True
        # swanctl still ran
        mock_conn.run.assert_called_once_with("sudo /usr/sbin/swanctl --load-all")


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
