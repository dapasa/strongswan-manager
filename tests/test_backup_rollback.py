"""Tests for pre-write backup and rollback in sftp_push_tunnel_config / sftp_delete_tunnel_config.

Covers (per task spec):
  - Backup taken before write (swanctl and stroke)
  - Retention prune commands included
  - Rollback on reload failure — swanctl
  - Rollback on reload failure — stroke
  - Rollback when there was no previous file (rm new file instead of restore)
  - Rollback failure reported alongside original error
  - Success path unchanged (backup + write + reload → success=True)

Mocks at the transport level (patch get_transport) to stay independent of SSH/SSM details.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from app.services.transport.base import TransportError, TransportErrorKind
from app.utils.fan_out import ServerResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_server(id: int = 1, name: str = "vpn-1", ipsec_engine: str = "swanctl") -> MagicMock:
    srv = MagicMock()
    srv.id = id
    srv.name = name
    srv.ipsec_engine = ipsec_engine
    return srv


def _make_transport(
    *,
    execute_side_effect=None,
    write_side_effect=None,
    delete_side_effect=None,
) -> MagicMock:
    t = MagicMock()
    t.execute = AsyncMock(side_effect=execute_side_effect) if execute_side_effect is not None else AsyncMock()
    t.write_file = AsyncMock(side_effect=write_side_effect) if write_side_effect is not None else AsyncMock()
    t.delete_file = AsyncMock(side_effect=delete_side_effect) if delete_side_effect is not None else AsyncMock()
    return t


def _mock_settings():
    return MagicMock(
        ssh_command_timeout=30,
        vpn_conf_dir="/opt/strongswan/config/connections",
        vpn_stroke_secrets_dir="/etc/ipsec.d/secrets",
        vpn_swanctl_conf_dir="/etc/swanctl/conf.d",
        vpn_secrets_dir="/opt/strongswan/config/secrets",
        vpn_backup_dir="/var/backups/strongswan-manager",
        vpn_backup_retention=5,
    )


# ---------------------------------------------------------------------------
# TestBackupOnPush
# ---------------------------------------------------------------------------


class TestBackupOnPush:
    """Backup behaviour for sftp_push_tunnel_config."""

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_backup_execute_called_before_write_swanctl(self, mock_get_transport, mock_settings):
        """Swanctl push: transport.execute() for backup is called before write_file()."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()
        transport = _make_transport()
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="swanctl")
        await sftp_push_tunnel_config(
            server,
            name="t1",
            conf_content="conf\n",
            secrets_content=None,
            swanctl_content="combined\n",
        )

        # execute called twice: backup first, then reload
        assert transport.execute.call_count == 2
        # write_file called once
        assert transport.write_file.call_count == 1

        # First execute call must be the backup (contains mkdir for backup dir)
        first_exec_cmds = transport.execute.call_args_list[0].args[0]
        assert any("mkdir" in c and "backups" in c for c in first_exec_cmds)

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_backup_execute_called_before_write_stroke(self, mock_get_transport, mock_settings):
        """Stroke push with secrets: backup execute() called before any write_file()."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()

        call_order: list[str] = []

        async def _exec(cmds):
            call_order.append("execute")

        async def _write(path, content, *, mode="644", make_dirs=True):
            call_order.append("write")

        transport = MagicMock()
        transport.execute = AsyncMock(side_effect=_exec)
        transport.write_file = AsyncMock(side_effect=_write)
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="stroke")
        await sftp_push_tunnel_config(
            server,
            name="t1",
            conf_content="conf\n",
            secrets_content="psk\n",
        )

        # backup execute comes before any write_file
        assert call_order[0] == "execute"
        assert call_order.count("write") == 2
        assert call_order.count("execute") == 2  # backup + reload

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_backup_commands_include_retention_prune(self, mock_get_transport, mock_settings):
        """Backup commands include a prune step (tail -n +N | xargs rm -f) for each path."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()
        transport = _make_transport()
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="swanctl")
        await sftp_push_tunnel_config(
            server, name="t1", conf_content="c\n", secrets_content=None, swanctl_content="s\n"
        )

        backup_cmds = transport.execute.call_args_list[0].args[0]
        # Must have a command that removes old backups via xargs rm
        assert any("xargs" in c and "rm" in c for c in backup_cmds)
        # retention=5 → tail -n +6
        assert any("tail -n +6" in c for c in backup_cmds)

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_success_path_unchanged(self, mock_get_transport, mock_settings):
        """Happy path: backup + write + reload all succeed → ServerResult(success=True)."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()
        transport = _make_transport()
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="swanctl")
        result = await sftp_push_tunnel_config(
            server, name="t1", conf_content="c\n", secrets_content=None, swanctl_content="s\n"
        )

        assert result.success is True
        assert result.server_id == 1
        assert result.server_name == "vpn-1"

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_rollback_on_reload_failure_swanctl(self, mock_get_transport, mock_settings):
        """Swanctl push: reload fails → rollback restore+reload; result is failure with rollback note."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()

        execute_calls: list[list[str]] = []

        async def _execute(cmds):
            execute_calls.append(list(cmds))
            # Second call is reload — fail it; first is backup, third is rollback
            if len(execute_calls) == 2:
                raise TransportError("swanctl reload failed", kind=TransportErrorKind.COMMAND_FAILED)

        transport = _make_transport(execute_side_effect=_execute)
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="swanctl")
        result = await sftp_push_tunnel_config(
            server, name="t1", conf_content="c\n", secrets_content=None, swanctl_content="s\n"
        )

        assert result.success is False
        assert "swanctl reload failed" in result.error
        assert "rolled back successfully" in result.error

        # Three execute calls: backup, reload (fails), rollback
        assert len(execute_calls) == 3
        # Rollback commands include the reload command
        assert any("swanctl" in c for c in execute_calls[2])

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_rollback_on_reload_failure_stroke(self, mock_get_transport, mock_settings):
        """Stroke push: reload fails → rollback restore+reload; result is failure with rollback note."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()

        execute_calls: list[list[str]] = []

        async def _execute(cmds):
            execute_calls.append(list(cmds))
            if len(execute_calls) == 2:
                raise TransportError("ipsec reload failed", kind=TransportErrorKind.COMMAND_FAILED)

        transport = _make_transport(execute_side_effect=_execute)
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="stroke")
        result = await sftp_push_tunnel_config(
            server, name="t1", conf_content="c\n", secrets_content="psk\n"
        )

        assert result.success is False
        assert "ipsec reload failed" in result.error
        assert "rolled back successfully" in result.error

        # Rollback commands include ipsec reload
        assert any("ipsec reload" in c for c in execute_calls[2])

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_rollback_when_no_previous_file(self, mock_get_transport, mock_settings):
        """Reload failure when no prior file existed: rollback removes the new file (not a restore)."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()

        execute_calls: list[list[str]] = []

        async def _execute(cmds):
            execute_calls.append(list(cmds))
            if len(execute_calls) == 2:
                raise TransportError("reload failed")

        transport = _make_transport(execute_side_effect=_execute)
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="swanctl")
        result = await sftp_push_tunnel_config(
            server, name="t1", conf_content="c\n", secrets_content=None, swanctl_content="s\n"
        )

        assert result.success is False
        # Rollback command uses: [ -f backup ] && restore || sudo rm -f path
        rollback_cmds = execute_calls[2]
        assert any("sudo rm -f" in c for c in rollback_cmds)

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_rollback_failure_reported(self, mock_get_transport, mock_settings):
        """Write fails AND rollback fails → error message mentions both failures."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()

        execute_calls: list[list[str]] = []

        async def _execute(cmds):
            execute_calls.append(list(cmds))
            if len(execute_calls) >= 2:  # reload fails; rollback execute also fails
                raise TransportError("transport gone")

        transport = _make_transport(execute_side_effect=_execute)
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="swanctl")
        result = await sftp_push_tunnel_config(
            server, name="t1", conf_content="c\n", secrets_content=None, swanctl_content="s\n"
        )

        assert result.success is False
        assert "rollback also failed" in result.error
        assert "transport gone" in result.error

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_backup_dir_creation_failure_blocks_write(self, mock_get_transport, mock_settings):
        """If backup dir creation fails, write_file is never called (fail-safe)."""
        from app.services.server_service import sftp_push_tunnel_config

        mock_settings.return_value = _mock_settings()

        async def _execute(cmds):
            raise TransportError("mkdir failed: permission denied")

        transport = _make_transport(execute_side_effect=_execute)
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="swanctl")
        result = await sftp_push_tunnel_config(
            server, name="t1", conf_content="c\n", secrets_content=None, swanctl_content="s\n"
        )

        assert result.success is False
        # write_file must NOT have been called
        assert transport.write_file.call_count == 0


# ---------------------------------------------------------------------------
# TestBackupOnDelete
# ---------------------------------------------------------------------------


class TestBackupOnDelete:
    """Backup behaviour for sftp_delete_tunnel_config."""

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_backup_taken_before_delete(self, mock_get_transport, mock_settings):
        """Backup execute() is called before delete_file()."""
        from app.services.server_service import sftp_delete_tunnel_config

        mock_settings.return_value = _mock_settings()

        call_order: list[str] = []

        async def _exec(cmds):
            call_order.append("execute")

        async def _del(path):
            call_order.append("delete")

        transport = MagicMock()
        transport.execute = AsyncMock(side_effect=_exec)
        transport.delete_file = AsyncMock(side_effect=_del)
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="stroke")
        await sftp_delete_tunnel_config(server, name="t1")

        assert call_order[0] == "execute"  # backup first
        assert "delete" in call_order
        assert call_order.count("execute") == 2  # backup + reload

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_rollback_on_delete_reload_failure(self, mock_get_transport, mock_settings):
        """Stroke delete: reload fails → rollback restores files; result shows rollback."""
        from app.services.server_service import sftp_delete_tunnel_config

        mock_settings.return_value = _mock_settings()

        execute_calls: list[list[str]] = []

        async def _execute(cmds):
            execute_calls.append(list(cmds))
            if len(execute_calls) == 2:  # second call is reload
                raise TransportError("ipsec reload failed")

        transport = _make_transport(execute_side_effect=_execute)
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="stroke")
        result = await sftp_delete_tunnel_config(server, name="t1")

        assert result.success is False
        assert "ipsec reload failed" in result.error
        assert "rolled back successfully" in result.error
        # Three execute calls: backup, reload (fails), rollback
        assert len(execute_calls) == 3

    @patch("app.services.server_service.get_settings")
    @patch("app.services.server_service.get_transport")
    async def test_delete_success_path_unchanged(self, mock_get_transport, mock_settings):
        """Happy path delete: backup + delete + reload all succeed → success=True."""
        from app.services.server_service import sftp_delete_tunnel_config

        mock_settings.return_value = _mock_settings()
        transport = _make_transport()
        mock_get_transport.return_value = transport

        server = _make_server(ipsec_engine="swanctl")
        result = await sftp_delete_tunnel_config(server, name="t1")

        assert result.success is True
        assert transport.delete_file.call_count == 1
        assert transport.execute.call_count == 2  # backup + reload
