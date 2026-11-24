"""Unit tests for tunnel initiate / terminate endpoints and service layer.

Covers:
- Role enforcement: viewer → 403, operator → allowed, admin → allowed
- Active node resolution: primary vs secondary holder
- Command built correctly for initiate and terminate actions
- swanctl success → 200 success=true
- swanctl command failure → 200 success=false
- Transport timeout → audit written, 200 success=false
- SSM infrastructure failure → 502 (InfrastructureError)
- Tunnel not found → 404
- EIP not associated → 502, audit entry still written
- Audit entry written on EVERY outcome (success, failure, timeout, node-resolution failure)
- Wrapper timeout passed to execute_command is strictly greater than swanctl --timeout
- Migration 0018 constraint includes initiate and terminate
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
from botocore.exceptions import ClientError
from fastapi import Request

from app.db.models import Server, Tunnel, User
from app.exceptions import InfrastructureError, NotFoundError
from app.services.tunnel_service import (
    _SWANCTL_TIMEOUT,
    _WRAPPER_TIMEOUT,
    _control_tunnel,
    _filter_swanctl_output,
    _find_server_by_instance_id,
    _resolve_active_node_sync,
    _validate_tunnel_name_safe,
)
from app.utils.fan_out import ServerResult


# ---------------------------------------------------------------------------
# Constants shared across tests
# ---------------------------------------------------------------------------

PRIMARY_INSTANCE = "i-0aaaaaaaaaaaaaaaa"
SECONDARY_INSTANCE = "i-0bbbbbbbbbbbbbbb"
EIP_ALLOC = "eipalloc-0abc1234def56789"
PRIMARY_IP = "10.0.1.10"
SECONDARY_IP = "10.0.2.10"

FAILOVER_CONFIG = {
    "eip_allocation_id": EIP_ALLOC,
    "route_table_ids": ["rtb-aaaa1111"],
    "primary_ip": PRIMARY_IP,
    "secondary_ip": SECONDARY_IP,
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_ec2_mock(
    holder_instance_id: str | None = PRIMARY_INSTANCE,
    primary_instance: str = PRIMARY_INSTANCE,
    secondary_instance: str = SECONDARY_INSTANCE,
) -> MagicMock:
    """Return a mock EC2 client that reports primary as the EIP holder by default."""
    ec2 = MagicMock()

    ec2.describe_network_interfaces.return_value = {
        "NetworkInterfaces": [
            {
                "NetworkInterfaceId": "eni-primary",
                "PrivateIpAddress": PRIMARY_IP,
                "Attachment": {"InstanceId": primary_instance, "DeviceIndex": 0},
            },
            {
                "NetworkInterfaceId": "eni-secondary",
                "PrivateIpAddress": SECONDARY_IP,
                "Attachment": {"InstanceId": secondary_instance, "DeviceIndex": 0},
            },
        ]
    }

    ec2.describe_addresses.return_value = {
        "Addresses": [{"InstanceId": holder_instance_id}] if holder_instance_id else []
    }

    return ec2


def _make_tunnel(name: str = "test-tunnel") -> MagicMock:
    t = MagicMock(spec=Tunnel)
    t.id = 42
    t.name = name
    t.deleted_at = None
    return t


def _make_server(instance_id: str = PRIMARY_INSTANCE) -> MagicMock:
    s = MagicMock(spec=Server)
    s.id = 1
    s.name = "primary-node"
    s.ec2_instance_id = instance_id
    s.is_active = True
    s.deleted_at = None
    return s


def _make_user(role: str = "operator") -> MagicMock:
    u = MagicMock(spec=User)
    u.id = 99
    u.role = role
    u.is_active = True
    return u


def _make_request() -> MagicMock:
    r = MagicMock(spec=Request)
    r.headers = {}
    r.client = None
    return r


# ---------------------------------------------------------------------------
# _validate_tunnel_name_safe
# ---------------------------------------------------------------------------


class TestValidateTunnelNameSafe:
    def test_valid_name_passes(self):
        # Should not raise
        _validate_tunnel_name_safe("daniel-local-test")
        _validate_tunnel_name_safe("tunnel_1")
        _validate_tunnel_name_safe("vpn.conn-1")

    def test_shell_injection_raises(self):
        with pytest.raises(InfrastructureError):
            _validate_tunnel_name_safe("bad;rm -rf /")

    def test_dollar_sign_raises(self):
        with pytest.raises(InfrastructureError):
            _validate_tunnel_name_safe("tunnel$VAR")

    def test_backtick_raises(self):
        with pytest.raises(InfrastructureError):
            _validate_tunnel_name_safe("tunnel`whoami`")

    def test_space_raises(self):
        with pytest.raises(InfrastructureError):
            _validate_tunnel_name_safe("tunnel name")


# ---------------------------------------------------------------------------
# _resolve_active_node_sync — primary vs secondary holder
# ---------------------------------------------------------------------------


class TestResolveActiveNodeSync:
    def test_primary_holder(self):
        ec2 = _make_ec2_mock(holder_instance_id=PRIMARY_INSTANCE)
        instance_id, node_label = _resolve_active_node_sync(ec2, FAILOVER_CONFIG)
        assert instance_id == PRIMARY_INSTANCE
        assert node_label == "primary"

    def test_secondary_holder(self):
        ec2 = _make_ec2_mock(holder_instance_id=SECONDARY_INSTANCE)
        instance_id, node_label = _resolve_active_node_sync(ec2, FAILOVER_CONFIG)
        assert instance_id == SECONDARY_INSTANCE
        assert node_label == "secondary"

    def test_eip_not_associated_raises(self):
        ec2 = _make_ec2_mock(holder_instance_id=None)
        with pytest.raises(InfrastructureError) as exc_info:
            _resolve_active_node_sync(ec2, FAILOVER_CONFIG)
        assert "not currently associated" in exc_info.value.message

    def test_holder_not_a_vpn_node_raises(self):
        # EIP is on an unrelated instance
        ec2 = _make_ec2_mock(holder_instance_id="i-0unknown")
        with pytest.raises(InfrastructureError) as exc_info:
            _resolve_active_node_sync(ec2, FAILOVER_CONFIG)
        assert "not a known VPN node" in exc_info.value.message

    def test_missing_eip_alloc_id_raises(self):
        ec2 = _make_ec2_mock()
        config_no_eip = {**FAILOVER_CONFIG}
        del config_no_eip["eip_allocation_id"]
        with pytest.raises(InfrastructureError) as exc_info:
            _resolve_active_node_sync(ec2, config_no_eip)
        assert "eip_allocation_id" in exc_info.value.message

    def test_missing_primary_ip_raises(self):
        ec2 = _make_ec2_mock()
        config_no_primary = {**FAILOVER_CONFIG}
        del config_no_primary["primary_ip"]
        with pytest.raises(InfrastructureError) as exc_info:
            _resolve_active_node_sync(ec2, config_no_primary)
        assert "primary_ip" in exc_info.value.message

    def test_describe_addresses_client_error_raises(self):
        ec2 = _make_ec2_mock()
        ec2.describe_addresses.side_effect = ClientError(
            {"Error": {"Code": "InvalidAllocationID.NotFound", "Message": ""}},
            "DescribeAddresses",
        )
        with pytest.raises(InfrastructureError) as exc_info:
            _resolve_active_node_sync(ec2, FAILOVER_CONFIG)
        assert "DescribeAddresses" in exc_info.value.message

    def test_describe_network_interfaces_error_raises(self):
        ec2 = _make_ec2_mock()
        ec2.describe_network_interfaces.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": ""}},
            "DescribeNetworkInterfaces",
        )
        with pytest.raises(InfrastructureError) as exc_info:
            _resolve_active_node_sync(ec2, FAILOVER_CONFIG)
        assert "DescribeNetworkInterfaces" in exc_info.value.message


# ---------------------------------------------------------------------------
# _control_tunnel — service-layer unit tests
# ---------------------------------------------------------------------------


class TestControlTunnel:
    """Tests for _control_tunnel that mock all external dependencies."""

    def _make_session_mock(
        self,
        tunnel: MagicMock | None = None,
        active_server: MagicMock | None = None,
        target_server: MagicMock | None = None,
    ):
        """Build a mock AsyncSession that returns the right objects from execute()."""
        session = AsyncMock()
        session.commit = AsyncMock()

        t = tunnel or _make_tunnel()
        any_srv = active_server or _make_server()
        tgt_srv = target_server or _make_server()

        # get_tunnel calls session.execute() → scalar_one_or_none() → tunnel
        # _get_any_active_server calls session.execute() → scalar_one_or_none() → server
        # _find_server_by_instance_id calls session.execute() → scalar_one_or_none() → server
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()

        # We use side_effect to return different objects per call
        scalar_mock.scalar_one_or_none.side_effect = [t, any_srv, tgt_srv]
        exec_mock.return_value = scalar_mock
        session.execute = exec_mock

        return session, t, any_srv, tgt_srv

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_initiate_success(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_execute,
        mock_resolve,
        mock_read_failover,
    ):
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.return_value = (PRIMARY_INSTANCE, "primary")
        mock_execute.return_value = ServerResult(
            server_id=1, server_name="primary", success=True, output="CHILD_SA established"
        )

        session, t, any_srv, tgt_srv = self._make_session_mock()

        result = await _control_tunnel(
            session, 42, action="initiate", user=_make_user(), request=_make_request()
        )

        assert result["tunnel_id"] == 42
        assert result["action"] == "initiate"
        assert result["node"] == "primary"
        assert result["instance_id"] == PRIMARY_INSTANCE
        assert result["success"] is True
        assert "CHILD_SA" in result["output"]

        # Audit must be written
        mock_audit.assert_called_once()
        audit_call_kwargs = mock_audit.call_args.kwargs
        assert audit_call_kwargs["action"] == "initiate"
        assert audit_call_kwargs["entity_type"] == "tunnel"

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_terminate_success(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_execute,
        mock_resolve,
        mock_read_failover,
    ):
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.return_value = (SECONDARY_INSTANCE, "secondary")
        mock_execute.return_value = ServerResult(
            server_id=1, server_name="secondary", success=True, output="IKE_SA closed"
        )

        session, t, any_srv, tgt_srv = self._make_session_mock(
            target_server=_make_server(SECONDARY_INSTANCE)
        )

        result = await _control_tunnel(
            session, 42, action="terminate", user=_make_user(), request=_make_request()
        )

        assert result["action"] == "terminate"
        assert result["node"] == "secondary"
        assert result["success"] is True

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_swanctl_command_failure_returns_success_false(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_execute,
        mock_resolve,
        mock_read_failover,
    ):
        """swanctl exits non-zero → success=false, still 200, audit written."""
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.return_value = (PRIMARY_INSTANCE, "primary")
        mock_execute.return_value = ServerResult(
            server_id=1,
            server_name="primary",
            success=False,
            error="SSM command finished with status 'Failed': peer not responding",
        )

        session, t, any_srv, tgt_srv = self._make_session_mock()

        result = await _control_tunnel(
            session, 42, action="initiate", user=_make_user(), request=_make_request()
        )

        assert result["success"] is False
        assert "peer not responding" in result["output"]

        # Audit still written
        mock_audit.assert_called_once()

    @pytest.mark.anyio
    @patch("app.services.tunnel_service.get_settings")
    async def test_missing_config_bucket_raises_infra_error(self, mock_settings):
        mock_settings.return_value.strongswan_config_bucket = ""
        session = AsyncMock()
        with pytest.raises(InfrastructureError) as exc_info:
            await _control_tunnel(
                session, 1, action="initiate", user=_make_user(), request=None
            )
        assert "STRONGSWAN_CONFIG_BUCKET" in exc_info.value.message

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_eip_not_associated_raises_infra_error_and_audit_written(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_resolve,
        mock_read_failover,
    ):
        """EIP not associated → 502 re-raised, AND an audit entry is written with the error."""
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.side_effect = InfrastructureError(
            "EC2", "EIP eipalloc-xxx is not currently associated"
        )

        session, t, any_srv, tgt_srv = self._make_session_mock()

        with pytest.raises(InfrastructureError) as exc_info:
            await _control_tunnel(
                session, 42, action="initiate", user=_make_user(), request=None
            )
        assert "not currently associated" in exc_info.value.message

        # Audit MUST be written even when node resolution failed — that is what
        # lets operators debug "what happened?" in the audit log.
        mock_audit.assert_called_once()
        audit_kwargs = mock_audit.call_args.kwargs
        assert audit_kwargs["action"] == "initiate"
        assert audit_kwargs["entity_type"] == "tunnel"
        new_state = audit_kwargs["new_state"]
        assert "error" in new_state
        assert "not currently associated" in new_state["error"]

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_command_uses_correct_swanctl_args_initiate(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_execute,
        mock_resolve,
        mock_read_failover,
    ):
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.return_value = (PRIMARY_INSTANCE, "primary")
        mock_execute.return_value = ServerResult(
            server_id=1, server_name="primary", success=True, output=""
        )

        tunnel = _make_tunnel(name="daniel-local-test")
        session, t, any_srv, tgt_srv = self._make_session_mock(tunnel=tunnel)

        await _control_tunnel(
            session, 42, action="initiate", user=_make_user(), request=None
        )

        # Verify swanctl command uses --child with the tunnel name
        mock_execute.assert_called_once()
        called_commands = mock_execute.call_args.args[2]  # list[str]
        assert len(called_commands) == 1
        cmd = called_commands[0]
        assert "/usr/sbin/swanctl" in cmd
        assert "--initiate" in cmd
        assert "--child daniel-local-test" in cmd
        assert f"--timeout {_SWANCTL_TIMEOUT}" in cmd

        # Wrapper timeout must be passed explicitly and be > swanctl timeout
        wrapper_timeout = mock_execute.call_args.kwargs.get("timeout")
        assert wrapper_timeout is not None, "timeout kwarg must be passed to execute_command"
        assert wrapper_timeout > _SWANCTL_TIMEOUT, (
            f"wrapper timeout {wrapper_timeout} must be > swanctl --timeout {_SWANCTL_TIMEOUT}"
        )

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_command_uses_correct_swanctl_args_terminate(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_execute,
        mock_resolve,
        mock_read_failover,
    ):
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.return_value = (PRIMARY_INSTANCE, "primary")
        mock_execute.return_value = ServerResult(
            server_id=1, server_name="primary", success=True, output=""
        )

        tunnel = _make_tunnel(name="daniel-local-test")
        session, t, any_srv, tgt_srv = self._make_session_mock(tunnel=tunnel)

        await _control_tunnel(
            session, 42, action="terminate", user=_make_user(), request=None
        )

        # Verify swanctl command uses --ike with the tunnel name for terminate
        called_commands = mock_execute.call_args.args[2]
        cmd = called_commands[0]
        assert "--terminate" in cmd
        assert "--ike daniel-local-test" in cmd
        assert f"--timeout {_SWANCTL_TIMEOUT}" in cmd

        # Wrapper timeout must exceed the swanctl --timeout
        wrapper_timeout = mock_execute.call_args.kwargs.get("timeout")
        assert wrapper_timeout is not None, "timeout kwarg must be passed to execute_command"
        assert wrapper_timeout > _SWANCTL_TIMEOUT

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_output_trimmed_to_2000_chars(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_execute,
        mock_resolve,
        mock_read_failover,
    ):
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.return_value = (PRIMARY_INSTANCE, "primary")
        long_output = "x" * 5000
        mock_execute.return_value = ServerResult(
            server_id=1, server_name="primary", success=True, output=long_output
        )

        session, t, any_srv, tgt_srv = self._make_session_mock()

        result = await _control_tunnel(
            session, 42, action="initiate", user=_make_user(), request=None
        )

        assert len(result["output"]) <= 2000

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_failed_ssm_audit_contains_swanctl_stderr_not_noise(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_execute,
        mock_resolve,
        mock_read_failover,
    ):
        """Failed SSM: audit output has real swanctl error, not plugin-load noise."""
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.return_value = (PRIMARY_INSTANCE, "primary")
        # Simulate execute_command carrying TransportError.stderr in result.output
        swanctl_stderr = (
            "plugin 'aes': failed to load - aes_plugin_create not found and no plugin file available\n"
            "agent plugin requires CAP_SETUID/CAP_SETGID capability\n"
            "plugin 'agent': failed to load - agent_plugin_create returned NULL\n"
            "initiate failed: CHILD_SA 'daniel-local-test' not established after 30000ms\n"
            "failed to run commands: exit status 1"
        )
        mock_execute.return_value = ServerResult(
            server_id=1,
            server_name="primary",
            success=False,
            output=swanctl_stderr,
            error="Transport error: SSM command abc on i-0xyz finished with status 'Failed'",
        )

        tunnel = _make_tunnel(name="daniel-local-test")
        session, t, any_srv, tgt_srv = self._make_session_mock(tunnel=tunnel)

        result = await _control_tunnel(
            session, 42, action="initiate", user=_make_user(), request=_make_request()
        )

        assert result["success"] is False
        # Real swanctl output must be present
        assert "initiate failed: CHILD_SA" in result["output"]
        assert "failed to run commands" in result["output"]
        # Plugin-load noise must be stripped
        assert "aes_plugin_create" not in result["output"]
        assert "plugin 'aes'" not in result["output"]
        assert "CAP_SETUID" not in result["output"]

        # Audit new_state.output must also contain the real output
        mock_audit.assert_called_once()
        new_state = mock_audit.call_args.kwargs["new_state"]
        assert "initiate failed: CHILD_SA" in new_state["output"]


# ---------------------------------------------------------------------------
# _filter_swanctl_output — noise filter unit tests
# ---------------------------------------------------------------------------


class TestFilterSwanctlOutput:
    """Unit tests for the strongSwan plugin-load noise filter."""

    def test_removes_plugin_failed_to_load_lines(self):
        raw = (
            "plugin 'aes': failed to load - aes_plugin_create not found\n"
            "initiate failed: CHILD_SA 'test' not established after 30000ms"
        )
        filtered = _filter_swanctl_output(raw)
        assert "aes_plugin_create" not in filtered
        assert "initiate failed: CHILD_SA" in filtered

    def test_removes_cap_setuid_lines(self):
        raw = (
            "agent plugin requires CAP_SETUID/CAP_SETGID capability\n"
            "initiate failed: CHILD_SA 'test' not established after 30000ms"
        )
        filtered = _filter_swanctl_output(raw)
        assert "CAP_SETUID" not in filtered
        assert "initiate failed: CHILD_SA" in filtered

    def test_removes_plugin_returned_null_lines(self):
        raw = (
            "plugin 'agent': failed to load - agent_plugin_create returned NULL\n"
            "some real output"
        )
        filtered = _filter_swanctl_output(raw)
        assert "agent_plugin_create" not in filtered
        assert "some real output" in filtered

    def test_non_noise_lines_pass_through(self):
        raw = "CHILD_SA established successfully\nIKE_SA up"
        filtered = _filter_swanctl_output(raw)
        assert filtered == raw

    def test_empty_string_returns_empty(self):
        assert _filter_swanctl_output("") == ""

    def test_all_noise_returns_empty(self):
        raw = (
            "plugin 'aes': failed to load - reason\n"
            "agent plugin requires CAP_SETUID/CAP_SETGID capability"
        )
        filtered = _filter_swanctl_output(raw)
        assert filtered == ""


# ---------------------------------------------------------------------------
# RBAC enforcement via HTTP layer
# ---------------------------------------------------------------------------


class TestRBACEnforcement:
    """Viewer gets 403; operator and admin are allowed."""

    @pytest.mark.anyio
    @patch("app.services.tunnel_service.initiate_tunnel", new_callable=AsyncMock)
    async def test_viewer_cannot_initiate(self, mock_initiate):
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        viewer = _make_user(role="viewer")

        async def _override_db():
            yield AsyncMock()

        async def _override_user():
            return viewer

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = _override_user

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/tunnels/42/initiate")
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.anyio
    @patch("app.services.tunnel_service.terminate_tunnel", new_callable=AsyncMock)
    async def test_viewer_cannot_terminate(self, mock_terminate):
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        viewer = _make_user(role="viewer")

        async def _override_db():
            yield AsyncMock()

        async def _override_user():
            return viewer

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = _override_user

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/tunnels/42/terminate")
            assert resp.status_code == 403
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.anyio
    @patch("app.services.tunnel_service.initiate_tunnel", new_callable=AsyncMock)
    async def test_operator_can_initiate(self, mock_initiate):
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        operator = _make_user(role="operator")
        mock_initiate.return_value = {
            "tunnel_id": 42,
            "action": "initiate",
            "node": "primary",
            "instance_id": PRIMARY_INSTANCE,
            "success": True,
            "output": "ok",
        }

        async def _override_db():
            yield AsyncMock()

        async def _override_user():
            return operator

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = _override_user

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/tunnels/42/initiate")
            assert resp.status_code == 200
            body = resp.json()
            assert body["tunnel_id"] == 42
            assert body["action"] == "initiate"
            assert body["success"] is True
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.anyio
    @patch("app.services.tunnel_service.terminate_tunnel", new_callable=AsyncMock)
    async def test_operator_can_terminate(self, mock_terminate):
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        operator = _make_user(role="operator")
        mock_terminate.return_value = {
            "tunnel_id": 7,
            "action": "terminate",
            "node": "secondary",
            "instance_id": SECONDARY_INSTANCE,
            "success": True,
            "output": "terminated",
        }

        async def _override_db():
            yield AsyncMock()

        async def _override_user():
            return operator

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = _override_user

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/tunnels/7/terminate")
            assert resp.status_code == 200
            body = resp.json()
            assert body["action"] == "terminate"
            assert body["node"] == "secondary"
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.anyio
    @patch("app.services.tunnel_service.initiate_tunnel", new_callable=AsyncMock)
    async def test_infrastructure_error_returns_502(self, mock_initiate):
        """InfrastructureError (e.g. EIP not associated) → 502."""
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        operator = _make_user(role="operator")
        mock_initiate.side_effect = InfrastructureError(
            "EC2", "EIP not currently associated"
        )

        async def _override_db():
            yield AsyncMock()

        async def _override_user():
            return operator

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = _override_user

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/tunnels/42/initiate")
            assert resp.status_code == 502
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.anyio
    @patch("app.services.tunnel_service.initiate_tunnel", new_callable=AsyncMock)
    async def test_not_found_returns_404(self, mock_initiate):
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        operator = _make_user(role="operator")
        mock_initiate.side_effect = NotFoundError("Tunnel", 999)

        async def _override_db():
            yield AsyncMock()

        async def _override_user():
            return operator

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = _override_user

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/tunnels/999/initiate")
            assert resp.status_code == 404
        finally:
            app.dependency_overrides.clear()

    @pytest.mark.anyio
    @patch("app.services.tunnel_service.initiate_tunnel", new_callable=AsyncMock)
    async def test_swanctl_failure_still_returns_200(self, mock_initiate):
        """swanctl command failure → 200 with success=false (not 5xx)."""
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        operator = _make_user(role="operator")
        mock_initiate.return_value = {
            "tunnel_id": 42,
            "action": "initiate",
            "node": "primary",
            "instance_id": PRIMARY_INSTANCE,
            "success": False,
            "output": "peer not responding",
        }

        async def _override_db():
            yield AsyncMock()

        async def _override_user():
            return operator

        app.dependency_overrides[get_db] = _override_db
        app.dependency_overrides[get_current_user] = _override_user

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post("/api/v1/tunnels/42/initiate")
            assert resp.status_code == 200
            body = resp.json()
            assert body["success"] is False
            assert "peer not responding" in body["output"]
        finally:
            app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Timeout — wrapper vs swanctl constant relationship
# ---------------------------------------------------------------------------


class TestTimeoutConstants:
    """Static assertions on the timeout constants used in _control_tunnel."""

    def test_wrapper_timeout_greater_than_swanctl_timeout(self):
        """_WRAPPER_TIMEOUT must be strictly greater than _SWANCTL_TIMEOUT.

        If they are equal (or the wrapper is smaller), asyncio.wait_for will
        cut off execute_command before swanctl's own --timeout fires, so the
        real swanctl output never comes back.
        """
        assert _WRAPPER_TIMEOUT > _SWANCTL_TIMEOUT, (
            f"_WRAPPER_TIMEOUT ({_WRAPPER_TIMEOUT}) must be > "
            f"_SWANCTL_TIMEOUT ({_SWANCTL_TIMEOUT})"
        )


# ---------------------------------------------------------------------------
# Transport timeout — audit written even when execute_command times out
# ---------------------------------------------------------------------------


class TestAuditOnTimeout:
    """Audit entry must be written even when execute_command returns a timeout."""

    def _make_session_mock(self, tunnel=None, active_server=None, target_server=None):
        session = AsyncMock()
        session.commit = AsyncMock()
        t = tunnel or _make_tunnel()
        any_srv = active_server or _make_server()
        tgt_srv = target_server or _make_server()
        exec_mock = AsyncMock()
        scalar_mock = MagicMock()
        scalar_mock.scalar_one_or_none.side_effect = [t, any_srv, tgt_srv]
        exec_mock.return_value = scalar_mock
        session.execute = exec_mock
        return session, t, any_srv, tgt_srv

    @pytest.mark.anyio
    @patch("app.services.tunnel_service._read_failover_config_for_control", new_callable=AsyncMock)
    @patch("app.services.tunnel_service._resolve_active_node", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_client_for_server")
    @patch("app.services.tunnel_service.get_settings")
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    async def test_audit_written_on_transport_timeout(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_execute,
        mock_resolve,
        mock_read_failover,
    ):
        """execute_command returns success=False with 'Command timed out' → audit still written."""
        mock_settings.return_value.strongswan_config_bucket = "test-bucket"
        mock_read_failover.return_value = FAILOVER_CONFIG
        mock_resolve.return_value = (PRIMARY_INSTANCE, "primary")
        mock_execute.return_value = ServerResult(
            server_id=1,
            server_name="primary",
            success=False,
            error="Command timed out",
        )

        session, t, any_srv, tgt_srv = self._make_session_mock()

        result = await _control_tunnel(
            session, 42, action="initiate", user=_make_user(), request=_make_request()
        )

        # Result exposes the timeout as a failed command
        assert result["success"] is False
        assert "timed out" in result["output"]

        # Audit must be written even on timeout
        mock_audit.assert_called_once()
        audit_kwargs = mock_audit.call_args.kwargs
        assert audit_kwargs["action"] == "initiate"
        new_state = audit_kwargs["new_state"]
        assert new_state["success"] is False
        assert "command" in new_state, "new_state must include the command that was run"


# ---------------------------------------------------------------------------
# Migration 0018 — constraint must include initiate and terminate
# ---------------------------------------------------------------------------


class TestMigration0018AuditConstraint:
    """The ck_audit_action constraint added in 0018 must cover the new action values."""

    def test_migration_includes_initiate_and_terminate(self):
        """Migration 0018 source must contain 'initiate' and 'terminate' in the constraint."""
        import pathlib

        mig_path = (
            pathlib.Path(__file__).parent.parent
            / "alembic" / "versions" / "0018_add_tunnel_control_audit_actions.py"
        )
        assert mig_path.exists(), f"Migration file not found: {mig_path}"
        source = mig_path.read_text()
        assert "'initiate'" in source, "Migration 0018 must include 'initiate' in ck_audit_action"
        assert "'terminate'" in source, "Migration 0018 must include 'terminate' in ck_audit_action"

    def test_migration_preserves_existing_actions(self):
        """Migration 0018 must preserve all pre-existing allowed action values."""
        import pathlib

        mig_path = (
            pathlib.Path(__file__).parent.parent
            / "alembic" / "versions" / "0018_add_tunnel_control_audit_actions.py"
        )
        source = mig_path.read_text()
        # Every value present in migration 0015's constraint must still be present
        for existing_action in ("'create'", "'update'", "'delete'", "'retry'", "'login'", "'rotate_psk'"):
            assert existing_action in source, (
                f"Migration 0018 must preserve existing action {existing_action}"
            )
