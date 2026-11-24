"""Unit tests for tunnel initiate / terminate endpoints and service layer.

Covers:
- Role enforcement: viewer → 403, operator → allowed, admin → allowed
- Active node resolution: primary vs secondary holder
- Command built correctly for initiate and terminate actions
- swanctl success → 200 success=true
- swanctl command failure → 200 success=false
- SSM infrastructure failure → 502 (InfrastructureError)
- Tunnel not found → 404
- EIP not associated → 502
- Audit entry written on each call
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch, call

import pytest
from botocore.exceptions import ClientError
from fastapi import Request

from app.db.models import Server, Tunnel, User
from app.exceptions import InfrastructureError, NotFoundError
from app.services.tunnel_service import (
    _control_tunnel,
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
    async def test_eip_not_associated_raises_infra_error(
        self,
        mock_audit,
        mock_settings,
        mock_get_client,
        mock_resolve,
        mock_read_failover,
    ):
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
        # Audit must NOT be written when we didn't execute the command
        mock_audit.assert_not_called()

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
        assert "--timeout 30" in cmd

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
        assert "--timeout 30" in cmd

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
