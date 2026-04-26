"""Tests for orchestration services — tunnel, iptables, build_iptables_command."""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.exceptions import ConflictError, NotFoundError


# ---------------------------------------------------------------------------
# build_iptables_command
# ---------------------------------------------------------------------------


class TestBuildIPTablesCommand:
    def _make_rule(self, **kwargs):
        """Create a mock IPTablesRule with sensible defaults."""
        defaults = {
            "chain": "FORWARD",
            "protocol": "tcp",
            "source_cidr": "10.0.0.0/24",
            "dest_cidr": "192.168.1.0/24",
            "sport": None,
            "dport": 443,
            "action": "ACCEPT",
            "state_match": None,
            "comment": None,
            "position": None,
        }
        defaults.update(kwargs)
        rule = MagicMock()
        for k, v in defaults.items():
            setattr(rule, k, v)
        return rule

    def test_basic_command(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule()
        cmd = build_iptables_command(rule)
        assert cmd == "iptables -A FORWARD -p tcp -s 10.0.0.0/24 -d 192.168.1.0/24 --dport 443 -j ACCEPT"

    def test_delete_flag(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule()
        cmd = build_iptables_command(rule, delete=True)
        assert cmd.startswith("iptables -D FORWARD")

    def test_all_protocol_omits_p_flag(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule(protocol="all", dport=None)
        cmd = build_iptables_command(rule)
        assert "-p" not in cmd

    def test_with_state_match(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule(state_match=["NEW", "ESTABLISHED"])
        cmd = build_iptables_command(rule)
        assert "-m state --state NEW,ESTABLISHED" in cmd

    def test_with_comment(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule(comment="Allow HTTPS")
        cmd = build_iptables_command(rule)
        assert '-m comment --comment "Allow HTTPS"' in cmd

    def test_with_sport(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule(sport=8080)
        cmd = build_iptables_command(rule)
        assert "--sport 8080" in cmd

    def test_minimal_rule(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule(
            protocol="all",
            source_cidr=None,
            dest_cidr=None,
            sport=None,
            dport=None,
        )
        cmd = build_iptables_command(rule)
        assert cmd == "iptables -A FORWARD -j ACCEPT"

    def test_icmp_no_ports(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule(protocol="icmp", sport=None, dport=None)
        cmd = build_iptables_command(rule)
        assert "-p icmp" in cmd
        assert "--sport" not in cmd
        assert "--dport" not in cmd


# ---------------------------------------------------------------------------
# Tunnel service — _parse_tunnel_state
# ---------------------------------------------------------------------------


class TestParseTunnelState:
    def test_up_tunnel(self):
        from app.services.tunnel_service import _parse_tunnel_state

        output = """
Security Associations (1 up, 0 connecting):
  prod-tunnel[1]: ESTABLISHED 3 hours ago, 10.0.0.1[local]...203.0.113.1[remote]
  prod-tunnel{1}: INSTALLED, TUNNEL, reqid 1
"""
        assert _parse_tunnel_state("prod-tunnel", output) == "UP"

    def test_down_tunnel(self):
        from app.services.tunnel_service import _parse_tunnel_state

        output = """
Security Associations (0 up, 1 connecting):
  prod-tunnel[1]: CONNECTING, 10.0.0.1[local]...203.0.113.1[remote]
"""
        assert _parse_tunnel_state("prod-tunnel", output) == "DOWN"

    def test_unknown_tunnel_not_in_output(self):
        from app.services.tunnel_service import _parse_tunnel_state

        output = "Security Associations (0 up, 0 connecting):"
        assert _parse_tunnel_state("missing-tunnel", output) == "UNKNOWN"

    def test_empty_output(self):
        from app.services.tunnel_service import _parse_tunnel_state

        assert _parse_tunnel_state("test", "") == "UNKNOWN"


# ---------------------------------------------------------------------------
# Tunnel service — create_tunnel
# ---------------------------------------------------------------------------


class TestTunnelServiceCreate:
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    async def test_create_tunnel_success(self, mock_lock, mock_sync, mock_audit):
        from app.services.tunnel_service import create_tunnel

        session = AsyncMock()
        # name uniqueness check returns None (no conflict)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        user = MagicMock()
        user.id = 1

        data = MagicMock()
        data.name = "new-tunnel"
        data.description = None
        data.peer_ip = "203.0.113.1"
        data.local_cidrs = ["10.0.0.0/24"]
        data.remote_cidrs = ["192.168.1.0/24"]
        data.psk = "vpn/psk"
        data.ike_version = "2"
        data.ike_proposals = None
        data.esp_proposals = None
        data.dpd_action = "restart"
        data.dpd_delay = 30
        data.dpd_timeout = 150

        tunnel = await create_tunnel(session, data=data, user=user)

        session.add.assert_called_once()
        session.flush.assert_called()
        session.commit.assert_called_once()
        mock_lock.assert_called_once()
        mock_sync.assert_called_once()
        mock_audit.assert_called_once()

    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    async def test_create_tunnel_duplicate_name(self, mock_lock):
        from app.services.tunnel_service import create_tunnel

        session = AsyncMock()
        # name uniqueness check returns an existing ID
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = 42
        session.execute.return_value = mock_result

        user = MagicMock()
        user.id = 1
        data = MagicMock()
        data.name = "existing-tunnel"

        with pytest.raises(ConflictError, match="already exists"):
            await create_tunnel(session, data=data, user=user)


# ---------------------------------------------------------------------------
# Tunnel service — retry_tunnel_sync
# ---------------------------------------------------------------------------


class TestTunnelServiceRetry:
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.s3.upload_file", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.ipsec_config.render_connection_conf", return_value="conn test\n")
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_retry_success(self, mock_get, mock_lock, mock_render, mock_upload, mock_fan_out, mock_audit):
        from app.services.tunnel_service import retry_tunnel_sync
        from app.utils.fan_out import FanOutResult, ServerResult

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.sync_status = "failed"
        tunnel.name = "test"
        tunnel.peer_ip = "1.2.3.4"
        tunnel.local_cidrs = ["10.0.0.0/24"]
        tunnel.remote_cidrs = ["192.168.0.0/24"]
        tunnel.created_at = datetime.now(timezone.utc)
        tunnel.updated_at = datetime.now(timezone.utc)
        mock_get.return_value = tunnel
        mock_fan_out.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        result = await retry_tunnel_sync(session, 1, user=user)
        assert result.sync_status == "synced"
        mock_upload.assert_called_once()
        mock_fan_out.assert_called_once()

    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_retry_not_failed_raises_conflict(self, mock_get):
        from app.services.tunnel_service import retry_tunnel_sync

        tunnel = MagicMock()
        tunnel.sync_status = "synced"
        mock_get.return_value = tunnel

        session = AsyncMock()
        user = MagicMock()

        with pytest.raises(ConflictError, match="not 'failed'"):
            await retry_tunnel_sync(session, 1, user=user)


# ---------------------------------------------------------------------------
# IPTables service — create_rule
# ---------------------------------------------------------------------------


class TestIPTablesServiceCreate:
    @patch("app.services.iptables_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.iptables_service.ssm.run_on_instances", new_callable=AsyncMock)
    @patch("app.services.iptables_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.iptables_service._get_active_tunnel", new_callable=AsyncMock)
    async def test_create_rule_success(self, mock_tunnel, mock_lock, mock_ssm, mock_audit):
        from app.services.iptables_service import create_rule

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        data = MagicMock()
        data.chain = "FORWARD"
        data.protocol = "tcp"
        data.source_cidr = None
        data.dest_cidr = None
        data.sport = None
        data.dport = 443
        data.action = "ACCEPT"
        data.state_match = None
        data.comment = None
        data.position = None

        rule = await create_rule(session, tunnel_id=1, data=data, user=user)

        session.add.assert_called_once()
        session.commit.assert_called_once()
        # SSM called twice: apply rule + iptables-save
        assert mock_ssm.call_count == 2
        mock_audit.assert_called_once()

    @patch("app.services.iptables_service._get_active_tunnel", new_callable=AsyncMock)
    async def test_create_rule_tunnel_not_found(self, mock_tunnel):
        from app.services.iptables_service import create_rule

        mock_tunnel.side_effect = NotFoundError("Tunnel", 999)

        session = AsyncMock()
        user = MagicMock()
        data = MagicMock()

        with pytest.raises(NotFoundError):
            await create_rule(session, tunnel_id=999, data=data, user=user)


# ---------------------------------------------------------------------------
# IPTables service — retry_rule
# ---------------------------------------------------------------------------


class TestIPTablesServiceRetry:
    @patch("app.services.iptables_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.iptables_service.ssm.run_on_instances", new_callable=AsyncMock)
    @patch("app.services.iptables_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.iptables_service.get_rule", new_callable=AsyncMock)
    async def test_retry_success(self, mock_get, mock_lock, mock_ssm, mock_audit):
        from app.services.iptables_service import retry_rule

        rule = MagicMock()
        rule.id = 1
        rule.sync_status = "failed"
        rule.chain = "FORWARD"
        rule.protocol = "tcp"
        rule.source_cidr = None
        rule.dest_cidr = None
        rule.sport = None
        rule.dport = 443
        rule.action = "ACCEPT"
        rule.state_match = None
        rule.comment = None
        rule.position = None
        rule.created_at = datetime.now(timezone.utc)
        rule.updated_at = datetime.now(timezone.utc)
        mock_get.return_value = rule

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        result = await retry_rule(session, 1, user=user)
        assert result.sync_status == "synced"

    @patch("app.services.iptables_service.get_rule", new_callable=AsyncMock)
    async def test_retry_not_failed(self, mock_get):
        from app.services.iptables_service import retry_rule

        rule = MagicMock()
        rule.sync_status = "synced"
        mock_get.return_value = rule

        session = AsyncMock()
        user = MagicMock()

        with pytest.raises(ConflictError, match="not 'failed'"):
            await retry_rule(session, 1, user=user)
