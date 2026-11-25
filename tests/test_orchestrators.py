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
        """Create a mock IPTablesRule with sensible defaults (filter table)."""
        defaults = {
            "rule_table": "filter",
            "chain": "FORWARD",
            "protocol": "tcp",
            "source_cidr": "10.0.0.0/24",
            "dest_cidr": "192.168.1.0/24",
            "sport": None,
            "dport": 443,
            "action": "ACCEPT",
            "to_source": None,
            "state_match": None,
            "comment": None,
            "position": None,
        }
        defaults.update(kwargs)
        rule = MagicMock()
        for k, v in defaults.items():
            setattr(rule, k, v)
        return rule

    def _make_snat_rule(self, **kwargs):
        """Create a mock IPTablesRule for nat/SNAT."""
        defaults = {
            "rule_table": "nat",
            "chain": "POSTROUTING",
            "protocol": "all",
            "source_cidr": "10.0.0.0/16",
            "dest_cidr": "192.168.50.0/24",
            "sport": None,
            "dport": None,
            "action": "SNAT",
            "to_source": "18.213.206.192",
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

    # --- SNAT / nat tests ---

    def test_snat_basic_command(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_snat_rule()
        cmd = build_iptables_command(rule)
        assert cmd == (
            "iptables -t nat -A POSTROUTING -s 10.0.0.0/16 -d 192.168.50.0/24"
            " -j SNAT --to-source 18.213.206.192"
        )

    def test_snat_delete_command(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_snat_rule()
        cmd = build_iptables_command(rule, delete=True)
        assert cmd == (
            "iptables -t nat -D POSTROUTING -s 10.0.0.0/16 -d 192.168.50.0/24"
            " -j SNAT --to-source 18.213.206.192"
        )

    def test_snat_positional_insert(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_snat_rule(position=1)
        cmd = build_iptables_command(rule)
        assert "-t nat -I POSTROUTING 1" in cmd
        assert "-j SNAT --to-source 18.213.206.192" in cmd

    def test_snat_with_source_cidr_only(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_snat_rule(source_cidr=None)
        cmd = build_iptables_command(rule)
        assert "-t nat" in cmd
        assert " -s " not in cmd
        assert "-d 192.168.50.0/24" in cmd

    def test_filter_rule_unaffected_by_snat_changes(self):
        """Filter rules must produce the same output as before SNAT support."""
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule()
        cmd = build_iptables_command(rule)
        assert cmd == "iptables -A FORWARD -p tcp -s 10.0.0.0/24 -d 192.168.1.0/24 --dport 443 -j ACCEPT"
        assert "-t nat" not in cmd
        assert "SNAT" not in cmd

    def test_filter_delete_unaffected(self):
        from app.services.iptables_service import build_iptables_command

        rule = self._make_rule(source_cidr=None, dest_cidr=None, dport=None, sport=None, protocol="all")
        cmd = build_iptables_command(rule, delete=True)
        assert cmd == "iptables -D FORWARD -j ACCEPT"
        assert "-t nat" not in cmd


# ---------------------------------------------------------------------------
# IPTables service — SNAT dest_cidr validation
# ---------------------------------------------------------------------------


class TestSnatDestCidrValidation:
    """_validate_cidr_rules is reused from route_service for SNAT rules."""

    def _make_tunnel(self, remote_cidrs: list[str]):
        tunnel = MagicMock()
        tunnel.remote_cidrs = remote_cidrs
        return tunnel

    def test_snat_dest_inside_remote_cidr(self):
        from app.services.route_service import _validate_cidr_rules
        from ipaddress import IPv4Network

        tunnel = self._make_tunnel(["192.168.50.0/24"])
        # Should not raise
        _validate_cidr_rules(tunnel, IPv4Network("192.168.50.0/24"))

    def test_snat_dest_subnet_of_remote_cidr(self):
        from app.services.route_service import _validate_cidr_rules
        from ipaddress import IPv4Network

        tunnel = self._make_tunnel(["192.168.50.0/24"])
        # Subnet is accepted
        _validate_cidr_rules(tunnel, IPv4Network("192.168.50.0/26"))

    def test_snat_dest_outside_remote_cidr_raises(self):
        from app.services.route_service import _validate_cidr_rules
        from app.exceptions import ValidationError
        from ipaddress import IPv4Network

        tunnel = self._make_tunnel(["192.168.50.0/24"])
        with pytest.raises(ValidationError, match="not inside any"):
            _validate_cidr_rules(tunnel, IPv4Network("10.0.0.0/8"))

    def test_snat_dest_default_route_raises(self):
        from app.services.route_service import _validate_cidr_rules
        from app.exceptions import ValidationError
        from ipaddress import IPv4Network

        tunnel = self._make_tunnel(["192.168.50.0/24"])
        with pytest.raises(ValidationError, match="prefix length 0"):
            _validate_cidr_rules(tunnel, IPv4Network("0.0.0.0/0"))


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

    def test_tunnel_down_when_not_in_output(self):
        from app.services.tunnel_service import _parse_tunnel_state

        output = "Security Associations (0 up, 0 connecting):"
        assert _parse_tunnel_state("missing-tunnel", output) == "DOWN"

    def test_empty_output(self):
        """Empty output with successful command means no SAs active → DOWN."""
        from app.services.tunnel_service import _parse_tunnel_state

        assert _parse_tunnel_state("test", "") == "DOWN"


# ---------------------------------------------------------------------------
# Tunnel service — create_tunnel
# ---------------------------------------------------------------------------


class TestTunnelServiceCreate:
    @patch("app.services.tunnel_service.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock, return_value="dGVzdC1jaXBoZXJ0ZXh0")
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    async def test_create_tunnel_success(self, mock_lock, mock_encrypt, mock_sync, mock_audit):
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
    @patch("app.services.tunnel_service.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.kms.decrypt_psk", new_callable=AsyncMock, return_value="test-psk-plaintext")
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_retry_success(self, mock_get, mock_lock, mock_decrypt, mock_sync, mock_audit):
        from app.services.tunnel_service import retry_tunnel_sync
        from app.utils.fan_out import FanOutResult, ServerResult

        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.sync_status = "failed"
        tunnel.name = "test"
        tunnel.psk_encrypted = "dGVzdC1jaXBoZXJ0ZXh0"
        tunnel.peer_ip = "1.2.3.4"
        tunnel.local_cidrs = ["10.0.0.0/24"]
        tunnel.remote_cidrs = ["192.168.0.0/24"]
        tunnel.created_at = datetime.now(timezone.utc)
        tunnel.updated_at = datetime.now(timezone.utc)
        mock_get.return_value = tunnel
        mock_sync.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        result = await retry_tunnel_sync(session, 1, user=user)
        assert result.sync_status == "synced"
        mock_decrypt.assert_called_once_with("dGVzdC1jaXBoZXJ0ZXh0")
        mock_sync.assert_called_once()

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
    @patch("app.services.iptables_service.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.iptables_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.iptables_service._get_active_tunnel", new_callable=AsyncMock)
    async def test_create_rule_success(self, mock_tunnel, mock_lock, mock_execute_all, mock_audit):
        from app.services.iptables_service import create_rule
        from app.utils.fan_out import FanOutResult, ServerResult

        mock_execute_all.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True)],
        )

        session = AsyncMock()
        user = MagicMock()
        user.id = 1

        data = MagicMock()
        data.rule_table = "filter"
        data.chain = "FORWARD"
        data.protocol = "tcp"
        data.source_cidr = None
        data.dest_cidr = None
        data.sport = None
        data.dport = 443
        data.action = "ACCEPT"
        data.to_source = None
        data.state_match = None
        data.comment = None
        data.position = None

        rule = await create_rule(session, tunnel_id=1, data=data, user=user)

        session.add.assert_called_once()
        session.commit.assert_called_once()
        # execute_on_all_servers called once with both commands combined
        mock_execute_all.assert_called_once()
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
    @patch("app.services.iptables_service.execute_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.iptables_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.iptables_service.get_rule", new_callable=AsyncMock)
    async def test_retry_success(self, mock_get, mock_lock, mock_execute_all, mock_audit):
        from app.services.iptables_service import retry_rule
        from app.utils.fan_out import FanOutResult, ServerResult

        mock_execute_all.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True)],
        )

        rule = MagicMock()
        rule.id = 1
        rule.sync_status = "failed"
        rule.rule_table = "filter"
        rule.chain = "FORWARD"
        rule.protocol = "tcp"
        rule.source_cidr = None
        rule.dest_cidr = None
        rule.sport = None
        rule.dport = 443
        rule.action = "ACCEPT"
        rule.to_source = None
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
