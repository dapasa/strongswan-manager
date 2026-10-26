"""Tests for stroke render: local_id, ike_lifetime, strict proposals."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.ipsec_config import render_connection_conf, render_secrets_file


@pytest.fixture()
def tunnel():
    t = MagicMock()
    t.name = "wlm-tunnel"
    t.peer_ip = "54.156.125.235"
    t.local_cidrs = ["10.0.0.0/24"]
    t.remote_cidrs = ["172.16.0.0/24"]
    t.ike_version = "2"
    t.ike_proposals = "aes256-sha256-modp2048"
    t.esp_proposals = "aes256-sha256-modp2048"
    t.dpd_action = "restart"
    t.dpd_delay = 30
    t.dpd_timeout = 150
    t.local_id = None
    t.remote_id = None
    t.start_action = "none"
    t.ike_lifetime = 86400
    return t


class TestStrokeLocalId:
    def test_local_id_absent_when_none(self, tunnel):
        tunnel.local_id = None
        result = render_connection_conf(tunnel)
        assert "leftid=" not in result

    def test_local_id_present_when_set(self, tunnel):
        tunnel.local_id = "44.215.155.152"
        result = render_connection_conf(tunnel)
        assert "leftid=44.215.155.152" in result

    def test_cidr_not_used_as_leftid(self, tunnel):
        """The CIDR network address must NOT appear as leftid."""
        tunnel.local_id = None
        result = render_connection_conf(tunnel)
        assert "leftid=10.0.0.0" not in result


class TestStrokeIkeLifetime:
    def test_ike_lifetime_default(self, tunnel):
        result = render_connection_conf(tunnel)
        assert "ikelifetime=86400s" in result

    def test_ike_lifetime_custom(self, tunnel):
        tunnel.ike_lifetime = 28800
        result = render_connection_conf(tunnel)
        assert "ikelifetime=28800s" in result


class TestStrokeStrictProposals:
    def test_ike_proposals_have_bang(self, tunnel):
        tunnel.ike_proposals = "aes256-sha256-modp2048"
        result = render_connection_conf(tunnel)
        assert "ike=aes256-sha256-modp2048!" in result

    def test_esp_proposals_have_bang(self, tunnel):
        tunnel.esp_proposals = "aes256-sha256"
        result = render_connection_conf(tunnel)
        assert "esp=aes256-sha256!" in result

    def test_no_double_bang_ike(self, tunnel):
        """Input already ending with '!' must not produce '!!'."""
        tunnel.ike_proposals = "aes256-sha256-modp2048!"
        result = render_connection_conf(tunnel)
        assert "!!" not in result
        assert "ike=aes256-sha256-modp2048!" in result

    def test_no_double_bang_esp(self, tunnel):
        tunnel.esp_proposals = "aes256-sha256!"
        result = render_connection_conf(tunnel)
        assert "!!" not in result
        assert "esp=aes256-sha256!" in result

    def test_proposals_absent_when_none(self, tunnel):
        tunnel.ike_proposals = None
        tunnel.esp_proposals = None
        result = render_connection_conf(tunnel)
        assert "\n    ike=" not in result
        assert "\n    esp=" not in result


class TestTunnelModelDefaults:
    def test_tunnel_ike_lifetime_column_default(self):
        from app.db.models import Tunnel
        col = Tunnel.__table__.c["ike_lifetime"]
        assert col.server_default is not None
        assert "86400" in str(col.server_default.arg)

    def test_tunnel_local_id_nullable(self):
        from app.db.models import Tunnel
        col = Tunnel.__table__.c["local_id"]
        assert col.nullable is True


class TestStrokeStartAction:
    def test_start_action_trap_renders_route(self, tunnel):
        """start_action=trap maps to auto=route in stroke conf."""
        tunnel.start_action = "trap"
        result = render_connection_conf(tunnel)
        assert "auto=route" in result

    def test_start_action_none_renders_add(self, tunnel):
        """start_action=none maps to auto=add in stroke conf."""
        tunnel.start_action = "none"
        result = render_connection_conf(tunnel)
        assert "auto=add" in result

    def test_start_action_start_renders_start(self, tunnel):
        """start_action=start maps to auto=start in stroke conf."""
        tunnel.start_action = "start"
        result = render_connection_conf(tunnel)
        assert "auto=start" in result


class TestStrokeRightId:
    def test_rightid_uses_remote_id_when_set(self, tunnel):
        """rightid must be the explicit remote_id when provided."""
        tunnel.remote_id = "203.0.113.42"
        result = render_connection_conf(tunnel)
        assert "rightid=203.0.113.42" in result

    def test_rightid_falls_back_to_peer_ip_when_remote_id_empty(self, tunnel):
        """rightid must fall back to peer_ip when remote_id is None."""
        tunnel.remote_id = None
        result = render_connection_conf(tunnel)
        assert f"rightid={tunnel.peer_ip}" in result
        assert "rightid=%any" not in result
