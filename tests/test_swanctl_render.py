"""Tests for swanctl single-file render and unchanged stroke renders."""
from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from app.services.ipsec_config import (
    render_connection_conf,
    render_secrets_file,
    render_swanctl_conf,
)


@pytest.fixture()
def tunnel():
    t = MagicMock()
    t.name = "vpn-test"
    t.peer_ip = "203.0.113.1"
    t.local_cidrs = ["10.0.1.0/24"]
    t.remote_cidrs = ["192.168.0.0/24"]
    t.ike_version = "2"
    t.ike_proposals = "aes256-sha256-modp2048"
    t.esp_proposals = "aes256-sha256-modp2048"
    t.dpd_action = "restart"
    t.dpd_delay = 30
    t.dpd_timeout = 150
    return t


class TestRenderSwanctlConf:
    """Unit tests for render_swanctl_conf — single-file swanctl format."""

    def test_contains_connections_block(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "connections {" in result
        assert "  vpn-test {" in result

    def test_contains_secrets_block(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "secrets {" in result
        assert "  ike-vpn-test {" in result
        assert 'secret = "test-psk-value"' in result

    def test_secrets_id_is_percent_any(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "id = %any" in result

    def test_contains_local_cidrs(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "local_ts = 10.0.1.0/24" in result

    def test_contains_remote_cidrs(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "remote_ts = 192.168.0.0/24" in result

    def test_contains_peer_ip(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "remote_addrs = 203.0.113.1" in result

    def test_leftid_derived_from_local_cidrs(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        # local_cidrs[0] = "10.0.1.0/24" → id = 10.0.1.0
        assert "id = 10.0.1.0" in result

    def test_ike_version_present(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "version = 2" in result

    def test_ike_proposals_present_when_set(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "proposals = aes256-sha256-modp2048" in result

    def test_esp_proposals_present_when_set(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "esp_proposals = aes256-sha256-modp2048" in result

    def test_proposals_absent_when_none(self, tunnel):
        tunnel.ike_proposals = None
        tunnel.esp_proposals = None
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "proposals" not in result

    def test_dpd_delay_present(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "dpd_delay = 30s" in result

    def test_dpd_action_present(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "dpd_action = restart" in result

    def test_no_stroke_leftsendcert(self, tunnel):
        """leftsendcert has no swanctl equivalent — must not appear."""
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "leftsendcert" not in result

    def test_no_stroke_rekeymargin(self, tunnel):
        """rekeymargin has no stored equivalent in the model — must not appear."""
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "rekeymargin" not in result

    def test_encap_yes(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "encap = yes" in result

    def test_ends_with_newline(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert result.endswith("\n")

    def test_psk_value_in_secret(self, tunnel):
        result = render_swanctl_conf(tunnel, "super-secret-key-123")
        assert 'secret = "super-secret-key-123"' in result

    def test_leftid_any_when_no_local_cidrs(self):
        t = MagicMock()
        t.name = "empty"
        t.peer_ip = "1.2.3.4"
        t.local_cidrs = []
        t.remote_cidrs = ["10.0.0.0/8"]
        t.ike_version = "2"
        t.ike_proposals = None
        t.esp_proposals = None
        t.dpd_action = "none"
        t.dpd_delay = 30
        result = render_swanctl_conf(t, "psk")
        assert "id = %any" in result


class TestStrokeRendersUnchanged:
    """Verify stroke renders are not modified by this change."""

    def test_stroke_render_connection_conf_format(self, tunnel):
        result = render_connection_conf(tunnel)
        assert result.startswith(f"conn {tunnel.name}")
        assert "left=%any" in result
        assert "rightauth=psk" in result
        assert "leftauth=psk" in result

    def test_stroke_render_contains_peer_ip(self, tunnel):
        result = render_connection_conf(tunnel)
        assert f"right={tunnel.peer_ip}" in result

    def test_stroke_render_does_not_contain_connections_block(self, tunnel):
        result = render_connection_conf(tunnel)
        assert "connections {" not in result

    def test_stroke_secrets_format(self, tunnel):
        result = render_secrets_file(tunnel, "my-psk")
        assert 'PSK "my-psk"' in result

    def test_stroke_secrets_contains_peer_ip(self, tunnel):
        result = render_secrets_file(tunnel, "my-psk")
        assert "203.0.113.1" in result

    def test_stroke_secrets_does_not_contain_ike_prefix(self, tunnel):
        result = render_secrets_file(tunnel, "my-psk")
        assert "ike-" not in result


class TestServerModelIpsecEngineDefault:
    """Verify Server model has ipsec_engine with server_default='stroke'."""

    def test_server_ipsec_engine_column_has_stroke_default(self):
        from app.db.models import Server
        col = Server.__table__.c["ipsec_engine"]
        assert col.server_default is not None
        assert "stroke" in str(col.server_default.arg)

    def test_server_ipsec_engine_column_not_nullable(self):
        from app.db.models import Server
        col = Server.__table__.c["ipsec_engine"]
        assert col.nullable is False
