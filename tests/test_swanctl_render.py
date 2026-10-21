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
    t.local_id = None
    t.ike_lifetime = 86400
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

    def test_local_id_absent_when_none(self, tunnel):
        """When local_id is None no id line appears in the local block."""
        tunnel.local_id = None
        result = render_swanctl_conf(tunnel, "test-psk-value")
        local_pos = result.index("    local {")
        local_close = result.index("    }", local_pos)
        local_block = result[local_pos:local_close]
        assert "id =" not in local_block

    def test_local_id_present_when_set(self, tunnel):
        """When local_id is set it appears inside the local block."""
        tunnel.local_id = "44.215.155.152"
        result = render_swanctl_conf(tunnel, "test-psk-value")
        local_pos = result.index("    local {")
        local_close = result.index("    }", local_pos)
        local_block = result[local_pos:local_close]
        assert "id = 44.215.155.152" in local_block

    def test_cidr_not_used_as_local_id(self, tunnel):
        """The first local CIDR network address must NOT appear as id."""
        tunnel.local_id = None
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "id = 10.0.1.0" not in result

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

    def test_local_block_has_no_send_cert(self, tunnel):
        """send_cert is not a valid key inside local { }; swanctl rejects it."""
        result = render_swanctl_conf(tunnel, "test-psk-value")
        local_pos = result.index("    local {")
        local_close = result.index("    }", local_pos)
        local_block = result[local_pos:local_close]
        assert "send_cert" not in local_block

    def test_no_invalid_connection_options(self, tunnel):
        """rekey_attempts and compress do not exist in swanctl; keyingtries does."""
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "rekey_attempts" not in result
        assert "compress" not in result
        assert "keyingtries = 0" in result

    def test_psk_quotes_and_backslashes_are_escaped(self, tunnel):
        """A '"' or '\\' in the PSK must not break the quoted secret."""
        result = render_swanctl_conf(tunnel, 'a"b\\c')
        assert 'secret = "a\\"b\\\\c"' in result

    def test_no_stroke_leftsendcert_literal(self, tunnel):
        """The stroke attribute name leftsendcert must not appear verbatim."""
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

    def test_ike_lifetime_in_connection(self, tunnel):
        """ike_lifetime maps to rekey_time at the IKE connection level."""
        tunnel.ike_lifetime = 28800
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "rekey_time = 28800s" in result

    def test_default_ike_lifetime(self, tunnel):
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "rekey_time = 86400s" in result

    def test_swanctl_proposals_no_bang(self, tunnel):
        """swanctl proposals must NOT have a '!' suffix (strict by default)."""
        tunnel.ike_proposals = "aes256-sha256-modp2048"
        result = render_swanctl_conf(tunnel, "test-psk-value")
        assert "!" not in result

    def test_secrets_id_percent_any_unchanged(self, tunnel):
        """The secrets block id = %any must remain regardless of local_id."""
        tunnel.local_id = "44.215.155.152"
        result = render_swanctl_conf(tunnel, "test-psk-value")
        secrets_pos = result.index("secrets {")
        secrets_block = result[secrets_pos:]
        assert "id = %any" in secrets_block

    def test_no_cidr_id_when_empty_local_cidrs(self):
        """With empty local_cidrs and no local_id there is no id line in local block."""
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
        t.local_id = None
        t.ike_lifetime = 86400
        result = render_swanctl_conf(t, "psk")
        # No local_id set — id line must not appear in local block
        local_pos = result.index("    local {")
        local_close = result.index("    }", local_pos)
        local_block = result[local_pos:local_close]
        assert "id =" not in local_block


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
