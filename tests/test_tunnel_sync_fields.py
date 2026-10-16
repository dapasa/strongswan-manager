"""Tests that TUNNEL_RENDER_FIELDS covers all fields read by the renderers,
and that PATCH on any render field triggers an infrastructure sync.
"""
from __future__ import annotations

import inspect
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.services.tunnel_service import TUNNEL_RENDER_FIELDS


# ---------------------------------------------------------------------------
# Coverage guard: every field the renderers read must be in TUNNEL_RENDER_FIELDS
# ---------------------------------------------------------------------------

class TestRenderFieldsCoverage:
    """Every Tunnel attribute used in render_connection_conf and render_swanctl_conf
    must be listed in TUNNEL_RENDER_FIELDS so that a PATCH on such a field triggers sync.
    """

    def _render_field_names(self) -> set[str]:
        """Return field names accessed as tunnel.<attr> inside ipsec_config module."""
        import app.services.ipsec_config as mod
        src = inspect.getsource(mod)
        import re
        # Find all "tunnel.<identifier>" patterns
        return {m.group(1) for m in re.finditer(r"tunnel\.([a-z_]+)", src)}

    def test_render_fields_covers_all_renderer_accesses(self):
        """TUNNEL_RENDER_FIELDS must contain every tunnel attribute the renderers touch."""
        accessed = self._render_field_names()
        # Exclude non-data attributes that are not DB columns (e.g. 'name' is already in)
        # and exclude 'psk_secret_name' which is metadata, not render input
        non_render = {"psk_secret_name", "sync_status", "sync_error", "sync_details",
                      "status", "description", "created_by", "deleted_at"}
        render_accessed = accessed - non_render
        missing = render_accessed - TUNNEL_RENDER_FIELDS
        assert not missing, (
            f"Fields read by renderers but missing from TUNNEL_RENDER_FIELDS: {sorted(missing)}. "
            "Add them so that PATCH on those fields triggers infra sync."
        )

    def test_local_id_in_render_fields(self):
        assert "local_id" in TUNNEL_RENDER_FIELDS

    def test_ike_lifetime_in_render_fields(self):
        assert "ike_lifetime" in TUNNEL_RENDER_FIELDS

    def test_peer_ip_in_render_fields(self):
        assert "peer_ip" in TUNNEL_RENDER_FIELDS

    def test_ike_proposals_in_render_fields(self):
        assert "ike_proposals" in TUNNEL_RENDER_FIELDS


# ---------------------------------------------------------------------------
# Behavioural: PATCH with local_id alone must trigger sync
# ---------------------------------------------------------------------------

def _make_tunnel(name: str = "t1") -> MagicMock:
    t = MagicMock()
    t.id = 1
    t.name = name
    t.description = None
    t.peer_ip = "203.0.113.1"
    t.local_cidrs = ["10.0.0.0/24"]
    t.remote_cidrs = ["192.168.1.0/24"]
    t.ike_version = "2"
    t.ike_proposals = "aes256-sha256-modp2048"
    t.esp_proposals = "aes256-sha256-modp2048"
    t.dpd_action = "restart"
    t.dpd_delay = 30
    t.dpd_timeout = 150
    t.local_id = None
    t.ike_lifetime = 86400
    t.status = "active"
    t.sync_status = "synced"
    t.sync_error = None
    t.sync_details = None
    t.psk_secret_name = f"secrets/{name}.secrets"
    t.created_by = 1
    t.deleted_at = None
    t.routes = []
    t.iptables_rules = []
    t.creator = None
    return t


class TestPatchLocalIdTriggerSync:
    """PATCH with only local_id must trigger infra sync (regression guard)."""

    def _make_fan_out(self) -> MagicMock:
        fan_out = MagicMock()
        fan_out.to_sync_status.return_value = "synced"
        fan_out.to_sync_error.return_value = None
        fan_out.to_sync_details.return_value = None
        return fan_out

    def _make_session(self) -> AsyncMock:
        session = AsyncMock()
        name_check = MagicMock()
        name_check.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=name_check)
        session.commit = AsyncMock()
        session.refresh = AsyncMock()
        session.flush = AsyncMock()
        return session

    @pytest.mark.asyncio
    @patch("app.services.tunnel_service.sftp_push_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit")
    @patch("app.services.tunnel_service.ipsec_config")
    async def test_patch_local_id_triggers_sync(
        self, mock_ipsec, mock_audit, mock_lock, mock_push
    ):
        """PATCH with only local_id must trigger infra sync (conf re-upload + fan-out)."""
        from app.services.tunnel_service import update_tunnel
        from app.schemas.tunnel import TunnelUpdate

        tunnel = _make_tunnel()
        mock_audit.log_action = AsyncMock()
        fan_out = self._make_fan_out()
        # psk=None path: render_connection_conf + sftp_push_on_all_servers (no sync_tunnel_config)
        mock_ipsec.render_connection_conf.return_value = "conn t1\n"
        mock_push.return_value = fan_out

        # s3 is imported as a local import inside the else-branch; patch the module directly
        with patch("app.services.s3") as mock_s3, \
             patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock, return_value=tunnel):
            mock_s3.upload_file = AsyncMock()
            data = TunnelUpdate(local_id="44.215.155.152")
            await update_tunnel(self._make_session(), tunnel.id, data=data, user=MagicMock(id=1), request=None)

        # render_connection_conf was called (sync path entered)
        mock_ipsec.render_connection_conf.assert_called_once()
        # sftp fan-out was triggered
        mock_push.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.services.tunnel_service.sftp_push_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit")
    @patch("app.services.tunnel_service.ipsec_config")
    async def test_patch_ike_lifetime_triggers_sync(
        self, mock_ipsec, mock_audit, mock_lock, mock_push
    ):
        from app.services.tunnel_service import update_tunnel
        from app.schemas.tunnel import TunnelUpdate

        tunnel = _make_tunnel()
        mock_audit.log_action = AsyncMock()
        fan_out = self._make_fan_out()
        mock_ipsec.render_connection_conf.return_value = "conn t1\n"
        mock_push.return_value = fan_out

        with patch("app.services.s3") as mock_s3, \
             patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock, return_value=tunnel):
            mock_s3.upload_file = AsyncMock()
            data = TunnelUpdate(ike_lifetime=7200)
            await update_tunnel(self._make_session(), tunnel.id, data=data, user=MagicMock(id=1), request=None)

        mock_ipsec.render_connection_conf.assert_called_once()
        mock_push.assert_called_once()

    @pytest.mark.asyncio
    @patch("app.services.tunnel_service.sftp_push_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.audit")
    @patch("app.services.tunnel_service.ipsec_config")
    async def test_patch_description_only_does_not_trigger_sync(
        self, mock_ipsec, mock_audit, mock_lock, mock_push
    ):
        """PATCH on description (non-render field) must NOT trigger infra sync."""
        from app.services.tunnel_service import update_tunnel
        from app.schemas.tunnel import TunnelUpdate

        tunnel = _make_tunnel()
        mock_audit.log_action = AsyncMock()

        with patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock, return_value=tunnel):
            data = TunnelUpdate(description="just a label change")
            await update_tunnel(self._make_session(), tunnel.id, data=data, user=MagicMock(id=1), request=None)

        mock_ipsec.render_connection_conf.assert_not_called()
        mock_push.assert_not_called()
