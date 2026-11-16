"""Tests for infrastructure services — all external calls mocked."""
from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from app.exceptions import InfrastructureError, LockConflictError


# ---------------------------------------------------------------------------
# Locks
# ---------------------------------------------------------------------------


class TestAdvisoryLocks:
    async def test_acquire_lock_success(self):
        from app.services.locks import acquire_advisory_lock

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = True
        session.execute.return_value = mock_result

        acquired = await acquire_advisory_lock(session, lock_key=1)
        assert acquired is True
        session.execute.assert_called_once()

    async def test_acquire_lock_denied(self):
        from app.services.locks import acquire_advisory_lock

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = False
        session.execute.return_value = mock_result

        acquired = await acquire_advisory_lock(session, lock_key=1)
        assert acquired is False

    async def test_require_lock_raises_on_denial(self):
        from app.services.locks import require_lock

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = False
        session.execute.return_value = mock_result

        with pytest.raises(LockConflictError) as exc_info:
            await require_lock(session, lock_key=2)
        assert exc_info.value.lock_id == 2

    async def test_require_lock_succeeds(self):
        from app.services.locks import require_lock

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one.return_value = True
        session.execute.return_value = mock_result

        await require_lock(session, lock_key=1)  # Should not raise


# ---------------------------------------------------------------------------
# Audit service
# ---------------------------------------------------------------------------


class TestAuditService:
    async def test_log_action_with_request(self):
        from app.services.audit import log_action

        session = AsyncMock()
        request = MagicMock()
        request.headers = {"user-agent": "TestAgent/1.0", "x-forwarded-for": "10.0.0.1"}
        request.client.host = "127.0.0.1"

        await log_action(
            session,
            user_id=1,
            entity_type="tunnel",
            entity_id=42,
            action="create",
            new_state={"name": "test"},
            request=request,
        )

        session.add.assert_called_once()
        entry = session.add.call_args[0][0]
        assert entry.user_id == 1
        assert entry.entity_type == "tunnel"
        assert entry.action == "create"
        assert entry.ip_address == "10.0.0.1"
        assert entry.user_agent == "TestAgent/1.0"

    async def test_log_action_without_request(self):
        from app.services.audit import log_action

        session = AsyncMock()

        await log_action(
            session,
            user_id=1,
            entity_type="route",
            entity_id=10,
            action="delete",
            previous_state={"cidr": "10.0.0.0/8"},
        )

        session.add.assert_called_once()
        entry = session.add.call_args[0][0]
        assert entry.ip_address is None
        assert entry.user_agent is None

    async def test_log_action_does_not_commit(self):
        from app.services.audit import log_action

        session = AsyncMock()

        await log_action(
            session,
            user_id=1,
            entity_type="tunnel",
            entity_id=1,
            action="update",
        )

        session.commit.assert_not_called()


# ---------------------------------------------------------------------------
# KMS service
# ---------------------------------------------------------------------------


class TestKMSService:
    @patch("app.services.kms._get_kms_client")
    @patch("app.services.kms.get_settings")
    async def test_encrypt_psk_success(self, mock_settings, mock_client_fn):
        import base64
        from app.services.kms import encrypt_psk

        mock_settings.return_value = MagicMock(kms_psk_key_id="alias/test-key")
        mock_client = MagicMock()
        mock_client.encrypt.return_value = {"CiphertextBlob": b"raw-ciphertext"}
        mock_client_fn.return_value = mock_client

        result = await encrypt_psk("MySuperSecretPSK")
        assert result == base64.b64encode(b"raw-ciphertext").decode("ascii")
        mock_client.encrypt.assert_called_once()
        call_kwargs = mock_client.encrypt.call_args[1]
        assert call_kwargs["KeyId"] == "alias/test-key"
        assert call_kwargs["Plaintext"] == b"MySuperSecretPSK"

    @patch("app.services.kms._get_kms_client")
    @patch("app.services.kms.get_settings")
    async def test_decrypt_psk_success(self, mock_settings, mock_client_fn):
        import base64
        from app.services.kms import decrypt_psk

        mock_settings.return_value = MagicMock(kms_psk_key_id="alias/test-key")
        mock_client = MagicMock()
        mock_client.decrypt.return_value = {"Plaintext": b"MySuperSecretPSK"}
        mock_client_fn.return_value = mock_client

        ciphertext_b64 = base64.b64encode(b"raw-ciphertext").decode("ascii")
        result = await decrypt_psk(ciphertext_b64)
        assert result == "MySuperSecretPSK"
        mock_client.decrypt.assert_called_once_with(CiphertextBlob=b"raw-ciphertext")

    @patch("app.services.kms._get_kms_client")
    @patch("app.services.kms.get_settings")
    async def test_encrypt_psk_failure(self, mock_settings, mock_client_fn):
        from app.services.kms import encrypt_psk

        mock_settings.return_value = MagicMock(kms_psk_key_id="alias/test-key")
        error_response = {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}}
        mock_client = MagicMock()
        mock_client.encrypt.side_effect = ClientError(error_response, "Encrypt")
        mock_client_fn.return_value = mock_client

        with pytest.raises(InfrastructureError) as exc_info:
            await encrypt_psk("psk")
        assert exc_info.value.service == "KMS"


# ---------------------------------------------------------------------------
# SSM service
# ---------------------------------------------------------------------------


class TestSSMService:
    @patch("app.services.ssm._get_ec2_client")
    @patch("app.services.ssm.get_settings")
    async def test_resolve_instance_id_success(self, mock_settings, mock_ec2_fn):
        from app.services.ssm import _instance_id_cache, resolve_instance_id

        # Clear cache for test isolation
        _instance_id_cache.clear()

        mock_settings.return_value = MagicMock()
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {
            "Reservations": [{"Instances": [{"InstanceId": "i-abc123"}]}]
        }
        mock_ec2_fn.return_value = mock_ec2

        instance_id = await resolve_instance_id("strongswan-primary")
        assert instance_id == "i-abc123"

    @patch("app.services.ssm._get_ec2_client")
    @patch("app.services.ssm.get_settings")
    async def test_resolve_instance_id_not_found(self, mock_settings, mock_ec2_fn):
        from app.services.ssm import _instance_id_cache, resolve_instance_id

        _instance_id_cache.clear()

        mock_settings.return_value = MagicMock()
        mock_ec2 = MagicMock()
        mock_ec2.describe_instances.return_value = {"Reservations": []}
        mock_ec2_fn.return_value = mock_ec2

        with pytest.raises(InfrastructureError) as exc_info:
            await resolve_instance_id("nonexistent-instance")
        assert "No running instance" in exc_info.value.message

    @patch("app.services.ssm._get_ec2_client")
    @patch("app.services.ssm.get_settings")
    async def test_resolve_instance_id_uses_cache(self, mock_settings, mock_ec2_fn):
        from app.services.ssm import _instance_id_cache, resolve_instance_id

        _instance_id_cache.clear()
        _instance_id_cache["cached-instance"] = "i-cached999"

        instance_id = await resolve_instance_id("cached-instance")
        assert instance_id == "i-cached999"
        mock_ec2_fn.return_value.describe_instances.assert_not_called()

    @patch("app.services.ssm.run_on_instances", new_callable=AsyncMock)
    @patch("app.services.ssm.get_settings")
    async def test_reload_ipsec_calls_both(self, mock_settings, mock_run):
        from app.services.ssm import reload_ipsec

        mock_settings.return_value = MagicMock()
        await reload_ipsec()
        mock_run.assert_called_once_with(
            commands=["/opt/strongswan/scripts/sync_config.sh"], target="both"
        )

    @patch("app.services.ssm.execute_command", new_callable=AsyncMock)
    @patch("app.services.ssm.resolve_instance_id", new_callable=AsyncMock)
    @patch("app.services.ssm.get_settings")
    async def test_run_on_instances_primary(self, mock_settings, mock_resolve, mock_exec):
        from app.services.ssm import run_on_instances

        settings = MagicMock()
        settings.vpn_primary_instance_name = "vpn-primary"
        settings.vpn_secondary_instance_name = "vpn-secondary"
        settings.ssm_command_timeout = 60
        mock_settings.return_value = settings
        mock_resolve.return_value = "i-primary"

        await run_on_instances(commands=["echo test"], target="primary")

        mock_resolve.assert_called_once_with("vpn-primary")
        mock_exec.assert_called_once()

    @patch("app.services.ssm.get_settings")
    async def test_run_on_instances_invalid_target(self, mock_settings):
        from app.services.ssm import run_on_instances

        mock_settings.return_value = MagicMock()

        with pytest.raises(ValueError, match="Invalid target"):
            await run_on_instances(commands=["echo"], target="invalid")


# ---------------------------------------------------------------------------
# IPSec config generator
# ---------------------------------------------------------------------------


class TestIPSecConfigGenerator:
    def test_render_connection_conf(self):
        from app.services.ipsec_config import render_connection_conf

        tunnel = MagicMock()
        tunnel.name = "prod-tunnel"
        tunnel.ike_version = "2"
        tunnel.local_cidrs = ["10.0.0.0/24", "10.0.1.0/24"]
        tunnel.peer_ip = "203.0.113.1"
        tunnel.remote_cidrs = ["192.168.1.0/24"]
        tunnel.ike_proposals = "aes256-sha512-ecp521"
        tunnel.esp_proposals = "aes256-sha512-ecp521"
        tunnel.dpd_action = "restart"
        tunnel.dpd_delay = 30
        tunnel.dpd_timeout = 150

        content = render_connection_conf(tunnel)
        assert "conn prod-tunnel" in content
        assert "keyexchange=ikev2" in content
        assert "left=%any" in content
        assert "leftsubnet=10.0.0.0/24,10.0.1.0/24" in content
        assert "right=203.0.113.1" in content
        assert "rightsubnet=192.168.1.0/24" in content
        assert "dpdaction=restart" in content
        assert "ike=aes256-sha512-ecp521" in content
        assert "esp=aes256-sha512-ecp521" in content

    def test_render_connection_conf_no_proposals(self):
        from app.services.ipsec_config import render_connection_conf

        tunnel = MagicMock()
        tunnel.name = "simple"
        tunnel.ike_version = "2"
        tunnel.local_cidrs = ["10.0.0.0/24"]
        tunnel.peer_ip = "1.2.3.4"
        tunnel.remote_cidrs = ["192.168.0.0/24"]
        tunnel.ike_proposals = None
        tunnel.esp_proposals = None
        tunnel.dpd_action = "restart"
        tunnel.dpd_delay = 30
        tunnel.dpd_timeout = 150

        content = render_connection_conf(tunnel)
        assert "conn simple" in content
        assert "\n    ike=" not in content
        assert "\n    esp=" not in content

    def test_render_secrets_file(self):
        from app.services.ipsec_config import render_secrets_file

        tunnel = MagicMock()
        tunnel.peer_ip = "203.0.113.1"
        tunnel.local_cidrs = ["10.0.0.0/24"]
        tunnel.remote_id = None
        tunnel.local_id = None

        content = render_secrets_file(tunnel, "MySecretPSK")
        assert '203.0.113.1 10.0.0.0 : PSK "MySecretPSK"' in content

    @patch("app.services.ipsec_config.sftp_push_on_all_servers", new_callable=AsyncMock)
    async def test_sync_tunnel_config(self, mock_fan_out):
        from app.services.ipsec_config import sync_tunnel_config
        from app.utils.fan_out import FanOutResult, ServerResult

        mock_fan_out.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        tunnel = MagicMock()
        tunnel.name = "test-tunnel"
        tunnel.ike_version = "2"
        tunnel.local_cidrs = ["10.0.0.0/24"]
        tunnel.peer_ip = "1.2.3.4"
        tunnel.remote_cidrs = ["192.168.0.0/24"]
        tunnel.ike_proposals = None
        tunnel.esp_proposals = None
        tunnel.dpd_action = "restart"
        tunnel.dpd_delay = 30
        tunnel.dpd_timeout = 150

        session = AsyncMock()
        result = await sync_tunnel_config(tunnel, psk="TestPSK123", session=session)

        mock_fan_out.assert_called_once()
        assert result.is_success is True

        # Verify fan-out received both conf and secrets content
        call_kwargs = mock_fan_out.call_args
        assert call_kwargs[0][1] == "test-tunnel"  # tunnel name

    @patch("app.services.ipsec_config.sftp_delete_on_all_servers", new_callable=AsyncMock)
    async def test_remove_tunnel_config(self, mock_fan_out):
        from app.services.ipsec_config import remove_tunnel_config
        from app.utils.fan_out import FanOutResult, ServerResult

        mock_fan_out.return_value = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )

        session = AsyncMock()
        result = await remove_tunnel_config("old-tunnel", session=session)

        mock_fan_out.assert_called_once()
        assert result.is_success is True


# ---------------------------------------------------------------------------
# Terragrunt service (file operations only — git/terragrunt mocked)
# ---------------------------------------------------------------------------


class TestTerragruntFileOps:
    def test_read_routes_file(self, tmp_path):
        from app.services.terragrunt import _read_routes_file

        routes_file = tmp_path / "vpn_routes.json"
        routes_file.write_text(json.dumps(["10.0.0.0/8", "172.16.0.0/12"]))

        cidrs = _read_routes_file(routes_file)
        assert cidrs == ["10.0.0.0/8", "172.16.0.0/12"]

    def test_read_routes_file_missing(self, tmp_path):
        from app.services.terragrunt import _read_routes_file

        missing = tmp_path / "nonexistent.json"
        cidrs = _read_routes_file(missing)
        assert cidrs == []

    def test_write_routes_file_sorted(self, tmp_path):
        from app.services.terragrunt import _write_routes_file

        routes_file = tmp_path / "vpn_routes.json"
        _write_routes_file(routes_file, ["172.16.0.0/12", "10.0.0.0/8", "192.168.0.0/16"])

        data = json.loads(routes_file.read_text())
        assert data == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

    def test_write_routes_file_deduplication(self, tmp_path):
        from app.services.terragrunt import _read_routes_file, _write_routes_file

        routes_file = tmp_path / "vpn_routes.json"
        # Write then read back
        _write_routes_file(routes_file, ["10.0.0.0/8", "10.0.0.0/8"])
        cidrs = _read_routes_file(routes_file)
        # sorted() preserves dupes — but add_route checks before appending
        assert len(cidrs) == 2  # _write_routes_file doesn't dedupe, add_route does

    def test_authenticated_url(self):
        from app.services.terragrunt import _authenticated_url

        with patch("app.services.terragrunt.get_settings") as mock_settings:
            settings = MagicMock()
            settings.github_repo_url = "https://github.com/org/repo.git"
            settings.github_token = "ghp_abc123"
            mock_settings.return_value = settings

            url = _authenticated_url()
            assert url == "https://ghp_abc123@github.com/org/repo.git"



# ---------------------------------------------------------------------------
# Tunnel service — create_tunnel and update_tunnel field handling
# ---------------------------------------------------------------------------


class TestTunnelServiceCreateFields:
    """Verify create_tunnel passes local_id and ike_lifetime to the Tunnel constructor."""

    @patch("app.services.tunnel_service.audit")
    @patch("app.services.tunnel_service.ipsec_config")
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    async def test_create_tunnel_passes_local_id_and_ike_lifetime(
        self, mock_lock, mock_encrypt, mock_ipsec, mock_audit
    ):
        from ipaddress import IPv4Address, IPv4Network

        from app.schemas.tunnel import TunnelCreate
        from app.services.tunnel_service import create_tunnel
        from app.utils.fan_out import FanOutResult, ServerResult

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        mock_encrypt.return_value = "encrypted_psk"
        fan_out = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )
        mock_ipsec.sync_tunnel_config = AsyncMock(return_value=fan_out)
        mock_audit.log_action = AsyncMock()

        user = MagicMock()
        user.id = 1

        data = TunnelCreate(
            name="t1",
            peer_ip=IPv4Address("10.0.0.1"),
            local_cidrs=[IPv4Network("192.168.0.0/24")],
            remote_cidrs=[IPv4Network("10.100.0.0/24")],
            psk="secret",
            local_id="eip-203.0.113.5",
            ike_lifetime=28800,
        )

        await create_tunnel(session, data=data, user=user)

        # The Tunnel instance is captured from session.add()
        assert session.add.called
        tunnel_obj = session.add.call_args[0][0]
        assert tunnel_obj.local_id == "eip-203.0.113.5"
        assert tunnel_obj.ike_lifetime == 28800

    @patch("app.services.tunnel_service.audit")
    @patch("app.services.tunnel_service.ipsec_config")
    @patch("app.services.kms.encrypt_psk", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    async def test_create_tunnel_defaults_local_id_none_ike_lifetime_86400(
        self, mock_lock, mock_encrypt, mock_ipsec, mock_audit
    ):
        """When local_id and ike_lifetime are omitted, schema defaults are forwarded."""
        from ipaddress import IPv4Address, IPv4Network

        from app.schemas.tunnel import TunnelCreate
        from app.services.tunnel_service import create_tunnel
        from app.utils.fan_out import FanOutResult, ServerResult

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute.return_value = mock_result

        mock_encrypt.return_value = "enc"
        fan_out = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )
        mock_ipsec.sync_tunnel_config = AsyncMock(return_value=fan_out)
        mock_audit.log_action = AsyncMock()

        user = MagicMock()
        user.id = 1

        data = TunnelCreate(
            name="t2",
            peer_ip=IPv4Address("10.0.0.2"),
            local_cidrs=[IPv4Network("192.168.0.0/24")],
            remote_cidrs=[IPv4Network("10.100.0.0/24")],
            psk="secret",
        )

        await create_tunnel(session, data=data, user=user)

        assert session.add.called
        tunnel_obj = session.add.call_args[0][0]
        assert tunnel_obj.local_id is None
        assert tunnel_obj.ike_lifetime == 86400


class TestTunnelServiceUpdateFields:
    """Verify update_tunnel handles local_id and ike_lifetime correctly."""

    def _make_tunnel(self, local_id=None, ike_lifetime=86400):
        tunnel = MagicMock()
        tunnel.id = 1
        tunnel.name = "existing"
        tunnel.local_id = local_id
        tunnel.ike_lifetime = ike_lifetime
        tunnel.psk_encrypted = "enc"
        tunnel.sync_status = "synced"
        return tunnel

    @patch("app.services.tunnel_service.audit")
    @patch("app.services.tunnel_service.ipsec_config")
    @patch("app.services.kms.decrypt_psk", new_callable=AsyncMock)
    @patch("app.services.ipsec_config.sftp_push_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_update_tunnel_sets_local_id(
        self, mock_get, mock_lock, mock_sftp, mock_decrypt, mock_ipsec, mock_audit
    ):
        from app.schemas.tunnel import TunnelUpdate
        from app.services.tunnel_service import update_tunnel
        from app.utils.fan_out import FanOutResult, ServerResult

        tunnel = self._make_tunnel()
        mock_get.return_value = tunnel

        mock_decrypt.return_value = "plain_psk"
        fan_out = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )
        mock_sftp.return_value = fan_out
        mock_ipsec.render_connection_conf = MagicMock(return_value="conf")
        mock_ipsec.sync_tunnel_config = AsyncMock(return_value=fan_out)
        mock_audit.log_action = AsyncMock()

        session = AsyncMock()
        session.execute.return_value = MagicMock()
        user = MagicMock()
        user.id = 1

        data = TunnelUpdate(local_id="203.0.113.99")
        await update_tunnel(session, 1, data=data, user=user)

        assert tunnel.local_id == "203.0.113.99"

    @patch("app.services.tunnel_service.audit")
    @patch("app.services.tunnel_service.ipsec_config")
    @patch("app.services.kms.decrypt_psk", new_callable=AsyncMock)
    @patch("app.services.ipsec_config.sftp_push_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_update_tunnel_ike_lifetime_none_not_overwritten(
        self, mock_get, mock_lock, mock_sftp, mock_decrypt, mock_ipsec, mock_audit
    ):
        """Sending ike_lifetime=null must not overwrite the existing value with NULL."""
        from app.schemas.tunnel import TunnelUpdate
        from app.services.tunnel_service import update_tunnel
        from app.utils.fan_out import FanOutResult, ServerResult

        tunnel = self._make_tunnel(ike_lifetime=3600)
        mock_get.return_value = tunnel

        mock_decrypt.return_value = "plain_psk"
        fan_out = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )
        mock_sftp.return_value = fan_out
        mock_ipsec.render_connection_conf = MagicMock(return_value="conf")
        mock_ipsec.sync_tunnel_config = AsyncMock(return_value=fan_out)
        mock_audit.log_action = AsyncMock()

        session = AsyncMock()
        session.execute.return_value = MagicMock()
        user = MagicMock()
        user.id = 1

        data = TunnelUpdate(ike_lifetime=None)
        await update_tunnel(session, 1, data=data, user=user)

        assert tunnel.ike_lifetime == 3600

    @patch("app.services.tunnel_service.audit")
    @patch("app.services.tunnel_service.ipsec_config")
    @patch("app.services.kms.decrypt_psk", new_callable=AsyncMock)
    @patch("app.services.ipsec_config.sftp_push_on_all_servers", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.require_lock", new_callable=AsyncMock)
    @patch("app.services.tunnel_service.get_tunnel", new_callable=AsyncMock)
    async def test_update_tunnel_ike_lifetime_valid_value_updated(
        self, mock_get, mock_lock, mock_sftp, mock_decrypt, mock_ipsec, mock_audit
    ):
        from app.schemas.tunnel import TunnelUpdate
        from app.services.tunnel_service import update_tunnel
        from app.utils.fan_out import FanOutResult, ServerResult

        tunnel = self._make_tunnel(ike_lifetime=86400)
        mock_get.return_value = tunnel

        mock_decrypt.return_value = "plain_psk"
        fan_out = FanOutResult(
            total=1, succeeded=1, failed=0,
            servers=[ServerResult(server_id=1, server_name="vpn-1", success=True, output="ok")],
        )
        mock_sftp.return_value = fan_out
        mock_ipsec.render_connection_conf = MagicMock(return_value="conf")
        mock_ipsec.sync_tunnel_config = AsyncMock(return_value=fan_out)
        mock_audit.log_action = AsyncMock()

        session = AsyncMock()
        session.execute.return_value = MagicMock()
        user = MagicMock()
        user.id = 1

        data = TunnelUpdate(ike_lifetime=7200)
        await update_tunnel(session, 1, data=data, user=user)

        assert tunnel.ike_lifetime == 7200


# ---------------------------------------------------------------------------
# get_all_tunnels_live_status
# ---------------------------------------------------------------------------


class TestGetAllTunnelsLiveStatus:
    """Unit tests for the bulk live status service function."""

    def _make_tunnel(self, tunnel_id: int, name: str):
        t = MagicMock()
        t.id = tunnel_id
        t.name = name
        t.deleted_at = None
        return t

    def _mock_scalars(self, values):
        scalars = MagicMock()
        scalars.all.return_value = values
        result = MagicMock()
        result.scalars.return_value = scalars
        return result

    @patch("app.services.tunnel_service._status_fan_out", new_callable=AsyncMock)
    async def test_maps_states_per_tunnel(self, mock_fan_out):
        from app.services.tunnel_service import get_all_tunnels_live_status
        from app.utils.fan_out import ServerResult

        t1 = self._make_tunnel(1, "tunnel-one")
        t2 = self._make_tunnel(2, "tunnel-two")

        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([t1, t2])

        output = "tunnel-one[1]: ESTABLISHED\n"
        mock_fan_out.return_value = [
            (ServerResult(server_id=1, server_name="vpn-1", success=True, output=output), "stroke"),
        ]

        data = await get_all_tunnels_live_status(session)

        assert len(data["tunnels"]) == 2
        rows = {r["name"]: r for r in data["tunnels"]}
        assert rows["tunnel-one"]["overall"] == "UP"
        assert rows["tunnel-two"]["overall"] == "DOWN"
        assert data["server_errors"] == {}
        assert data["summary"]["total"] == 2
        assert data["summary"]["up"] == 1
        assert data["summary"]["down"] == 1

    @patch("app.services.tunnel_service._status_fan_out", new_callable=AsyncMock)
    async def test_server_error_marks_tunnels_unknown(self, mock_fan_out):
        from app.services.tunnel_service import get_all_tunnels_live_status
        from app.utils.fan_out import ServerResult

        t1 = self._make_tunnel(1, "tunnel-one")

        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([t1])

        mock_fan_out.return_value = [
            (ServerResult(server_id=1, server_name="vpn-1", success=False, error="connection refused"), "stroke"),
        ]

        data = await get_all_tunnels_live_status(session)

        assert data["tunnels"][0]["overall"] == "UNKNOWN"
        assert 1 in data["server_errors"]
        assert "connection refused" in data["server_errors"][1]

    async def test_no_tunnels_returns_empty(self):
        from app.services.tunnel_service import get_all_tunnels_live_status

        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([])

        data = await get_all_tunnels_live_status(session)

        assert data["tunnels"] == []
        assert data["summary"]["total"] == 0
        assert data["server_errors"] == {}

    @patch(
        "app.services.tunnel_service._status_fan_out",
        new_callable=AsyncMock,
        side_effect=InfrastructureError("servers", "No active servers registered"),
    )
    async def test_no_servers_returns_all_unknown(self, mock_fan_out):
        from app.services.tunnel_service import get_all_tunnels_live_status

        t1 = self._make_tunnel(1, "tunnel-one")
        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([t1])

        data = await get_all_tunnels_live_status(session)

        assert data["tunnels"][0]["overall"] == "UNKNOWN"
        assert data["summary"]["unknown"] == 1

    @patch("app.services.tunnel_service._status_fan_out", new_callable=AsyncMock)
    async def test_swanctl_server_parsed_correctly(self, mock_fan_out):
        """swanctl output for an active tunnel is correctly parsed as UP."""
        from app.services.tunnel_service import get_all_tunnels_live_status
        from app.utils.fan_out import ServerResult

        SWANCTL_REAL_OUTPUT = (
            "daniel-local-test: #594, ESTABLISHED, IKEv2, abc def\n"
            "  local  '44.215.155.152' @ 10.0.1.200[4500]\n"
            "  remote '90.74.94.33' @ 90.74.94.33[58212]\n"
            "  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048\n"
            "  established 11507s ago, rekeying in 17160s\n"
            "  daniel-local-test: #12, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_CBC-256/HMAC_SHA2_256_128\n"
            "    installed 1491s ago, rekeying in 1879s, expires in 2469s\n"
        )

        t1 = self._make_tunnel(1, "daniel-local-test")
        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([t1])

        mock_fan_out.return_value = [
            (ServerResult(server_id=1, server_name="vpn-swanctl", success=True, output=SWANCTL_REAL_OUTPUT), "swanctl"),
        ]

        data = await get_all_tunnels_live_status(session)

        assert data["tunnels"][0]["overall"] == "UP"

    @patch("app.services.tunnel_service._status_fan_out", new_callable=AsyncMock)
    async def test_mixed_fleet_stroke_up_swanctl_up(self, mock_fan_out):
        """Mixed fleet: one stroke server, one swanctl server, both show UP → overall UP."""
        from app.services.tunnel_service import get_all_tunnels_live_status
        from app.utils.fan_out import ServerResult

        STROKE_OUTPUT = "my-tunnel[1]: ESTABLISHED\n"
        SWANCTL_OUTPUT = (
            "my-tunnel: #1, ESTABLISHED, IKEv2, abc def\n"
            "  my-tunnel: #1, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_CBC-256\n"
        )

        t1 = self._make_tunnel(1, "my-tunnel")
        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([t1])

        mock_fan_out.return_value = [
            (ServerResult(server_id=1, server_name="vpn-stroke", success=True, output=STROKE_OUTPUT), "stroke"),
            (ServerResult(server_id=2, server_name="vpn-swanctl", success=True, output=SWANCTL_OUTPUT), "swanctl"),
        ]

        data = await get_all_tunnels_live_status(session)

        assert data["tunnels"][0]["overall"] == "UP"
        assert data["summary"]["up"] == 1


# ---------------------------------------------------------------------------
# _parse_swanctl_tunnel_state
# ---------------------------------------------------------------------------


class TestParseSwanctlTunnelState:
    """Unit tests for the swanctl output parser."""

    REAL_OUTPUT = (
        "daniel-local-test: #594, ESTABLISHED, IKEv2, abc def\n"
        "  local  '44.215.155.152' @ 10.0.1.200[4500]\n"
        "  remote '90.74.94.33' @ 90.74.94.33[58212]\n"
        "  AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048\n"
        "  established 11507s ago, rekeying in 17160s\n"
        "  daniel-local-test: #12, reqid 1, INSTALLED, TUNNEL-in-UDP, ESP:AES_CBC-256/HMAC_SHA2_256_128\n"
        "    installed 1491s ago, rekeying in 1879s, expires in 2469s\n"
        "    in  c92b2e85,      0 bytes,     0 packets\n"
        "    out c68141e3,      0 bytes,     0 packets\n"
        "    local  10.0.0.0/16\n"
        "    remote 172.16.99.1/32\n"
    )

    def test_real_output_established_plus_installed_is_up(self):
        from app.services.tunnel_service import _parse_swanctl_tunnel_state

        assert _parse_swanctl_tunnel_state("daniel-local-test", self.REAL_OUTPUT) == "UP"

    def test_real_output_unknown_tunnel_is_down(self):
        from app.services.tunnel_service import _parse_swanctl_tunnel_state

        assert _parse_swanctl_tunnel_state("other-tunnel", self.REAL_OUTPUT) == "DOWN"

    def test_empty_output_is_unknown(self):
        from app.services.tunnel_service import _parse_swanctl_tunnel_state

        assert _parse_swanctl_tunnel_state("any-tunnel", "") == "UNKNOWN"

    def test_ike_established_but_no_child_installed_is_down(self):
        from app.services.tunnel_service import _parse_swanctl_tunnel_state

        output = (
            "my-tunnel: #1, ESTABLISHED, IKEv2, abc def\n"
            "  my-tunnel: #1, reqid 1, ROUTED, TUNNEL\n"
        )
        assert _parse_swanctl_tunnel_state("my-tunnel", output) == "DOWN"

    def test_tunnel_absent_from_output_is_down(self):
        from app.services.tunnel_service import _parse_swanctl_tunnel_state

        output = (
            "other-conn: #1, ESTABLISHED, IKEv2, abc\n"
            "  other-conn: #1, reqid 1, INSTALLED, TUNNEL-in-UDP\n"
        )
        assert _parse_swanctl_tunnel_state("my-tunnel", output) == "DOWN"


# ---------------------------------------------------------------------------
# _status_fan_out engine dispatch
# ---------------------------------------------------------------------------


class TestStatusFanOutEngineDispatch:
    """Verify _status_fan_out sends the right command to each engine type."""

    def _make_server(self, server_id: int, name: str, engine: str):
        s = MagicMock()
        s.id = server_id
        s.name = name
        s.ipsec_engine = engine
        s.is_active = True
        s.deleted_at = None
        return s

    def _mock_scalars(self, values):
        scalars = MagicMock()
        scalars.all.return_value = values
        result = MagicMock()
        result.scalars.return_value = scalars
        return result

    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    async def test_stroke_server_receives_ipsec_statusall(self, mock_exec):
        from app.services.tunnel_service import _status_fan_out
        from app.utils.fan_out import ServerResult

        stroke_srv = self._make_server(1, "vpn-stroke", "stroke")
        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([stroke_srv])
        mock_exec.return_value = ServerResult(server_id=1, server_name="vpn-stroke", success=True, output="")

        await _status_fan_out(session)

        mock_exec.assert_called_once()
        _, _, commands = mock_exec.call_args.args
        assert commands == ["sudo /usr/sbin/ipsec statusall"]

    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    async def test_swanctl_server_receives_swanctl_list_sas(self, mock_exec):
        from app.services.tunnel_service import _status_fan_out
        from app.utils.fan_out import ServerResult

        swanctl_srv = self._make_server(2, "vpn-swanctl", "swanctl")
        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([swanctl_srv])
        mock_exec.return_value = ServerResult(server_id=2, server_name="vpn-swanctl", success=True, output="")

        await _status_fan_out(session)

        mock_exec.assert_called_once()
        _, _, commands = mock_exec.call_args.args
        assert commands == ["sudo swanctl --list-sas 2>/dev/null"]

    @patch("app.services.tunnel_service.execute_command", new_callable=AsyncMock)
    async def test_mixed_fleet_each_server_gets_own_command(self, mock_exec):
        from app.services.tunnel_service import _status_fan_out
        from app.utils.fan_out import ServerResult

        stroke_srv = self._make_server(1, "vpn-stroke", "stroke")
        swanctl_srv = self._make_server(2, "vpn-swanctl", "swanctl")
        session = AsyncMock()
        session.execute.return_value = self._mock_scalars([stroke_srv, swanctl_srv])
        mock_exec.side_effect = [
            ServerResult(server_id=1, server_name="vpn-stroke", success=True, output=""),
            ServerResult(server_id=2, server_name="vpn-swanctl", success=True, output=""),
        ]

        pairs = await _status_fan_out(session)

        assert len(pairs) == 2
        calls = mock_exec.call_args_list
        assert calls[0].args[2] == ["sudo /usr/sbin/ipsec statusall"]
        assert calls[1].args[2] == ["sudo swanctl --list-sas 2>/dev/null"]
        assert pairs[0][1] == "stroke"
        assert pairs[1][1] == "swanctl"
