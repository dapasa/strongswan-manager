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
# S3 service
# ---------------------------------------------------------------------------


class TestS3Service:
    @patch("app.services.s3._get_s3_client")
    @patch("app.services.s3.get_settings")
    async def test_download_ipsec_conf_success(self, mock_settings, mock_client_fn):
        from app.services.s3 import download_ipsec_conf

        settings = MagicMock()
        settings.s3_bucket = "test-bucket"
        settings.s3_ipsec_key = "ipsec.conf"
        mock_settings.return_value = settings

        body_mock = MagicMock()
        body_mock.read.return_value = b"conn test\n    left=%defaultroute\n"
        mock_client = MagicMock()
        mock_client.get_object.return_value = {"Body": body_mock}
        mock_client_fn.return_value = mock_client

        content = await download_ipsec_conf()
        assert "conn test" in content
        mock_client.get_object.assert_called_once_with(Bucket="test-bucket", Key="ipsec.conf")

    @patch("app.services.s3._get_s3_client")
    @patch("app.services.s3.get_settings")
    async def test_download_ipsec_conf_no_such_key(self, mock_settings, mock_client_fn):
        from app.services.s3 import download_ipsec_conf

        settings = MagicMock()
        settings.s3_bucket = "test-bucket"
        settings.s3_ipsec_key = "ipsec.conf"
        mock_settings.return_value = settings

        error_response = {"Error": {"Code": "NoSuchKey", "Message": "Not found"}}
        mock_client = MagicMock()
        mock_client.get_object.side_effect = ClientError(error_response, "GetObject")
        mock_client_fn.return_value = mock_client

        with pytest.raises(InfrastructureError) as exc_info:
            await download_ipsec_conf()
        assert "not found" in exc_info.value.message.lower()

    @patch("app.services.s3._get_s3_client")
    @patch("app.services.s3.get_settings")
    async def test_upload_ipsec_conf_success(self, mock_settings, mock_client_fn):
        from app.services.s3 import upload_ipsec_conf

        settings = MagicMock()
        settings.s3_bucket = "test-bucket"
        settings.s3_ipsec_key = "ipsec.conf"
        mock_settings.return_value = settings

        mock_client = MagicMock()
        mock_client_fn.return_value = mock_client

        await upload_ipsec_conf("conn test\n")
        mock_client.put_object.assert_called_once()
        call_kwargs = mock_client.put_object.call_args[1]
        assert call_kwargs["Bucket"] == "test-bucket"
        assert call_kwargs["Key"] == "ipsec.conf"

    @patch("app.services.s3._get_s3_client")
    @patch("app.services.s3.get_settings")
    async def test_upload_ipsec_conf_failure(self, mock_settings, mock_client_fn):
        from app.services.s3 import upload_ipsec_conf

        settings = MagicMock()
        settings.s3_bucket = "test-bucket"
        settings.s3_ipsec_key = "ipsec.conf"
        mock_settings.return_value = settings

        error_response = {"Error": {"Code": "AccessDenied", "Message": "Denied"}}
        mock_client = MagicMock()
        mock_client.put_object.side_effect = ClientError(error_response, "PutObject")
        mock_client_fn.return_value = mock_client

        with pytest.raises(InfrastructureError) as exc_info:
            await upload_ipsec_conf("content")
        assert exc_info.value.service == "S3"


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
        mock_run.assert_called_once_with(commands=["ipsec reload"], target="both")

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
    async def test_generate_empty_config(self):
        from app.services.ipsec_config import generate_ipsec_conf

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute.return_value = mock_result

        content = await generate_ipsec_conf(session)
        assert "AUTO-GENERATED" in content
        assert "config setup" in content
        assert "conn " not in content

    async def test_generate_with_tunnels(self):
        from app.services.ipsec_config import generate_ipsec_conf

        tunnel = MagicMock()
        tunnel.name = "prod-tunnel"
        tunnel.ike_version = "2"
        tunnel.local_cidrs = ["10.0.0.0/24", "10.0.1.0/24"]
        tunnel.peer_ip = "203.0.113.1"
        tunnel.remote_cidrs = ["192.168.1.0/24"]
        tunnel.dpd_action = "restart"
        tunnel.dpd_delay = 30
        tunnel.dpd_timeout = 150

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [tunnel]
        session.execute.return_value = mock_result

        content = await generate_ipsec_conf(session)
        assert "conn prod-tunnel" in content
        assert "keyexchange=ikev2" in content
        assert "left=%defaultroute" in content
        assert "leftsubnet=10.0.0.0/24,10.0.1.0/24" in content
        assert "right=203.0.113.1" in content
        assert "rightsubnet=192.168.1.0/24" in content
        assert "dpdaction=restart" in content

    async def test_generate_multiple_tunnels(self):
        from app.services.ipsec_config import generate_ipsec_conf

        tunnels = []
        for i, name in enumerate(["alpha", "beta"]):
            t = MagicMock()
            t.name = name
            t.ike_version = "2"
            t.local_cidrs = [f"10.{i}.0.0/24"]
            t.peer_ip = f"203.0.113.{i + 1}"
            t.remote_cidrs = [f"192.168.{i}.0/24"]
            t.dpd_action = "restart"
            t.dpd_delay = 30
            t.dpd_timeout = 150
            tunnels.append(t)

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = tunnels
        session.execute.return_value = mock_result

        content = await generate_ipsec_conf(session)
        assert "conn alpha" in content
        assert "conn beta" in content

    @patch("app.services.ipsec_config.ssm.reload_ipsec", new_callable=AsyncMock)
    @patch("app.services.ipsec_config.s3.upload_ipsec_conf", new_callable=AsyncMock)
    async def test_sync_ipsec_config(self, mock_upload, mock_reload):
        from app.services.ipsec_config import sync_ipsec_config

        session = AsyncMock()
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = []
        session.execute.return_value = mock_result

        await sync_ipsec_config(session)

        mock_upload.assert_called_once()
        mock_reload.assert_called_once()
        # Verify the uploaded content is valid
        uploaded_content = mock_upload.call_args[0][0]
        assert "AUTO-GENERATED" in uploaded_content


# ---------------------------------------------------------------------------
# Terragrunt service (file operations only — git/terragrunt mocked)
# ---------------------------------------------------------------------------


class TestTerragruntFileOps:
    def test_read_routes_file(self, tmp_path):
        from app.services.terragrunt import _read_routes_file

        routes_file = tmp_path / "vpn_routes.json"
        routes_file.write_text(json.dumps({"cidrs": ["10.0.0.0/8", "172.16.0.0/12"]}))

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
        assert data["cidrs"] == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

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
