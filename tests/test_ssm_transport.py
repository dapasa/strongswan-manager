"""Tests for SsmTransport (Phase 3).

Mocks boto3 at the get_client_for_server boundary so no real AWS calls are made.
Covers:
- execute: happy path, InProgress -> Success poll, TimedOut, Failed, permission denied
- write_file: happy path, size limit exceeded
- delete_file / rename_file: basic delegation to _send_and_poll
- check_reachable: found, not found (unreachable), API timeout, ClientError
- Error mapping: InvalidInstanceId -> NODE_UNREACHABLE, AccessDeniedException -> PERMISSION_DENIED
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from app.services.transport.base import CommandResult, TransportError, TransportErrorKind
from app.services.transport.ssm_transport import (
    SsmTransport,
    _MAX_POLL_ATTEMPTS,
    _SSM_COMMAND_MAX_CHARS,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_server(
    *,
    name: str = "test-server",
    ec2_instance_id: str | None = "i-0abc1234567890def",
    aws_role_arn: str | None = None,
    aws_region_override: str | None = None,
) -> MagicMock:
    """Return a mock Server with the given SSM fields."""
    srv = MagicMock()
    srv.name = name
    srv.ec2_instance_id = ec2_instance_id
    srv.aws_role_arn = aws_role_arn
    srv.aws_region_override = aws_region_override
    return srv


def _client_error(code: str, message: str = "error") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "TestOperation")


def _make_ssm_mock(
    command_id: str = "cmd-abc123",
    statuses: list[str] | None = None,
) -> MagicMock:
    """Return a mock SSM boto3 client.

    statuses: list of Status values returned by successive get_command_invocation
              calls. Defaults to ["Success"].
    """
    if statuses is None:
        statuses = ["Success"]

    mock_ssm = MagicMock()
    mock_ssm.send_command.return_value = {"Command": {"CommandId": command_id}}

    invocations = [
        {
            "Status": s,
            "StandardOutputContent": "stdout content" if s == "Success" else "",
            "StandardErrorContent": "stderr" if s in ("Failed", "TimedOut") else "",
        }
        for s in statuses
    ]
    mock_ssm.get_command_invocation.side_effect = invocations
    return mock_ssm


# ---------------------------------------------------------------------------
# SsmTransport construction
# ---------------------------------------------------------------------------

class TestSsmTransportValidation:
    def test_raises_when_no_instance_id(self):
        server = _make_server(ec2_instance_id=None)
        with pytest.raises(TransportError) as exc_info:
            SsmTransport(server)
        assert exc_info.value.kind == TransportErrorKind.UNKNOWN
        assert "ec2_instance_id" in str(exc_info.value)

    def test_ok_with_valid_instance_id(self):
        server = _make_server()
        transport = SsmTransport(server)
        assert transport is not None


# ---------------------------------------------------------------------------
# execute
# ---------------------------------------------------------------------------

class TestSsmTransportExecute:
    @pytest.mark.asyncio
    async def test_execute_happy_path(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock(statuses=["Success"])

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ):
            result = await transport.execute(["echo hello"])

        assert isinstance(result, CommandResult)
        assert result.exit_code == 0
        assert result.stdout == "stdout content"
        mock_ssm.send_command.assert_called_once()
        call_kwargs = mock_ssm.send_command.call_args[1]
        assert "echo hello" in call_kwargs["Parameters"]["commands"][0]

    @pytest.mark.asyncio
    async def test_execute_polls_through_inprogress(self):
        """Verifies polling loop: InProgress x2 then Success."""
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock(statuses=["InProgress", "InProgress", "Success"])

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            result = await transport.execute(["echo poll"])

        assert result.exit_code == 0
        assert mock_ssm.get_command_invocation.call_count == 3

    @pytest.mark.asyncio
    async def test_execute_timeout_status_raises(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock(statuses=["TimedOut"])

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock), pytest.raises(TransportError) as exc_info:
            await transport.execute(["sleep 999"])

        assert exc_info.value.kind == TransportErrorKind.TIMEOUT

    @pytest.mark.asyncio
    async def test_execute_failed_status_raises_command_failed(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock(statuses=["Failed"])

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock), pytest.raises(TransportError) as exc_info:
            await transport.execute(["bad command"])

        assert exc_info.value.kind == TransportErrorKind.COMMAND_FAILED

    @pytest.mark.asyncio
    async def test_execute_failed_with_permission_denied_in_stderr(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = MagicMock()
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-x"}}
        mock_ssm.get_command_invocation.return_value = {
            "Status": "Failed",
            "StandardOutputContent": "",
            "StandardErrorContent": "sudo: permission denied",
        }

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock), pytest.raises(TransportError) as exc_info:
            await transport.execute(["sudo restricted"])

        assert exc_info.value.kind == TransportErrorKind.PERMISSION_DENIED

    @pytest.mark.asyncio
    async def test_execute_poll_exhausted_raises_timeout(self):
        """All poll attempts return InProgress — should raise TIMEOUT."""
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock(statuses=["InProgress"] * (_MAX_POLL_ATTEMPTS + 5))

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock), pytest.raises(TransportError) as exc_info:
            await transport.execute(["noop"])

        assert exc_info.value.kind == TransportErrorKind.TIMEOUT

    @pytest.mark.asyncio
    async def test_execute_send_command_invalid_instance_id(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = MagicMock()
        mock_ssm.send_command.side_effect = _client_error("InvalidInstanceId")

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), pytest.raises(TransportError) as exc_info:
            await transport.execute(["echo"])

        assert exc_info.value.kind == TransportErrorKind.NODE_UNREACHABLE

    @pytest.mark.asyncio
    async def test_execute_send_command_access_denied(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = MagicMock()
        mock_ssm.send_command.side_effect = _client_error("AccessDeniedException")

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), pytest.raises(TransportError) as exc_info:
            await transport.execute(["echo"])

        assert exc_info.value.kind == TransportErrorKind.PERMISSION_DENIED

    @pytest.mark.asyncio
    async def test_execute_invocation_does_not_exist_keeps_polling(self):
        """InvocationDoesNotExist on first get_command_invocation, then Success."""
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = MagicMock()
        mock_ssm.send_command.return_value = {"Command": {"CommandId": "cmd-y"}}
        mock_ssm.get_command_invocation.side_effect = [
            _client_error("InvocationDoesNotExist"),
            {
                "Status": "Success",
                "StandardOutputContent": "ok",
                "StandardErrorContent": "",
            },
        ]

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            result = await transport.execute(["echo ok"])

        assert result.exit_code == 0
        assert mock_ssm.get_command_invocation.call_count == 2

    @pytest.mark.asyncio
    async def test_execute_joins_multiple_commands_with_and(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock()

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            await transport.execute(["cmd1", "cmd2", "cmd3"])

        sent = mock_ssm.send_command.call_args[1]["Parameters"]["commands"][0]
        assert sent == "cmd1 && cmd2 && cmd3"


# ---------------------------------------------------------------------------
# write_file
# ---------------------------------------------------------------------------

class TestSsmTransportWriteFile:
    @pytest.mark.asyncio
    async def test_write_file_happy_path(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock()

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            await transport.write_file("/etc/test.conf", "content here", mode="600")

        sent_cmd = mock_ssm.send_command.call_args[1]["Parameters"]["commands"][0]
        assert "base64 -d" in sent_cmd
        assert "sudo tee /etc/test.conf" in sent_cmd
        assert "sudo mkdir -p /etc" in sent_cmd
        assert "sudo chmod 600 /etc/test.conf" in sent_cmd

    @pytest.mark.asyncio
    async def test_write_file_no_mkdir_when_make_dirs_false(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock()

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            await transport.write_file("/tmp/x", "data", make_dirs=False)

        sent_cmd = mock_ssm.send_command.call_args[1]["Parameters"]["commands"][0]
        assert "mkdir" not in sent_cmd

    def test_write_file_raises_on_oversized_content(self):
        """Content that produces a command > _SSM_COMMAND_MAX_CHARS raises immediately."""
        server = _make_server()
        transport = SsmTransport(server)
        # Each byte of content becomes ~1.33 chars in base64;
        # to exceed 4096 chars we need at least ~3072 bytes of content,
        # but the command scaffold adds overhead. Use a large string.
        oversized_content = "x" * 4096  # this will produce a command >> 4096 chars

        with pytest.raises(TransportError) as exc_info:
            # write_file raises before any async call, so no loop needed
            import asyncio
            asyncio.get_event_loop().run_until_complete(
                transport.write_file("/etc/big.conf", oversized_content)
            )

        err = exc_info.value
        assert err.kind == TransportErrorKind.COMMAND_FAILED
        assert "too large" in str(err).lower() or "too large" in err.message.lower()

    def test_write_file_size_check_gives_max_bytes_hint(self):
        """Error message mentions maximum original content size."""
        server = _make_server()
        transport = SsmTransport(server)
        huge = "y" * 8192

        with pytest.raises(TransportError) as exc_info:
            asyncio.get_event_loop().run_until_complete(
                transport.write_file("/path/f", huge)
            )

        assert "bytes" in exc_info.value.message


# ---------------------------------------------------------------------------
# delete_file / rename_file
# ---------------------------------------------------------------------------

class TestSsmTransportDeleteRename:
    @pytest.mark.asyncio
    async def test_delete_file(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock()

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            await transport.delete_file("/etc/old.conf")

        sent = mock_ssm.send_command.call_args[1]["Parameters"]["commands"][0]
        assert "sudo rm -f /etc/old.conf" == sent

    @pytest.mark.asyncio
    async def test_rename_file(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = _make_ssm_mock()

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch("asyncio.sleep", new_callable=AsyncMock):
            await transport.rename_file("/etc/a.conf", "/etc/b.conf")

        sent = mock_ssm.send_command.call_args[1]["Parameters"]["commands"][0]
        assert "sudo mv /etc/a.conf /etc/b.conf" == sent


# ---------------------------------------------------------------------------
# check_reachable
# ---------------------------------------------------------------------------

class TestSsmTransportCheckReachable:
    @pytest.mark.asyncio
    async def test_reachable_when_instance_found(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = MagicMock()
        mock_ssm.describe_instance_information.return_value = {
            "InstanceInformationList": [{"InstanceId": "i-0abc1234567890def", "PingStatus": "Online"}]
        }

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ):
            result = await transport.check_reachable()

        assert result is True

    @pytest.mark.asyncio
    async def test_unreachable_when_instance_not_found(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = MagicMock()
        mock_ssm.describe_instance_information.return_value = {"InstanceInformationList": []}

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), pytest.raises(TransportError) as exc_info:
            await transport.check_reachable()

        assert exc_info.value.kind == TransportErrorKind.NODE_UNREACHABLE

    @pytest.mark.asyncio
    async def test_check_reachable_client_error_maps_correctly(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = MagicMock()
        mock_ssm.describe_instance_information.side_effect = _client_error("InvalidInstanceId")

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), pytest.raises(TransportError) as exc_info:
            await transport.check_reachable()

        assert exc_info.value.kind == TransportErrorKind.NODE_UNREACHABLE

    @pytest.mark.asyncio
    async def test_check_reachable_timeout(self):
        server = _make_server()
        transport = SsmTransport(server)
        mock_ssm = MagicMock()

        async def slow_describe():
            await asyncio.sleep(100)

        mock_ssm.describe_instance_information.side_effect = lambda **_: (_ for _ in ()).throw(
            asyncio.TimeoutError
        )

        with patch(
            "app.services.transport.ssm_transport.get_client_for_server",
            return_value=mock_ssm,
        ), patch(
            "asyncio.wait_for",
            side_effect=asyncio.TimeoutError,
        ), pytest.raises(TransportError) as exc_info:
            await transport.check_reachable(timeout=1)

        assert exc_info.value.kind == TransportErrorKind.TIMEOUT


# ---------------------------------------------------------------------------
# factory integration
# ---------------------------------------------------------------------------

class TestFactoryReturnsSSMTransport:
    def test_get_transport_ssm(self):
        from app.services.transport.factory import get_transport

        server = _make_server()
        server.connection_type = "ssm"

        transport = get_transport(server)
        assert isinstance(transport, SsmTransport)

    def test_get_transport_ssh_unchanged(self):
        from app.services.transport.factory import get_transport
        from app.services.transport.ssh_transport import SshTransport

        server = MagicMock()
        server.connection_type = "ssh"
        server.hostname = "10.0.0.1"
        server.ssh_private_key_encrypted = "encrypted_key"
        server.ssh_port = 22
        server.ssh_user = "admin"

        transport = get_transport(server)
        assert isinstance(transport, SshTransport)
