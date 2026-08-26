"""SSM transport implementation using AWS Systems Manager Run Command.

This module is the only place in the transport layer that imports boto3/botocore.
All AWS-specific exceptions are caught here and re-raised as TransportError so
callers never need to depend on botocore.

write_file constraint: SSM Run Command does not support stdin piping, so content
is base64-encoded and embedded inline:
  printf '%s' '<B64>' | base64 -d | sudo tee <path> > /dev/null
Each command string in the SSM Parameters map is limited to
_SSM_COMMAND_MAX_CHARS characters. If the content would exceed this limit,
write_file raises TransportError immediately with a clear size message.
"""

from __future__ import annotations

import asyncio
import base64
import posixpath
from typing import TYPE_CHECKING

from botocore.exceptions import ClientError

from app.logging_config import get_logger
from app.services.aws_client import get_client_for_server

from .base import CommandResult, NodeTransport, TransportError, TransportErrorKind

if TYPE_CHECKING:
    from app.db.models import Server

logger = get_logger(__name__)

# SSM Run Command polling
_POLL_INTERVAL_SECONDS: float = 2.0
_MAX_POLL_ATTEMPTS: int = 30

# Maximum characters allowed per command string in SSM Parameters
_SSM_COMMAND_MAX_CHARS: int = 4096

# SSM document that executes shell scripts
_SSM_DOCUMENT: str = "AWS-RunShellScript"

# Default execution timeout sent to SSM (seconds)
_DEFAULT_TIMEOUT: int = 60


class SsmTransport(NodeTransport):
    """NodeTransport implementation that uses AWS SSM Run Command.

    Requires the EC2 instance to have the SSM agent installed and registered,
    plus the IAM role permissions for ssm:SendCommand and ssm:GetCommandInvocation.

    No SSH credentials are used or needed.

    Args:
        server: Server ORM instance. ec2_instance_id must not be None.
    """

    def __init__(self, server: Server) -> None:
        self._server = server
        self._validate()

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        """Raise TransportError immediately if required SSM fields are missing."""
        srv = self._server
        if not srv.ec2_instance_id:
            raise TransportError(
                f"Server {srv.name!r} has no ec2_instance_id configured — cannot use SSM transport",
                kind=TransportErrorKind.UNKNOWN,
            )

    # ------------------------------------------------------------------
    # AWS client access
    # ------------------------------------------------------------------

    def _ssm_client(self):  # noqa: ANN202
        """Return a boto3 SSM client scoped to this server's role/region."""
        return get_client_for_server(self._server, "ssm")

    # ------------------------------------------------------------------
    # Error mapping
    # ------------------------------------------------------------------

    @staticmethod
    def _map_client_error(exc: ClientError, stderr: str = "") -> TransportError:
        """Map botocore ClientError to an appropriate TransportError kind."""
        code = exc.response.get("Error", {}).get("Code", "")
        if code == "InvalidInstanceId":
            return TransportError(
                f"Instance not reachable via SSM ({code}): {exc}",
                kind=TransportErrorKind.NODE_UNREACHABLE,
                stderr=stderr,
            )
        if code in (
            "AccessDeniedException",
            "AccessDenied",
            "UnauthorizedAccess",
            "InvalidClientTokenId",
        ):
            return TransportError(
                f"IAM/SSM permission denied ({code}): {exc}",
                kind=TransportErrorKind.PERMISSION_DENIED,
                stderr=stderr,
            )
        return TransportError(
            f"AWS error ({code}): {exc}",
            kind=TransportErrorKind.UNKNOWN,
            stderr=stderr,
        )

    # ------------------------------------------------------------------
    # Core send-and-poll primitive
    # ------------------------------------------------------------------

    async def _send_and_poll(
        self,
        commands: list[str],
        timeout: int = _DEFAULT_TIMEOUT,
    ) -> CommandResult:
        """Send an SSM Run Command and poll until it reaches a terminal state.

        Args:
            commands: List of shell command strings sent to AWS-RunShellScript.
                      For sequential execution with abort-on-failure, pass a
                      single string with commands joined by ' && '.
            timeout:  SSM execution timeout in seconds passed to send_command.

        Returns:
            CommandResult on Success status.

        Raises:
            TransportError: On any AWS error, command failure, or poll timeout.
        """
        instance_id = self._server.ec2_instance_id
        loop = asyncio.get_running_loop()
        ssm = self._ssm_client()

        try:
            send_response = await loop.run_in_executor(
                None,
                lambda: ssm.send_command(
                    InstanceIds=[instance_id],
                    DocumentName=_SSM_DOCUMENT,
                    Parameters={"commands": commands},
                    TimeoutSeconds=timeout,
                ),
            )
        except ClientError as exc:
            raise self._map_client_error(exc) from exc

        command_id = send_response["Command"]["CommandId"]
        logger.info(
            "ssm_transport_command_sent",
            command_id=command_id,
            instance_id=instance_id,
        )

        for attempt in range(_MAX_POLL_ATTEMPTS):
            await asyncio.sleep(_POLL_INTERVAL_SECONDS)

            try:
                invocation = await loop.run_in_executor(
                    None,
                    lambda: ssm.get_command_invocation(
                        CommandId=command_id,
                        InstanceId=instance_id,
                    ),
                )
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if code == "InvocationDoesNotExist":
                    # SSM agent has not registered the invocation yet — keep polling
                    continue
                raise self._map_client_error(exc) from exc

            status = invocation.get("Status", "")
            stdout = invocation.get("StandardOutputContent", "") or ""
            stderr = invocation.get("StandardErrorContent", "") or ""

            if status == "Success":
                logger.info(
                    "ssm_transport_command_success",
                    command_id=command_id,
                    instance_id=instance_id,
                    attempt=attempt + 1,
                )
                return CommandResult(stdout=stdout, stderr=stderr, exit_code=0)

            if status == "TimedOut":
                raise TransportError(
                    f"SSM command {command_id} timed out on instance {instance_id}",
                    kind=TransportErrorKind.TIMEOUT,
                    stderr=stderr,
                )

            if status in ("Failed", "Cancelled"):
                kind = TransportErrorKind.COMMAND_FAILED
                if stderr and "permission denied" in stderr.lower():
                    kind = TransportErrorKind.PERMISSION_DENIED
                raise TransportError(
                    f"SSM command {command_id} on {instance_id} finished with status '{status}'",
                    kind=kind,
                    stderr=stderr,
                    exit_code=1,
                )

            # InProgress / Pending / Delayed — keep polling
            logger.debug(
                "ssm_transport_polling",
                command_id=command_id,
                status=status,
                attempt=attempt + 1,
            )

        raise TransportError(
            f"SSM command {command_id} on {instance_id} did not complete within "
            f"{_MAX_POLL_ATTEMPTS * _POLL_INTERVAL_SECONDS:.0f}s",
            kind=TransportErrorKind.TIMEOUT,
        )

    # ------------------------------------------------------------------
    # NodeTransport implementation
    # ------------------------------------------------------------------

    async def execute(
        self,
        commands: list[str],
        *,
        timeout: int | None = None,
    ) -> CommandResult:
        """Run commands joined with ' && ' via SSM Run Command.

        Raises:
            TransportError: On connection/permission failure, command failure,
                            or poll timeout.
        """
        command = " && ".join(commands)
        effective_timeout = timeout if timeout is not None else _DEFAULT_TIMEOUT
        return await self._send_and_poll([command], timeout=effective_timeout)

    async def write_file(
        self,
        path: str,
        content: str,
        *,
        mode: str = "644",
        make_dirs: bool = True,
    ) -> None:
        """Write *content* to *path* on the remote node via base64 inline transfer.

        SSM Run Command does not support stdin piping, so the content is
        base64-encoded and embedded in the shell command:

            printf '%s' '<B64>' | base64 -d | sudo tee <path> > /dev/null

        The full command (mkdir + write + chmod joined with ' && ') must not
        exceed _SSM_COMMAND_MAX_CHARS. A TransportError is raised with a
        descriptive size message before any API call if the content is too large.

        Raises:
            TransportError: If content exceeds the SSM command size limit, or
                            if mkdir / write / chmod fails remotely.
        """
        dir_path = posixpath.dirname(path)
        b64_content = base64.b64encode(content.encode()).decode("ascii")
        write_cmd = f"printf '%s' '{b64_content}' | base64 -d | sudo tee {path} > /dev/null"

        cmd_parts: list[str] = []
        if make_dirs and dir_path:
            cmd_parts.append(f"sudo mkdir -p {dir_path}")
        cmd_parts.append(write_cmd)
        cmd_parts.append(f"sudo chmod {mode} {path}")
        full_cmd = " && ".join(cmd_parts)

        if len(full_cmd) > _SSM_COMMAND_MAX_CHARS:
            scaffold_len = len(full_cmd) - len(b64_content)
            max_b64_chars = _SSM_COMMAND_MAX_CHARS - scaffold_len
            max_original_bytes = int(max_b64_chars * 3 / 4)
            raise TransportError(
                f"Content for {path!r} is too large to embed in a single SSM command "
                f"(command is {len(full_cmd)} chars, limit is {_SSM_COMMAND_MAX_CHARS}). "
                f"Maximum original content is approximately {max_original_bytes} bytes.",
                kind=TransportErrorKind.COMMAND_FAILED,
            )

        await self._send_and_poll([full_cmd])

    async def delete_file(self, path: str) -> None:
        """Remove *path* via ``sudo rm -f`` (idempotent — missing file is OK).

        Raises:
            TransportError: If rm fails for a reason other than file-not-found.
        """
        await self._send_and_poll([f"sudo rm -f {path}"])

    async def rename_file(self, src: str, dst: str) -> None:
        """Move *src* to *dst* via ``sudo mv``.

        Raises:
            TransportError: On failure.
        """
        await self._send_and_poll([f"sudo mv {src} {dst}"])

    async def check_reachable(self, *, timeout: int = 10) -> bool:
        """Verify that the instance is registered and online in SSM.

        Uses describe_instance_information filtered by instance ID.
        Returns True if the instance appears in the SSM inventory.

        Raises:
            TransportError: If the instance is not found, the call times out,
                            or an AWS error occurs.
        """
        instance_id = self._server.ec2_instance_id
        loop = asyncio.get_running_loop()
        ssm = self._ssm_client()

        try:
            response = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: ssm.describe_instance_information(
                        Filters=[{"Key": "InstanceIds", "ValueSet": [instance_id]}]
                    ),
                ),
                timeout=timeout,
            )
        except asyncio.TimeoutError:
            raise TransportError(
                f"SSM describe_instance_information timed out for {instance_id!r}",
                kind=TransportErrorKind.TIMEOUT,
            ) from None
        except ClientError as exc:
            raise self._map_client_error(exc) from exc

        instances = response.get("InstanceInformationList", [])
        if not instances:
            raise TransportError(
                f"Instance {instance_id!r} is not registered with SSM or SSM agent is offline",
                kind=TransportErrorKind.NODE_UNREACHABLE,
            )
        return True
