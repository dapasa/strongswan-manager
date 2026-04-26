"""SSM service — execute commands on VPN instances via AWS Systems Manager."""

from __future__ import annotations

import asyncio

from botocore.exceptions import ClientError

from app.config import get_settings
from app.exceptions import InfrastructureError
from app.logging_config import get_logger
from app.services.aws_session import get_client

logger = get_logger(__name__)

# Simple in-memory cache for instance ID resolution
_instance_id_cache: dict[str, str] = {}


_POLL_INTERVAL_SECONDS: float = 2.0
_MAX_POLL_ATTEMPTS: int = 30


def _get_ec2_client():  # noqa: ANN202
    """Return a boto3 EC2 client (cached, refreshed on credential rotation)."""
    return get_client("ec2")


def _get_ssm_client():  # noqa: ANN202
    """Return a boto3 SSM client (cached, refreshed on credential rotation)."""
    return get_client("ssm")


async def resolve_instance_id(instance_name: str) -> str:
    """Resolve an EC2 instance ID from its Name tag or config.

    If a direct instance ID is configured for this name, returns it
    immediately without an EC2 API call. Otherwise falls back to
    ``describe_instances`` with Name tag filter.

    Results are cached in-memory since instance IDs rarely change.

    Args:
        instance_name: Value of the EC2 ``Name`` tag.

    Returns:
        The EC2 instance ID (e.g., ``i-0abc123...``).

    Raises:
        InfrastructureError: If no running instance matches the name.
    """
    if instance_name in _instance_id_cache:
        return _instance_id_cache[instance_name]

    # Check if a direct instance ID is configured for this name
    settings = get_settings()
    direct_id: str | None = None
    if instance_name == settings.vpn_primary_instance_name and settings.vpn_primary_instance_id:
        direct_id = settings.vpn_primary_instance_id
    elif instance_name == settings.vpn_secondary_instance_name and settings.vpn_secondary_instance_id:
        direct_id = settings.vpn_secondary_instance_id

    if direct_id:
        _instance_id_cache[instance_name] = direct_id
        logger.info(
            "ssm_instance_from_config",
            instance_name=instance_name,
            instance_id=direct_id,
        )
        return direct_id

    logger.info("ssm_resolve_instance", instance_name=instance_name)

    loop = asyncio.get_running_loop()
    try:
        response = await loop.run_in_executor(
            None,
            lambda: _get_ec2_client().describe_instances(
                Filters=[
                    {"Name": "tag:Name", "Values": [instance_name]},
                    {"Name": "instance-state-name", "Values": ["running"]},
                ],
            ),
        )
    except ClientError as exc:
        raise InfrastructureError(
            service="EC2",
            message=f"Failed to describe instances for name '{instance_name}'",
            detail=str(exc),
        ) from exc

    for reservation in response.get("Reservations", []):
        for instance in reservation.get("Instances", []):
            instance_id = instance["InstanceId"]
            _instance_id_cache[instance_name] = instance_id
            logger.info(
                "ssm_instance_resolved",
                instance_name=instance_name,
                instance_id=instance_id,
            )
            return instance_id

    raise InfrastructureError(
        service="EC2",
        message=f"No running instance found with Name tag '{instance_name}'",
    )


async def execute_command(
    instance_id: str,
    commands: list[str],
    timeout: int = 60,
) -> str:
    """Execute shell commands on an EC2 instance via SSM Run Command.

    Sends the command and polls ``get_command_invocation`` every 2 seconds
    until a terminal state is reached or the polling limit is exhausted.

    Args:
        instance_id: Target EC2 instance ID.
        commands: Shell commands to execute (passed to ``AWS-RunShellScript``).
        timeout: SSM execution timeout in seconds.

    Returns:
        Stdout from the command on success.

    Raises:
        InfrastructureError: On command failure, timeout, or SSM API error.
    """
    logger.info(
        "ssm_command_start",
        instance_id=instance_id,
        commands=commands,
        timeout=timeout,
    )

    loop = asyncio.get_running_loop()
    ssm = _get_ssm_client()

    try:
        send_response = await loop.run_in_executor(
            None,
            lambda: ssm.send_command(
                InstanceIds=[instance_id],
                DocumentName="AWS-RunShellScript",
                Parameters={"commands": commands},
                TimeoutSeconds=timeout,
            ),
        )
    except ClientError as exc:
        raise InfrastructureError(
            service="SSM",
            message=f"Failed to send command to {instance_id}",
            detail=str(exc),
        ) from exc

    command_id = send_response["Command"]["CommandId"]
    logger.info("ssm_command_sent", command_id=command_id, instance_id=instance_id)

    # Poll for result
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
            error_code = exc.response.get("Error", {}).get("Code", "")
            if error_code == "InvocationDoesNotExist":
                # Command not yet registered — keep polling
                continue
            raise InfrastructureError(
                service="SSM",
                message=f"Failed to get command invocation for {command_id}",
                detail=str(exc),
            ) from exc

        status = invocation.get("Status", "")
        if status == "Success":
            stdout = invocation.get("StandardOutputContent", "")
            logger.info(
                "ssm_command_success",
                command_id=command_id,
                instance_id=instance_id,
                attempt=attempt + 1,
            )
            return stdout

        if status in ("Failed", "TimedOut", "Cancelled"):
            stderr = invocation.get("StandardErrorContent", "")
            raise InfrastructureError(
                service="SSM",
                message=(
                    f"Command {command_id} on {instance_id} finished "
                    f"with status '{status}'"
                ),
                detail=stderr or None,
            )

        # Still in progress — continue polling
        logger.debug(
            "ssm_command_polling",
            command_id=command_id,
            status=status,
            attempt=attempt + 1,
        )

    # Exhausted polling attempts
    raise InfrastructureError(
        service="SSM",
        message=(
            f"Command {command_id} on {instance_id} did not complete "
            f"within {_MAX_POLL_ATTEMPTS * _POLL_INTERVAL_SECONDS:.0f}s"
        ),
    )


async def reload_ipsec() -> None:
    """Sync configs from S3 and reload ipsec on both VPN instances.

    Runs the sync_config.sh script which:
    1. Downloads connection configs and secrets from S3 to local disk
    2. Detects changes via hash comparison
    3. Runs ipsec update + rereadsecrets if changed

    Raises:
        InfrastructureError: If the sync/reload fails on either instance.
    """
    settings = get_settings()
    await run_on_instances(commands=["/opt/strongswan/scripts/sync_config.sh"], target="both")
    logger.info("ssm_ipsec_reloaded")


async def run_on_instances(
    commands: list[str],
    target: str,
) -> None:
    """Run shell commands on one or both VPN instances.

    Args:
        commands: Shell commands to execute.
        target: ``'primary'``, ``'secondary'``, or ``'both'``.

    Raises:
        InfrastructureError: On command or resolution failure.
        ValueError: If *target* is not a recognised value.
    """
    settings = get_settings()

    instance_names: list[str] = []
    if target in ("primary", "both"):
        instance_names.append(settings.vpn_primary_instance_name)
    if target in ("secondary", "both"):
        instance_names.append(settings.vpn_secondary_instance_name)

    if not instance_names:
        raise ValueError(f"Invalid target '{target}'. Must be 'primary', 'secondary', or 'both'.")

    results: list[dict] = []
    for name in instance_names:
        try:
            instance_id = await resolve_instance_id(name)
            await execute_command(
                instance_id=instance_id,
                commands=commands,
                timeout=settings.ssm_command_timeout,
            )
            results.append({"instance": name, "status": "ok"})
            logger.info("ssm_instance_ok", instance_name=name)
        except InfrastructureError as exc:
            results.append({"instance": name, "status": "failed", "error": exc.message})
            logger.error("ssm_instance_failed", instance_name=name, error=exc.message)

    failed = [r for r in results if r["status"] == "failed"]
    if failed:
        status_parts = []
        for r in results:
            short_name = r["instance"].replace("dev-strongswan-", "").replace("vpn-", "")
            if r["status"] == "ok":
                status_parts.append(f"{short_name}: OK")
            else:
                status_parts.append(f"{short_name}: FAILED")
        summary = " | ".join(status_parts)

        detail_lines = []
        for r in results:
            if r["status"] == "failed":
                detail_lines.append(f"{r['instance']}: {r['error']}")
        detail = "\n".join(detail_lines)

        raise InfrastructureError(
            service="SSM",
            message=f"Reload {len(failed)}/{len(results)} failed — {summary}\n{detail}",
        )


async def check_connectivity() -> bool:
    """Verify SSM connectivity for the health endpoint.

    Returns:
        True if we can reach SSM, False otherwise.
    """
    loop = asyncio.get_running_loop()
    try:
        await loop.run_in_executor(
            None,
            lambda: _get_ssm_client().describe_instance_information(MaxResults=5),
        )
        return True
    except Exception:
        logger.warning("ssm_connectivity_check_failed")
        return False
