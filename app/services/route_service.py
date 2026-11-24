"""Route service — AWS EC2 API backed VPC route management (sc-31774).

Each create/delete/retry operation:
  1. Validates the request (CIDR rules, duplicate check, VPC overlap).
  2. Resolves the active ENI from the EIP holder in failover/config.yaml.
  3. Writes / deletes the route in every allowlisted route table.
  4. Records per-table outcomes in the DB; writes an audit log entry.
  5. Commits atomically.
"""

from __future__ import annotations

import asyncio
import io
from ipaddress import IPv4Network, ip_network
from typing import Any
from uuid import UUID

import yaml
from botocore.exceptions import ClientError
from fastapi import Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import Settings, get_settings
from app.db.models import AsyncOperation, Route, Server, Tunnel, User
from app.exceptions import (
    ConflictError,
    InfrastructureError,
    NotFoundError,
    ValidationError,
)
from app.logging_config import get_logger
from app.services import audit
from app.services.aws_client import get_client_for_server

logger = get_logger(__name__)

# Keys in failover/config.yaml
_FAILOVER_CONFIG_KEY_TABLES = "route_table_ids"
_FAILOVER_CONFIG_KEY_EIP = "eip_allocation_id"
_FAILOVER_CONFIG_KEY_PRIMARY_IP = "primary_ip"
_FAILOVER_CONFIG_KEY_SECONDARY_IP = "secondary_ip"


# ---------------------------------------------------------------------------
# DB read helpers (unchanged from prior version)
# ---------------------------------------------------------------------------


async def list_routes(
    session: AsyncSession,
    *,
    tunnel_id: int | None = None,
) -> list[Route]:
    """List active (non-deleted) routes, optionally filtered by tunnel.

    Args:
        session: Active database session.
        tunnel_id: If provided, filter routes to this tunnel only.

    Returns:
        List of active Route instances.
    """
    stmt = select(Route).where(Route.deleted_at.is_(None))
    if tunnel_id is not None:
        stmt = stmt.where(Route.tunnel_id == tunnel_id)
    stmt = stmt.order_by(Route.id)

    result = await session.execute(stmt)
    return list(result.scalars().all())


async def get_route(session: AsyncSession, route_id: int) -> Route:
    """Get a single route by ID.

    Args:
        session: Active database session.
        route_id: Primary key of the route.

    Returns:
        The Route instance.

    Raises:
        NotFoundError: If no active route with the given ID exists.
    """
    result = await session.execute(
        select(Route).where(
            Route.id == route_id,
            Route.deleted_at.is_(None),
        ),
    )
    route = result.scalar_one_or_none()
    if route is None:
        raise NotFoundError("Route", route_id)
    return route


async def get_operation(
    session: AsyncSession,
    operation_id: str,
) -> AsyncOperation:
    """Get an AsyncOperation by ID for polling.

    Args:
        session: Active database session.
        operation_id: UUID of the async operation.

    Returns:
        The AsyncOperation instance.

    Raises:
        NotFoundError: If the operation does not exist.
    """
    try:
        op_uuid = UUID(operation_id)
    except ValueError as exc:
        raise NotFoundError("AsyncOperation", operation_id) from exc

    result = await session.execute(
        select(AsyncOperation).where(AsyncOperation.id == op_uuid),
    )
    operation = result.scalar_one_or_none()
    if operation is None:
        raise NotFoundError("AsyncOperation", operation_id)
    return operation


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


async def _get_active_server(session: AsyncSession) -> Server:
    """Return the first active non-deleted server.

    Used to get AWS credentials (aws_role_arn, aws_region_override) for EC2
    and S3 API calls.  All servers in a VPN HA pair share the same account.

    Raises:
        InfrastructureError: If no active server exists.
    """
    result = await session.execute(
        select(Server).where(
            Server.is_active.is_(True),
            Server.deleted_at.is_(None),
        ).limit(1),
    )
    server = result.scalar_one_or_none()
    if server is None:
        raise InfrastructureError("servers", "No active server registered; cannot call AWS API")
    return server


def _read_failover_config_sync(s3_client: Any, bucket: str) -> dict:
    """Synchronous S3 read of failover/config.yaml — run via run_in_executor."""
    try:
        obj = s3_client.get_object(Bucket=bucket, Key="failover/config.yaml")
        return yaml.safe_load(obj["Body"].read())
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        raise InfrastructureError(
            "S3",
            f"Cannot read failover/config.yaml from bucket '{bucket}': {code}",
        ) from exc


async def _read_failover_config(s3_client: Any, bucket: str) -> dict:
    """Read failover/config.yaml from the StrongSwan config S3 bucket."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _read_failover_config_sync(s3_client, bucket),
    )


def _resolve_target_eni_sync(
    ec2_client: Any,
    failover_config: dict,
    managed_tables: list[str],
) -> str:
    """Synchronous ENI resolution — run via run_in_executor.

    Resolution order:
      1. Read primary_ip and secondary_ip from failover_config.
      2. DescribeNetworkInterfaces(private-ip-address in {primary_ip, secondary_ip})
         to build the set of VPN node ENIs (one per node, indexed by InstanceId).
         This matches how the failover script identifies routes it owns.
      3. DescribeAddresses(AllocationIds=[eip_allocation_id]) → InstanceId of the
         current EIP holder.
      4. If the EIP is associated: return the VPN ENI whose Attachment.InstanceId
         equals the holder.  Fail if no match.
      5. If the EIP is not associated: scan the managed route tables and collect
         ENIs that are in the VPN ENI set.  If all such routes target exactly one
         distinct VPN ENI, return it.  Otherwise fail explicitly.

    The fallback in step 5 filters to VPN ENIs only — a non-VPN ENI in a route
    table is invisible to the failover script and must not be returned.

    Raises:
        InfrastructureError: When the ENI cannot be unambiguously determined.
    """
    eip_alloc_id: str | None = failover_config.get(_FAILOVER_CONFIG_KEY_EIP)
    if not eip_alloc_id:
        raise InfrastructureError(
            "failover_config",
            f"failover/config.yaml missing '{_FAILOVER_CONFIG_KEY_EIP}' key",
        )

    primary_ip: str | None = failover_config.get(_FAILOVER_CONFIG_KEY_PRIMARY_IP)
    secondary_ip: str | None = failover_config.get(_FAILOVER_CONFIG_KEY_SECONDARY_IP)
    if not primary_ip or not secondary_ip:
        raise InfrastructureError(
            "failover_config",
            "failover/config.yaml missing 'primary_ip' or 'secondary_ip'; "
            "these are required to identify the VPN node ENIs",
        )

    # Discover VPN node ENIs by private IP — mirrors the failover script's approach
    vpn_ip_values = [primary_ip, secondary_ip]
    try:
        ni_resp = ec2_client.describe_network_interfaces(
            Filters=[{"Name": "private-ip-address", "Values": vpn_ip_values}]
        )
        vpn_enis_raw = ni_resp.get("NetworkInterfaces", [])
    except ClientError as exc:
        raise InfrastructureError(
            "EC2",
            f"DescribeNetworkInterfaces(private-ip-address in {vpn_ip_values}) failed: "
            f"{exc.response['Error']['Code']}",
        ) from exc

    # Build {instance_id → eni_id} map and a plain set for fast membership tests
    vpn_eni_by_instance: dict[str, str] = {}
    vpn_eni_ids: set[str] = set()
    for ni in vpn_enis_raw:
        eni_id: str | None = ni.get("NetworkInterfaceId")
        instance_id: str | None = ni.get("Attachment", {}).get("InstanceId")
        if eni_id and instance_id:
            vpn_eni_by_instance[instance_id] = eni_id
            vpn_eni_ids.add(eni_id)

    # Determine which instance currently holds the EIP
    holder_instance_id: str | None = None
    try:
        resp = ec2_client.describe_addresses(AllocationIds=[eip_alloc_id])
        addrs = resp.get("Addresses", [])
        if addrs:
            holder_instance_id = addrs[0].get("InstanceId")
    except ClientError as exc:
        raise InfrastructureError(
            "EC2",
            f"DescribeAddresses({eip_alloc_id}) failed: {exc.response['Error']['Code']}",
        ) from exc

    if holder_instance_id:
        target_eni = vpn_eni_by_instance.get(holder_instance_id)
        if target_eni:
            logger.info(
                "route_eni_resolved_via_primary_ip_eni",
                eni=target_eni,
                instance=holder_instance_id,
                eip=eip_alloc_id,
            )
            return target_eni
        raise InfrastructureError(
            "EC2",
            f"EIP is held by instance {holder_instance_id} but no VPN ENI "
            f"(primary_ip={primary_ip}, secondary_ip={secondary_ip}) is attached to it. "
            "Check failover/config.yaml primary_ip and secondary_ip.",
        )

    # EIP is not currently associated — fall back to inspecting the managed tables,
    # counting only routes that target a known VPN ENI
    logger.warning(
        "route_eip_not_associated",
        eip=eip_alloc_id,
        message="EIP not associated; scanning managed route tables for VPN ENI consensus",
    )

    candidate_enis: set[str] = set()
    for rtb_id in managed_tables:
        try:
            rt_resp = ec2_client.describe_route_tables(RouteTableIds=[rtb_id])
            tables = rt_resp.get("RouteTables", [])
            if not tables:
                continue
            for route in tables[0].get("Routes", []):
                eni = route.get("NetworkInterfaceId")
                if eni and eni in vpn_eni_ids:
                    candidate_enis.add(eni)
        except ClientError as exc:
            raise InfrastructureError(
                "EC2",
                f"DescribeRouteTables({rtb_id}) failed: {exc.response['Error']['Code']}",
            ) from exc

    if len(candidate_enis) == 1:
        target_eni = next(iter(candidate_enis))
        logger.info(
            "route_eni_resolved_via_route_scan",
            eni=target_eni,
            tables=managed_tables,
        )
        return target_eni

    if len(candidate_enis) == 0:
        raise InfrastructureError(
            "EC2",
            "EIP is not associated and no VPN-ENI-targeted routes exist in the managed "
            "route tables; cannot determine the target ENI. Associate the EIP first.",
        )

    raise InfrastructureError(
        "EC2",
        f"EIP is not associated and multiple VPN ENIs found across managed "
        f"route tables ({sorted(candidate_enis)}). Cannot determine the active node. "
        "Associate the EIP first.",
    )


async def _resolve_target_eni(
    ec2_client: Any,
    failover_config: dict,
    managed_tables: list[str],
) -> str:
    """Async wrapper for ENI resolution."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _resolve_target_eni_sync(ec2_client, failover_config, managed_tables),
    )


def _validate_cidr_rules(tunnel: Tunnel, cidr_net: IPv4Network) -> None:
    """Validate CIDR against tunnel rules.

    Rules:
    - Prefix length 0 (/0) is always rejected.
    - CIDR must be a subnet of (or equal to) at least one of the tunnel's remote_cidrs.

    Raises:
        ValidationError
    """
    if cidr_net.prefixlen == 0:
        raise ValidationError("CIDR with prefix length 0 (default route) is not allowed")

    for remote_str in tunnel.remote_cidrs:
        try:
            remote_net = IPv4Network(str(remote_str), strict=False)
            if cidr_net.subnet_of(remote_net):
                return  # Passes
        except ValueError:
            continue

    raise ValidationError(
        f"{cidr_net} is not inside any of the tunnel's remote CIDRs "
        f"({[str(c) for c in tunnel.remote_cidrs]})"
    )


async def _validate_no_duplicate(
    session: AsyncSession,
    tunnel_id: int,
    cidr_str: str,
) -> None:
    """Raise ConflictError if an active route with the same CIDR already exists on this tunnel."""
    result = await session.execute(
        select(Route).where(
            Route.tunnel_id == tunnel_id,
            Route.cidr == cidr_str,
            Route.deleted_at.is_(None),
        ),
    )
    existing = result.scalar_one_or_none()
    if existing is not None:
        raise ConflictError(
            f"Route {cidr_str} already exists on tunnel {tunnel_id} (id={existing.id})"
        )


def _validate_vpc_overlap_sync(
    ec2_client: Any,
    managed_tables: list[str],
    cidr_net: IPv4Network,
) -> None:
    """Check CIDR does not overlap any CIDR block of the VPC that owns the route tables.

    Uses the first managed table to identify the VpcId, then checks all
    CidrBlockAssociationSet entries.

    Raises:
        ValidationError: If the CIDR overlaps a VPC CIDR.
        InfrastructureError: On AWS API error.
    """
    rtb_id = managed_tables[0]
    try:
        rt_resp = ec2_client.describe_route_tables(RouteTableIds=[rtb_id])
        tables = rt_resp.get("RouteTables", [])
        if not tables:
            raise InfrastructureError("EC2", f"Route table {rtb_id} not found")
        vpc_id = tables[0].get("VpcId")
        if not vpc_id:
            raise InfrastructureError("EC2", f"Route table {rtb_id} has no VpcId")
    except ClientError as exc:
        raise InfrastructureError(
            "EC2",
            f"DescribeRouteTables({rtb_id}) failed: {exc.response['Error']['Code']}",
        ) from exc

    try:
        vpc_resp = ec2_client.describe_vpcs(VpcIds=[vpc_id])
        vpcs = vpc_resp.get("Vpcs", [])
        if not vpcs:
            raise InfrastructureError("EC2", f"VPC {vpc_id} not found")
        for assoc in vpcs[0].get("CidrBlockAssociationSet", []):
            cidr_block = assoc.get("CidrBlock")
            if not cidr_block:
                continue
            vpc_net = IPv4Network(cidr_block, strict=False)
            if cidr_net.overlaps(vpc_net):
                raise ValidationError(
                    f"{cidr_net} overlaps VPC CIDR {vpc_net} (VPC {vpc_id})"
                )
    except ClientError as exc:
        raise InfrastructureError(
            "EC2",
            f"DescribeVpcs({vpc_id}) failed: {exc.response['Error']['Code']}",
        ) from exc


async def _validate_vpc_overlap(
    ec2_client: Any,
    managed_tables: list[str],
    cidr_net: IPv4Network,
) -> None:
    """Async wrapper for VPC overlap validation."""
    loop = asyncio.get_running_loop()
    await loop.run_in_executor(
        None,
        lambda: _validate_vpc_overlap_sync(ec2_client, managed_tables, cidr_net),
    )


def _validate_tables_in_failover(
    managed_tables: list[str],
    failover_config: dict,
) -> None:
    """Ensure every managed route table is listed in failover/config.yaml route_table_ids.

    If a table is not under failover control, routes written to it will not be
    moved to the active node after a failover, breaking connectivity.

    Raises:
        ValidationError: If any managed table is absent from the failover config.
    """
    failover_tables: list[str] = failover_config.get(_FAILOVER_CONFIG_KEY_TABLES, []) or []
    failover_set = set(failover_tables)

    missing = [t for t in managed_tables if t not in failover_set]
    if missing:
        raise ValidationError(
            f"Managed route table(s) not in failover/config.yaml route_table_ids: {missing}. "
            "Routes written to these tables would not be moved after a failover."
        )


def _write_routes_to_tables_sync(
    ec2_client: Any,
    managed_tables: list[str],
    cidr: str,
    eni_id: str,
) -> dict[str, dict[str, str]]:
    """Write a route to every managed table synchronously.

    Returns table_outcomes dict: {rtb_id: {"status": ..., "error": ...}}
    Status values: "ok", "already_exists_same_target", "failed"
    """
    outcomes: dict[str, dict[str, str]] = {}

    for rtb_id in managed_tables:
        # Check if the route already exists in this table
        try:
            rt_resp = ec2_client.describe_route_tables(RouteTableIds=[rtb_id])
            tables = rt_resp.get("RouteTables", [])
            existing_eni: str | None = None
            if tables:
                for route in tables[0].get("Routes", []):
                    if route.get("DestinationCidrBlock") == cidr:
                        existing_eni = route.get("NetworkInterfaceId")
                        break
        except ClientError as exc:
            outcomes[rtb_id] = {
                "status": "failed",
                "error": f"DescribeRouteTables: {exc.response['Error']['Code']}",
            }
            continue

        if existing_eni is not None:
            if existing_eni == eni_id:
                outcomes[rtb_id] = {"status": "already_exists_same_target"}
                continue
            else:
                outcomes[rtb_id] = {
                    "status": "failed",
                    "error": (
                        f"Route already exists in {rtb_id} targeting a different ENI "
                        f"({existing_eni} != {eni_id}). Will not replace."
                    ),
                }
                continue

        # Route does not exist — create it
        try:
            ec2_client.create_route(
                RouteTableId=rtb_id,
                DestinationCidrBlock=cidr,
                NetworkInterfaceId=eni_id,
            )
            outcomes[rtb_id] = {"status": "ok"}
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            # AWS sometimes returns RouteAlreadyExists for a concurrent create
            if code == "RouteAlreadyExists":
                # Describe again to check the target
                try:
                    rt2 = ec2_client.describe_route_tables(RouteTableIds=[rtb_id])
                    t2 = rt2.get("RouteTables", [])
                    race_eni: str | None = None
                    if t2:
                        for r2 in t2[0].get("Routes", []):
                            if r2.get("DestinationCidrBlock") == cidr:
                                race_eni = r2.get("NetworkInterfaceId")
                                break
                    if race_eni == eni_id:
                        outcomes[rtb_id] = {"status": "already_exists_same_target"}
                    else:
                        outcomes[rtb_id] = {
                            "status": "failed",
                            "error": (
                                f"RouteAlreadyExists in {rtb_id} targeting a different ENI "
                                f"({race_eni} != {eni_id})."
                            ),
                        }
                except ClientError:
                    outcomes[rtb_id] = {
                        "status": "failed",
                        "error": f"RouteAlreadyExists and re-describe failed",
                    }
            else:
                outcomes[rtb_id] = {
                    "status": "failed",
                    "error": f"CreateRoute: {code}",
                }

    return outcomes


async def _write_routes_to_tables(
    ec2_client: Any,
    managed_tables: list[str],
    cidr: str,
    eni_id: str,
) -> dict[str, dict[str, str]]:
    """Async wrapper for route writing."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _write_routes_to_tables_sync(ec2_client, managed_tables, cidr, eni_id),
    )


def _delete_routes_from_tables_sync(
    ec2_client: Any,
    managed_tables: list[str],
    cidr: str,
) -> dict[str, dict[str, str]]:
    """Delete a route from every managed table synchronously.

    Returns table_outcomes dict. "route_not_found" counts as success.
    """
    outcomes: dict[str, dict[str, str]] = {}

    for rtb_id in managed_tables:
        try:
            ec2_client.delete_route(
                RouteTableId=rtb_id,
                DestinationCidrBlock=cidr,
            )
            outcomes[rtb_id] = {"status": "ok"}
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("InvalidRoute.NotFound", "RouteNotFound"):
                # Already gone — count as success
                outcomes[rtb_id] = {"status": "not_found_ok"}
            else:
                outcomes[rtb_id] = {
                    "status": "failed",
                    "error": f"DeleteRoute: {code}",
                }

    return outcomes


async def _delete_routes_from_tables(
    ec2_client: Any,
    managed_tables: list[str],
    cidr: str,
) -> dict[str, dict[str, str]]:
    """Async wrapper for route deletion."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(
        None,
        lambda: _delete_routes_from_tables_sync(ec2_client, managed_tables, cidr),
    )


def _outcomes_sync_status(outcomes: dict[str, dict[str, str]]) -> str:
    """Derive sync_status from per-table outcomes.

    Returns 'synced' only if every table is 'ok' or 'already_exists_same_target'.
    Otherwise returns 'failed'.
    """
    success_states = {"ok", "already_exists_same_target", "not_found_ok"}
    all_ok = all(v.get("status") in success_states for v in outcomes.values())
    return "synced" if all_ok else "failed"


def _outcomes_error_summary(outcomes: dict[str, dict[str, str]]) -> str | None:
    """Build a human-readable error summary from failed table outcomes."""
    failures = {
        rtb_id: v["error"]
        for rtb_id, v in outcomes.items()
        if v.get("status") == "failed"
    }
    if not failures:
        return None
    parts = [f"{rtb}: {msg}" for rtb, msg in sorted(failures.items())]
    return "; ".join(parts)


def _route_to_dict(route: Route) -> dict[str, Any]:
    """Serialize a Route model to a dict for audit JSONB storage."""
    return {
        "id": route.id,
        "tunnel_id": route.tunnel_id,
        "cidr": str(route.cidr) if route.cidr else None,
        "description": route.description,
        "sync_status": route.sync_status,
        "sync_error": route.sync_error,
        "target_eni": route.target_eni,
        "table_outcomes": route.table_outcomes,
        "created_by": route.created_by,
        "created_at": route.created_at.isoformat() if route.created_at else None,
        "updated_at": route.updated_at.isoformat() if route.updated_at else None,
    }


def _require_managed_tables(settings: Settings) -> list[str]:
    """Return non-empty managed table list or raise ValidationError."""
    tables = [t.strip() for t in settings.managed_route_table_ids if t.strip()]
    if not tables:
        raise ValidationError(
            "MANAGED_ROUTE_TABLE_IDS is empty; route-write feature is disabled"
        )
    if not settings.strongswan_config_bucket.strip():
        raise ValidationError(
            "STRONGSWAN_CONFIG_BUCKET is empty; route-write feature is disabled"
        )
    return tables


# ---------------------------------------------------------------------------
# Public write operations
# ---------------------------------------------------------------------------


async def create_route(
    session: AsyncSession,
    *,
    tunnel_id: int,
    cidr: IPv4Network,
    description: str | None,
    user: User,
    request: Request | None = None,
) -> Route:
    """Create a VPC route for a tunnel via the AWS EC2 API.

    Validates:
    - MANAGED_ROUTE_TABLE_IDS is non-empty.
    - CIDR is not /0.
    - CIDR is inside one of the tunnel's remote CIDRs.
    - No duplicate active route for the same tunnel+CIDR in the DB.
    - CIDR does not overlap any VPC CIDR block.
    - Every managed table is listed in failover/config.yaml route_table_ids.

    Then resolves the target ENI (from the EIP holder), writes the route
    to every table, and records per-table outcomes.

    Args:
        session: Active database session.
        tunnel_id: Tunnel to associate the route with.
        cidr: Destination CIDR for the route.
        description: Optional human-readable label.
        user: Operator or admin performing the action.
        request: FastAPI request for audit context.

    Returns:
        The created Route model (sync_status may be 'synced' or 'failed').

    Raises:
        NotFoundError: Tunnel does not exist.
        ValidationError: Any of the CIDR validation rules failed.
        ConflictError: Duplicate route in the DB.
        InfrastructureError: AWS API or S3 failure.
    """
    settings = get_settings()
    managed_tables = _require_managed_tables(settings)

    # --- Load tunnel ---
    result = await session.execute(
        select(Tunnel).where(Tunnel.id == tunnel_id, Tunnel.deleted_at.is_(None)),
    )
    tunnel = result.scalar_one_or_none()
    if tunnel is None:
        raise NotFoundError("Tunnel", tunnel_id)

    cidr_str = str(cidr)

    # --- Validation (before any AWS calls or DB writes) ---
    _validate_cidr_rules(tunnel, cidr)
    await _validate_no_duplicate(session, tunnel_id, cidr_str)

    # --- Get server for AWS credentials ---
    server = await _get_active_server(session)
    ec2 = get_client_for_server(server, "ec2")
    s3 = get_client_for_server(server, "s3")

    # --- Failover config + VPC overlap (AWS calls, can raise) ---
    failover_config = await _read_failover_config(s3, settings.strongswan_config_bucket)
    _validate_tables_in_failover(managed_tables, failover_config)
    await _validate_vpc_overlap(ec2, managed_tables, cidr)

    # --- Resolve target ENI ---
    target_eni = await _resolve_target_eni(ec2, failover_config, managed_tables)

    # --- Create Route record (pending) ---
    route = Route(
        tunnel_id=tunnel_id,
        cidr=cidr_str,
        description=description,
        sync_status="pending",
        created_by=user.id,
    )
    session.add(route)
    await session.flush()  # Assign PK before AWS calls

    # --- Write routes to all tables ---
    table_outcomes = await _write_routes_to_tables(ec2, managed_tables, cidr_str, target_eni)

    sync_status = _outcomes_sync_status(table_outcomes)
    sync_error = _outcomes_error_summary(table_outcomes)

    route.sync_status = sync_status
    route.sync_error = sync_error
    route.target_eni = target_eni
    route.table_outcomes = table_outcomes

    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="route",
        entity_id=route.id,
        action="create",
        new_state={
            **_route_to_dict(route),
            "tunnel_id": tunnel_id,
            "cidr": cidr_str,
            "target_eni": target_eni,
            "managed_tables": managed_tables,
        },
        request=request,
    )

    await session.commit()
    await session.refresh(route)

    logger.info(
        "route_created",
        route_id=route.id,
        tunnel_id=tunnel_id,
        cidr=cidr_str,
        target_eni=target_eni,
        sync_status=sync_status,
        tables=list(table_outcomes.keys()),
    )
    return route


async def delete_route(
    session: AsyncSession,
    *,
    route_id: int,
    user: User,
    request: Request | None = None,
) -> None:
    """Delete a VPC route via the AWS EC2 API and soft-delete the DB record.

    Removes the route from every allowlisted table. 'Route not found' in a
    table counts as success (idempotent). Soft-deletes the DB record after
    all tables are processed (regardless of per-table results).

    Args:
        session: Active database session.
        route_id: Primary key of the route to delete.
        user: Operator or admin performing the action.
        request: FastAPI request for audit context.

    Raises:
        NotFoundError: Route does not exist.
        InfrastructureError: AWS API failure.
    """
    settings = get_settings()
    managed_tables = _require_managed_tables(settings)

    route = await get_route(session, route_id)
    cidr_str = str(route.cidr)
    previous_state = _route_to_dict(route)

    server = await _get_active_server(session)
    ec2 = get_client_for_server(server, "ec2")

    # Mark as pending_delete before AWS calls
    route.sync_status = "pending_delete"

    table_outcomes = await _delete_routes_from_tables(ec2, managed_tables, cidr_str)

    # Soft-delete regardless of per-table results
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    route.deleted_at = now
    route.sync_status = "pending_delete"  # retained on deleted record
    route.table_outcomes = table_outcomes

    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="route",
        entity_id=route.id,
        action="delete",
        previous_state=previous_state,
        new_state={
            **_route_to_dict(route),
            "managed_tables": managed_tables,
            "table_outcomes": table_outcomes,
        },
        request=request,
    )

    await session.commit()

    logger.info(
        "route_deleted",
        route_id=route_id,
        cidr=cidr_str,
        table_outcomes=table_outcomes,
    )


async def retry_route(
    session: AsyncSession,
    *,
    route_id: int,
    user: User,
    request: Request | None = None,
) -> Route:
    """Retry AWS route provisioning for a route in 'failed' state.

    Only redoes the tables that are still missing (not 'ok' or
    'already_exists_same_target').  Re-resolves the target ENI at retry
    time (the active node may have changed since the original attempt).

    Args:
        session: Active database session.
        route_id: Primary key of the failed route.
        user: Operator or admin performing the action.
        request: FastAPI request for audit context.

    Returns:
        Updated Route instance.

    Raises:
        NotFoundError: Route does not exist.
        ValidationError: Route is not in 'failed' state.
        InfrastructureError: AWS API or S3 failure.
    """
    settings = get_settings()
    managed_tables = _require_managed_tables(settings)

    route = await get_route(session, route_id)
    if route.sync_status != "failed":
        raise ValidationError(
            f"Route {route_id} is in '{route.sync_status}' state; retry only allowed for 'failed'"
        )

    cidr_str = str(route.cidr)
    previous_state = _route_to_dict(route)

    server = await _get_active_server(session)
    ec2 = get_client_for_server(server, "ec2")
    s3 = get_client_for_server(server, "s3")

    failover_config = await _read_failover_config(s3, settings.strongswan_config_bucket)
    target_eni = await _resolve_target_eni(ec2, failover_config, managed_tables)

    # Determine which tables still need to be written (missing or failed)
    success_states = {"ok", "already_exists_same_target"}
    existing_outcomes: dict[str, dict[str, str]] = route.table_outcomes or {}
    tables_to_retry = [
        t for t in managed_tables
        if existing_outcomes.get(t, {}).get("status") not in success_states
    ]

    if not tables_to_retry:
        # Everything already succeeded — mark as synced
        route.sync_status = "synced"
        route.sync_error = None
        await session.commit()
        await session.refresh(route)
        return route

    new_outcomes = await _write_routes_to_tables(ec2, tables_to_retry, cidr_str, target_eni)

    # Merge with existing outcomes
    merged_outcomes = {**existing_outcomes, **new_outcomes}
    sync_status = _outcomes_sync_status(merged_outcomes)
    sync_error = _outcomes_error_summary(merged_outcomes)

    route.sync_status = sync_status
    route.sync_error = sync_error
    route.target_eni = target_eni
    route.table_outcomes = merged_outcomes

    await audit.log_action(
        session,
        user_id=user.id,
        entity_type="route",
        entity_id=route.id,
        action="retry",
        previous_state=previous_state,
        new_state={
            **_route_to_dict(route),
            "target_eni": target_eni,
            "tables_retried": tables_to_retry,
            "managed_tables": managed_tables,
        },
        request=request,
    )

    await session.commit()
    await session.refresh(route)

    logger.info(
        "route_retried",
        route_id=route_id,
        cidr=cidr_str,
        target_eni=target_eni,
        sync_status=sync_status,
        tables_retried=tables_to_retry,
    )
    return route
