"""Unit tests for the AWS-API-backed route management (sc-31774 step 2).

Covers:
- CIDR validation rules (not in remote_cidrs, is /0, overlap with VPC CIDRs)
- Duplicate detection
- ENI resolution (EIP associated / not associated single ENI / ambiguous)
- Partial failure across tables + per-table outcome tracking
- Retry (only redoes missing/failed tables)
- RouteAlreadyExists — same ENI (treat as ok) / different ENI (fail)
- Delete with 'route not found' per table (counts as success)
- Role enforcement (viewer → 403, operator → allowed)
- Empty MANAGED_ROUTE_TABLE_IDS → feature disabled error
"""

from __future__ import annotations

from datetime import datetime, timezone
from ipaddress import IPv4Network
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from fastapi import Request

from app.db.models import Route, Server, Tunnel, User
from app.exceptions import ConflictError, InfrastructureError, ValidationError


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

MANAGED_TABLES = ["rtb-aaaa1111bbbb2222c", "rtb-cccc3333dddd4444e"]
CONFIG_BUCKET = "test-strongswan-config"
TARGET_ENI = "eni-0a1b2c3d4e5f67890"
ALT_ENI = "eni-ffffffffffffffff0"
EIP_ALLOC = "eipalloc-0abc1234def56789"

FAILOVER_CONFIG = {
    "eip_allocation_id": EIP_ALLOC,
    "route_table_ids": MANAGED_TABLES,
    "primary_ip": "10.0.1.10",
    "secondary_ip": "10.0.2.10",
}


def _mock_tunnel(
    remote_cidrs: list[str] | None = None,
    local_cidrs: list[str] | None = None,
) -> MagicMock:
    t = MagicMock(spec=Tunnel)
    t.id = 1
    t.name = "test-tunnel"
    t.deleted_at = None
    t.remote_cidrs = remote_cidrs or ["192.168.1.0/24", "10.100.0.0/16"]
    t.local_cidrs = local_cidrs or ["172.16.0.0/24"]
    return t


def _mock_user(role: str = "operator") -> MagicMock:
    u = MagicMock(spec=User)
    u.id = 42
    u.role = role
    u.is_active = True
    return u


def _mock_server() -> MagicMock:
    s = MagicMock(spec=Server)
    s.id = 1
    s.is_active = True
    s.deleted_at = None
    s.aws_role_arn = None
    s.aws_region_override = None
    return s


def _mock_route(
    cidr: str = "192.168.1.0/24",
    sync_status: str = "synced",
    table_outcomes: dict | None = None,
    target_eni: str | None = TARGET_ENI,
) -> MagicMock:
    r = MagicMock(spec=Route)
    r.id = 10
    r.tunnel_id = 1
    r.cidr = cidr
    r.description = None
    r.sync_status = sync_status
    r.sync_error = None
    r.target_eni = target_eni
    r.table_outcomes = table_outcomes or {
        t: {"status": "ok"} for t in MANAGED_TABLES
    }
    r.created_by = 42
    r.deleted_at = None
    r.created_at = datetime.now(timezone.utc)
    r.updated_at = datetime.now(timezone.utc)
    return r


def _make_client_error(code: str) -> ClientError:
    return ClientError(
        {"Error": {"Code": code, "Message": f"Mocked {code}"}},
        "TestOperation",
    )


def _describe_addresses_associated(eni: str, alloc: str) -> dict:
    return {"Addresses": [{"AllocationId": alloc, "NetworkInterfaceId": eni}]}


def _describe_addresses_unassociated() -> dict:
    return {"Addresses": [{"AllocationId": EIP_ALLOC}]}


def _describe_route_tables_with_routes(
    rtb_id: str,
    vpc_id: str = "vpc-00001111",
    routes: list[dict] | None = None,
) -> dict:
    return {
        "RouteTables": [
            {
                "RouteTableId": rtb_id,
                "VpcId": vpc_id,
                "Routes": routes or [],
            }
        ]
    }


def _describe_vpcs(cidr: str = "10.0.0.0/8", vpc_id: str = "vpc-00001111") -> dict:
    return {
        "Vpcs": [
            {
                "VpcId": vpc_id,
                "CidrBlock": cidr,
                "CidrBlockAssociationSet": [
                    {"CidrBlock": cidr, "CidrBlockState": {"State": "associated"}}
                ],
            }
        ]
    }


# ---------------------------------------------------------------------------
# CIDR validation helpers
# ---------------------------------------------------------------------------


class TestValidateCidrRules:
    """Tests for _validate_cidr_rules — no AWS or DB needed."""

    def _call(self, tunnel: Tunnel, cidr: str) -> None:
        from app.services.route_service import _validate_cidr_rules

        _validate_cidr_rules(tunnel, IPv4Network(cidr))

    def test_valid_exact_remote_cidr(self) -> None:
        tunnel = _mock_tunnel(remote_cidrs=["192.168.1.0/24"])
        self._call(tunnel, "192.168.1.0/24")  # exact match — OK

    def test_valid_subnet_of_remote_cidr(self) -> None:
        tunnel = _mock_tunnel(remote_cidrs=["10.100.0.0/16"])
        self._call(tunnel, "10.100.5.0/24")  # subnet — OK

    def test_rejects_slash_zero(self) -> None:
        tunnel = _mock_tunnel()
        with pytest.raises(ValidationError, match="prefix length 0"):
            self._call(tunnel, "0.0.0.0/0")

    def test_rejects_cidr_outside_remote(self) -> None:
        tunnel = _mock_tunnel(remote_cidrs=["192.168.1.0/24"])
        with pytest.raises(ValidationError, match="not inside any"):
            self._call(tunnel, "10.0.0.0/24")

    def test_rejects_supernet_of_remote(self) -> None:
        # 192.168.0.0/16 is NOT a subnet of 192.168.1.0/24
        tunnel = _mock_tunnel(remote_cidrs=["192.168.1.0/24"])
        with pytest.raises(ValidationError, match="not inside any"):
            self._call(tunnel, "192.168.0.0/16")

    def test_valid_host_route_in_remote(self) -> None:
        tunnel = _mock_tunnel(remote_cidrs=["192.168.1.0/24"])
        self._call(tunnel, "192.168.1.50/32")  # host in range — OK


# ---------------------------------------------------------------------------
# ENI resolution
# ---------------------------------------------------------------------------


class TestResolveTargetEni:
    """Tests for _resolve_target_eni_sync."""

    def _call(
        self, ec2: MagicMock, failover: dict, tables: list[str]
    ) -> str:
        from app.services.route_service import _resolve_target_eni_sync

        return _resolve_target_eni_sync(ec2, failover, tables)

    def test_eip_associated_returns_eni(self) -> None:
        ec2 = MagicMock()
        ec2.describe_addresses.return_value = _describe_addresses_associated(
            TARGET_ENI, EIP_ALLOC
        )
        result = self._call(ec2, FAILOVER_CONFIG, MANAGED_TABLES)
        assert result == TARGET_ENI
        ec2.describe_addresses.assert_called_once_with(AllocationIds=[EIP_ALLOC])
        ec2.describe_route_tables.assert_not_called()

    def test_eip_not_associated_single_eni_fallback(self) -> None:
        ec2 = MagicMock()
        ec2.describe_addresses.return_value = _describe_addresses_unassociated()

        # Both tables have routes to the same ENI
        def _describe_rt(RouteTableIds):  # noqa: N803
            rtb = RouteTableIds[0]
            return _describe_route_tables_with_routes(
                rtb,
                routes=[{"DestinationCidrBlock": "192.168.1.0/24", "NetworkInterfaceId": TARGET_ENI}],
            )

        ec2.describe_route_tables.side_effect = _describe_rt

        result = self._call(ec2, FAILOVER_CONFIG, MANAGED_TABLES)
        assert result == TARGET_ENI

    def test_eip_not_associated_multiple_enis_raises(self) -> None:
        ec2 = MagicMock()
        ec2.describe_addresses.return_value = _describe_addresses_unassociated()

        def _describe_rt(RouteTableIds):  # noqa: N803
            rtb = RouteTableIds[0]
            # First table has TARGET_ENI, second has ALT_ENI
            eni = TARGET_ENI if rtb == MANAGED_TABLES[0] else ALT_ENI
            return _describe_route_tables_with_routes(
                rtb,
                routes=[{"DestinationCidrBlock": "192.168.1.0/24", "NetworkInterfaceId": eni}],
            )

        ec2.describe_route_tables.side_effect = _describe_rt

        with pytest.raises(InfrastructureError, match="multiple candidate ENIs"):
            self._call(ec2, FAILOVER_CONFIG, MANAGED_TABLES)

    def test_eip_not_associated_no_enis_raises(self) -> None:
        ec2 = MagicMock()
        ec2.describe_addresses.return_value = _describe_addresses_unassociated()
        ec2.describe_route_tables.return_value = _describe_route_tables_with_routes(
            MANAGED_TABLES[0], routes=[]
        )

        with pytest.raises(InfrastructureError, match="no ENI-targeted routes"):
            self._call(ec2, FAILOVER_CONFIG, MANAGED_TABLES)

    def test_missing_eip_key_raises(self) -> None:
        ec2 = MagicMock()
        with pytest.raises(InfrastructureError, match="eip_allocation_id"):
            self._call(ec2, {}, MANAGED_TABLES)


# ---------------------------------------------------------------------------
# Table validation
# ---------------------------------------------------------------------------


class TestValidateTablesInFailover:
    def _call(self, managed: list[str], failover: dict) -> None:
        from app.services.route_service import _validate_tables_in_failover

        _validate_tables_in_failover(managed, failover)

    def test_all_tables_present(self) -> None:
        self._call(MANAGED_TABLES, FAILOVER_CONFIG)  # should not raise

    def test_missing_table_raises(self) -> None:
        with pytest.raises(ValidationError, match="not in failover"):
            self._call(["rtb-not-in-failover"], FAILOVER_CONFIG)

    def test_subset_ok(self) -> None:
        self._call([MANAGED_TABLES[0]], FAILOVER_CONFIG)  # only first table — OK


# ---------------------------------------------------------------------------
# Write routes — partial failure and retry
# ---------------------------------------------------------------------------


class TestWriteRoutesToTables:
    def _call(
        self,
        ec2: MagicMock,
        tables: list[str],
        cidr: str,
        eni: str,
    ) -> dict:
        from app.services.route_service import _write_routes_to_tables_sync

        return _write_routes_to_tables_sync(ec2, tables, cidr, eni)

    def _empty_rt(self, rtb: str) -> dict:
        return _describe_route_tables_with_routes(rtb, routes=[])

    def test_all_tables_success(self) -> None:
        ec2 = MagicMock()
        ec2.describe_route_tables.side_effect = lambda RouteTableIds: self._empty_rt(RouteTableIds[0])
        ec2.create_route.return_value = {}

        outcomes = self._call(ec2, MANAGED_TABLES, "192.168.1.0/24", TARGET_ENI)

        assert all(v["status"] == "ok" for v in outcomes.values())
        assert ec2.create_route.call_count == len(MANAGED_TABLES)

    def test_first_table_fails_second_succeeds(self) -> None:
        ec2 = MagicMock()
        ec2.describe_route_tables.side_effect = lambda RouteTableIds: self._empty_rt(RouteTableIds[0])

        def _create(RouteTableId, **kwargs):  # noqa: N803
            if RouteTableId == MANAGED_TABLES[0]:
                raise _make_client_error("UnauthorizedOperation")

        ec2.create_route.side_effect = _create

        outcomes = self._call(ec2, MANAGED_TABLES, "192.168.1.0/24", TARGET_ENI)

        assert outcomes[MANAGED_TABLES[0]]["status"] == "failed"
        assert outcomes[MANAGED_TABLES[1]]["status"] == "ok"

    def test_route_already_exists_same_eni(self) -> None:
        ec2 = MagicMock()
        cidr = "192.168.1.0/24"

        def _describe(RouteTableIds):  # noqa: N803
            return _describe_route_tables_with_routes(
                RouteTableIds[0],
                routes=[{"DestinationCidrBlock": cidr, "NetworkInterfaceId": TARGET_ENI}],
            )

        ec2.describe_route_tables.side_effect = _describe

        outcomes = self._call(ec2, MANAGED_TABLES, cidr, TARGET_ENI)

        for v in outcomes.values():
            assert v["status"] == "already_exists_same_target"
        ec2.create_route.assert_not_called()

    def test_route_already_exists_different_eni_fails(self) -> None:
        ec2 = MagicMock()
        cidr = "192.168.1.0/24"

        def _describe(RouteTableIds):  # noqa: N803
            return _describe_route_tables_with_routes(
                RouteTableIds[0],
                routes=[{"DestinationCidrBlock": cidr, "NetworkInterfaceId": ALT_ENI}],
            )

        ec2.describe_route_tables.side_effect = _describe

        outcomes = self._call(ec2, MANAGED_TABLES, cidr, TARGET_ENI)

        for v in outcomes.values():
            assert v["status"] == "failed"
            assert "different ENI" in v["error"]
        ec2.create_route.assert_not_called()

    def test_aws_route_already_exists_error_same_eni(self) -> None:
        """CreateRoute raises RouteAlreadyExists; re-describe shows same ENI → ok."""
        cidr = "192.168.1.0/24"
        ec2 = MagicMock()
        # describe_route_tables: first call returns empty (no route), second call (after race) returns route with same ENI
        call_counts: dict[str, int] = {t: 0 for t in MANAGED_TABLES}

        def _describe(RouteTableIds):  # noqa: N803
            rtb = RouteTableIds[0]
            call_counts[rtb] += 1
            if call_counts[rtb] == 1:
                return _describe_route_tables_with_routes(rtb, routes=[])
            return _describe_route_tables_with_routes(
                rtb, routes=[{"DestinationCidrBlock": cidr, "NetworkInterfaceId": TARGET_ENI}]
            )

        ec2.describe_route_tables.side_effect = _describe
        ec2.create_route.side_effect = _make_client_error("RouteAlreadyExists")

        outcomes = self._call(ec2, MANAGED_TABLES, cidr, TARGET_ENI)
        for v in outcomes.values():
            assert v["status"] == "already_exists_same_target"


# ---------------------------------------------------------------------------
# Delete routes
# ---------------------------------------------------------------------------


class TestDeleteRoutesFromTables:
    def _call(self, ec2: MagicMock, tables: list[str], cidr: str) -> dict:
        from app.services.route_service import _delete_routes_from_tables_sync

        return _delete_routes_from_tables_sync(ec2, tables, cidr)

    def test_all_success(self) -> None:
        ec2 = MagicMock()
        ec2.delete_route.return_value = {}

        outcomes = self._call(ec2, MANAGED_TABLES, "192.168.1.0/24")
        for v in outcomes.values():
            assert v["status"] == "ok"

    def test_route_not_found_counts_as_success(self) -> None:
        ec2 = MagicMock()
        ec2.delete_route.side_effect = _make_client_error("InvalidRoute.NotFound")

        outcomes = self._call(ec2, MANAGED_TABLES, "192.168.1.0/24")
        for v in outcomes.values():
            assert v["status"] == "not_found_ok"

    def test_other_error_fails(self) -> None:
        ec2 = MagicMock()
        ec2.delete_route.side_effect = _make_client_error("UnauthorizedOperation")

        outcomes = self._call(ec2, MANAGED_TABLES, "192.168.1.0/24")
        for v in outcomes.values():
            assert v["status"] == "failed"


# ---------------------------------------------------------------------------
# Outcomes → sync_status
# ---------------------------------------------------------------------------


class TestOutcomesSyncStatus:
    def _call(self, outcomes: dict) -> str:
        from app.services.route_service import _outcomes_sync_status

        return _outcomes_sync_status(outcomes)

    def test_all_ok(self) -> None:
        assert self._call({"rtb-a": {"status": "ok"}, "rtb-b": {"status": "ok"}}) == "synced"

    def test_already_exists_same_target_ok(self) -> None:
        assert (
            self._call({
                "rtb-a": {"status": "already_exists_same_target"},
                "rtb-b": {"status": "ok"},
            })
            == "synced"
        )

    def test_one_failed(self) -> None:
        assert (
            self._call({
                "rtb-a": {"status": "ok"},
                "rtb-b": {"status": "failed", "error": "err"},
            })
            == "failed"
        )

    def test_not_found_ok_counts_as_synced(self) -> None:
        assert self._call({"rtb-a": {"status": "not_found_ok"}}) == "synced"


# ---------------------------------------------------------------------------
# create_route — service integration (mocked AWS + DB)
# ---------------------------------------------------------------------------


class TestCreateRoute:
    """Integration tests for route_service.create_route with mocked AWS/DB."""

    def _make_mock_session(
        self,
        tunnel: MagicMock,
        route: MagicMock | None = None,
        duplicate: MagicMock | None = None,
    ) -> AsyncMock:
        """Build a minimal mock AsyncSession that returns `tunnel` on execute."""
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()

        tunnel_result = MagicMock()
        tunnel_result.scalar_one_or_none.return_value = tunnel

        server_result = MagicMock()
        server_result.scalar_one_or_none.return_value = _mock_server()

        dup_result = MagicMock()
        dup_result.scalar_one_or_none.return_value = duplicate  # None = no dup

        session.execute.side_effect = [
            tunnel_result,  # SELECT tunnel
            server_result,  # SELECT server (for _get_active_server)
            dup_result,     # SELECT route (duplicate check)
        ]

        # session.add should capture the Route object
        def _side_add(obj: object) -> None:
            if isinstance(obj, MagicMock) and hasattr(obj, "sync_status"):
                pass  # MagicMock Route; skip

        session.add.side_effect = None
        return session

    @patch("app.services.route_service.get_client_for_server")
    @patch("app.services.route_service._read_failover_config")
    @patch("app.services.route_service._resolve_target_eni")
    @patch("app.services.route_service._validate_vpc_overlap")
    @patch("app.services.route_service._write_routes_to_tables")
    @patch("app.services.route_service.audit.log_action")
    @patch("app.services.route_service.get_settings")
    async def test_create_success(
        self,
        mock_settings,
        mock_audit,
        mock_write,
        mock_vpc_overlap,
        mock_resolve_eni,
        mock_read_config,
        mock_get_client,
    ) -> None:
        settings = MagicMock()
        settings.strongswan_config_bucket = CONFIG_BUCKET
        settings.managed_route_table_ids = MANAGED_TABLES
        mock_settings.return_value = settings

        tunnel = _mock_tunnel()
        session = AsyncMock()
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        session.refresh = AsyncMock()

        tunnel_result = MagicMock()
        tunnel_result.scalar_one_or_none.return_value = tunnel

        dup_result = MagicMock()
        dup_result.scalar_one_or_none.return_value = None  # no duplicate

        server_result = MagicMock()
        server_result.scalar_one_or_none.return_value = _mock_server()

        # Order: select tunnel → dup check → select server
        session.execute.side_effect = [tunnel_result, dup_result, server_result]

        mock_read_config.return_value = FAILOVER_CONFIG
        mock_resolve_eni.return_value = TARGET_ENI
        mock_vpc_overlap.return_value = None
        mock_write.return_value = {t: {"status": "ok"} for t in MANAGED_TABLES}
        mock_audit.return_value = None

        from app.services import route_service

        route = await route_service.create_route(
            session,
            tunnel_id=1,
            cidr=IPv4Network("192.168.1.0/24"),
            description="test route",
            user=_mock_user(),
        )

        session.commit.assert_awaited_once()
        mock_write.assert_awaited_once()
        mock_audit.assert_awaited_once()

    @patch("app.services.route_service.get_settings")
    async def test_create_disabled_when_no_tables(self, mock_settings) -> None:
        settings = MagicMock()
        settings.managed_route_table_ids = []
        mock_settings.return_value = settings

        from app.services import route_service

        with pytest.raises(ValidationError, match="MANAGED_ROUTE_TABLE_IDS is empty"):
            await route_service.create_route(
                AsyncMock(),
                tunnel_id=1,
                cidr=IPv4Network("192.168.1.0/24"),
                description=None,
                user=_mock_user(),
            )

    @patch("app.services.route_service.get_settings")
    async def test_create_duplicate_raises(self, mock_settings) -> None:
        settings = MagicMock()
        settings.managed_route_table_ids = MANAGED_TABLES
        settings.strongswan_config_bucket = CONFIG_BUCKET
        mock_settings.return_value = settings

        tunnel = _mock_tunnel()
        session = AsyncMock()

        tunnel_result = MagicMock()
        tunnel_result.scalar_one_or_none.return_value = tunnel

        existing_route = _mock_route()
        dup_result = MagicMock()
        dup_result.scalar_one_or_none.return_value = existing_route

        # Order: select tunnel → dup check (finds existing → raises)
        session.execute.side_effect = [tunnel_result, dup_result]

        from app.services import route_service

        with pytest.raises(ConflictError, match="already exists"):
            await route_service.create_route(
                session,
                tunnel_id=1,
                cidr=IPv4Network("192.168.1.0/24"),
                description=None,
                user=_mock_user(),
            )

    @patch("app.services.route_service.get_settings")
    async def test_create_cidr_not_in_remote_raises(self, mock_settings) -> None:
        settings = MagicMock()
        settings.managed_route_table_ids = MANAGED_TABLES
        settings.strongswan_config_bucket = CONFIG_BUCKET
        mock_settings.return_value = settings

        tunnel = _mock_tunnel(remote_cidrs=["192.168.1.0/24"])
        session = AsyncMock()

        tunnel_result = MagicMock()
        tunnel_result.scalar_one_or_none.return_value = tunnel

        # _validate_cidr_rules raises before any further DB calls
        session.execute.side_effect = [tunnel_result]

        from app.services import route_service

        with pytest.raises(ValidationError, match="not inside any"):
            await route_service.create_route(
                session,
                tunnel_id=1,
                cidr=IPv4Network("10.99.0.0/24"),  # not in remote_cidrs
                description=None,
                user=_mock_user(),
            )

    @patch("app.services.route_service.get_settings")
    async def test_create_slash_zero_raises(self, mock_settings) -> None:
        settings = MagicMock()
        settings.managed_route_table_ids = MANAGED_TABLES
        settings.strongswan_config_bucket = CONFIG_BUCKET
        mock_settings.return_value = settings

        tunnel = _mock_tunnel()
        session = AsyncMock()

        tunnel_result = MagicMock()
        tunnel_result.scalar_one_or_none.return_value = tunnel

        # _validate_cidr_rules raises before any further DB calls
        session.execute.side_effect = [tunnel_result]

        from app.services import route_service

        with pytest.raises(ValidationError, match="prefix length 0"):
            await route_service.create_route(
                session,
                tunnel_id=1,
                cidr=IPv4Network("0.0.0.0/0"),
                description=None,
                user=_mock_user(),
            )


# ---------------------------------------------------------------------------
# retry_route — service integration
# ---------------------------------------------------------------------------


class TestRetryRoute:
    @patch("app.services.route_service.get_client_for_server")
    @patch("app.services.route_service._read_failover_config")
    @patch("app.services.route_service._resolve_target_eni")
    @patch("app.services.route_service._write_routes_to_tables")
    @patch("app.services.route_service.audit.log_action")
    @patch("app.services.route_service.get_settings")
    async def test_retry_only_missing_tables(
        self,
        mock_settings,
        mock_audit,
        mock_write,
        mock_resolve_eni,
        mock_read_config,
        mock_get_client,
    ) -> None:
        settings = MagicMock()
        settings.managed_route_table_ids = MANAGED_TABLES
        settings.strongswan_config_bucket = CONFIG_BUCKET
        mock_settings.return_value = settings

        # table[0] already ok, table[1] failed
        route = _mock_route(
            sync_status="failed",
            table_outcomes={
                MANAGED_TABLES[0]: {"status": "ok"},
                MANAGED_TABLES[1]: {"status": "failed", "error": "err"},
            },
        )

        session = AsyncMock()
        route_result = MagicMock()
        route_result.scalar_one_or_none.return_value = route

        server_result = MagicMock()
        server_result.scalar_one_or_none.return_value = _mock_server()

        session.execute.side_effect = [route_result, server_result]
        session.commit = AsyncMock()
        session.refresh = AsyncMock()

        mock_read_config.return_value = FAILOVER_CONFIG
        mock_resolve_eni.return_value = TARGET_ENI
        mock_write.return_value = {MANAGED_TABLES[1]: {"status": "ok"}}
        mock_audit.return_value = None

        from app.services import route_service

        result = await route_service.retry_route(
            session,
            route_id=10,
            user=_mock_user(),
        )

        # Only the failed table should have been retried
        mock_write.assert_awaited_once_with(
            mock_get_client.return_value,
            [MANAGED_TABLES[1]],
            str(route.cidr),
            TARGET_ENI,
        )

    @patch("app.services.route_service.get_settings")
    async def test_retry_non_failed_route_raises(self, mock_settings) -> None:
        settings = MagicMock()
        settings.managed_route_table_ids = MANAGED_TABLES
        settings.strongswan_config_bucket = CONFIG_BUCKET
        mock_settings.return_value = settings

        route = _mock_route(sync_status="synced")

        session = AsyncMock()
        route_result = MagicMock()
        route_result.scalar_one_or_none.return_value = route

        server_result = MagicMock()
        server_result.scalar_one_or_none.return_value = _mock_server()

        session.execute.side_effect = [route_result, server_result]

        from app.services import route_service

        with pytest.raises(ValidationError, match="retry only allowed for 'failed'"):
            await route_service.retry_route(session, route_id=10, user=_mock_user())


# ---------------------------------------------------------------------------
# VPC overlap validation
# ---------------------------------------------------------------------------


class TestValidateVpcOverlap:
    def _call(self, ec2: MagicMock, tables: list[str], cidr: str) -> None:
        from app.services.route_service import _validate_vpc_overlap_sync

        _validate_vpc_overlap_sync(ec2, tables, IPv4Network(cidr))

    def test_non_overlapping_cidr_ok(self) -> None:
        ec2 = MagicMock()
        ec2.describe_route_tables.return_value = _describe_route_tables_with_routes(
            MANAGED_TABLES[0], vpc_id="vpc-00001111"
        )
        ec2.describe_vpcs.return_value = _describe_vpcs("10.0.0.0/8")

        # 192.168.1.0/24 does not overlap 10.0.0.0/8 — should not raise
        self._call(ec2, MANAGED_TABLES, "192.168.1.0/24")

    def test_overlapping_cidr_raises(self) -> None:
        ec2 = MagicMock()
        ec2.describe_route_tables.return_value = _describe_route_tables_with_routes(
            MANAGED_TABLES[0], vpc_id="vpc-00001111"
        )
        # VPC uses 10.0.0.0/8 — a 10.x.x.x route would overlap
        ec2.describe_vpcs.return_value = _describe_vpcs("10.0.0.0/8")

        with pytest.raises(ValidationError, match="overlaps VPC CIDR"):
            self._call(ec2, MANAGED_TABLES, "10.100.0.0/16")


# ---------------------------------------------------------------------------
# Role enforcement via HTTP router (operator required for writes)
# ---------------------------------------------------------------------------


class TestRouteRoleEnforcement:
    """Viewer gets 403 on all write endpoints; operator is allowed through."""

    async def _get_client(self, role: str = "viewer"):
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        import httpx

        user = _mock_user(role=role)

        async def _override_get_db():
            yield AsyncMock()

        async def _override_get_current_user():
            return user

        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides[get_current_user] = _override_get_current_user

        transport = httpx.ASGITransport(app=app)
        return httpx.AsyncClient(transport=transport, base_url="http://test")

    async def test_viewer_cannot_create_route(self) -> None:
        import httpx

        async with await self._get_client(role="viewer") as client:
            resp = await client.post(
                "/api/v1/routes/",
                params={"tunnel_id": 1},
                json={"cidr": "192.168.1.0/24"},
            )
        assert resp.status_code == 403

    async def test_viewer_cannot_delete_route(self) -> None:
        import httpx

        async with await self._get_client(role="viewer") as client:
            resp = await client.delete("/api/v1/routes/1")
        assert resp.status_code == 403

    async def test_viewer_cannot_retry_route(self) -> None:
        import httpx

        async with await self._get_client(role="viewer") as client:
            resp = await client.post("/api/v1/routes/1/retry")
        assert resp.status_code == 403

    async def test_viewer_cannot_create_via_tunnel(self) -> None:
        import httpx

        async with await self._get_client(role="viewer") as client:
            resp = await client.post(
                "/api/v1/tunnels/1/routes",
                json={"cidr": "192.168.1.0/24"},
            )
        assert resp.status_code == 403

    @patch("app.services.route_service.create_route", new_callable=AsyncMock)
    @patch("app.services.route_service.get_settings")
    async def test_operator_can_create_route(self, mock_settings, mock_create) -> None:
        import httpx

        settings = MagicMock()
        settings.managed_route_table_ids = MANAGED_TABLES
        settings.strongswan_config_bucket = CONFIG_BUCKET
        mock_settings.return_value = settings

        # create_route is fully mocked — returns a Route-like mock
        created = _mock_route(sync_status="synced")
        mock_create.return_value = created

        async with await self._get_client(role="operator") as client:
            resp = await client.post(
                "/api/v1/routes/",
                params={"tunnel_id": 1},
                json={"cidr": "192.168.1.0/24"},
            )
        # The mocked create_route doesn't go through the router's dependency on
        # the actual service (we patched the module-level function), so we just
        # verify auth passed (not 403).
        assert resp.status_code != 403
