"""Tests for the MissingGreenlet fix — session.refresh() after commit.

Root cause: TimestampMixin uses ``onupdate=func.now()`` for ``updated_at``.
After SQLAlchemy flushes an UPDATE, the column is marked as requiring a DB
fetch (the SQL expression result is unknown to Python). ``expire_on_commit=False``
does NOT un-expire these server-computed columns, so accessing ``updated_at``
after commit triggers a lazy-load that raises ``MissingGreenlet`` in async
context.

The fix is to call ``await session.refresh(obj)`` after ``await session.commit()``
in every service function that returns an ORM object whose schema exposes
``updated_at``.

Affected service functions (before fix):
  - server_service.create_server
  - server_service.update_server
  - iptables_service.create_rule
  - iptables_service.update_rule
  - iptables_service.retry_rule

Each test below asserts that ``session.refresh(obj)`` is called AFTER
``session.commit()`` and before the service function returns. Without the fix
``session.refresh`` is never called and the assertions fail.
"""
from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, call, patch

import pytest

from app.db.models import IPTablesRule, Server


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dt() -> datetime:
    return datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)


def _make_mock_user(role: str = "admin") -> MagicMock:
    user = MagicMock()
    user.id = 1
    user.email = "admin@test.com"
    user.role = role
    return user


def _make_mock_session() -> AsyncMock:
    """Return a mock AsyncSession with commit and refresh as awaitable mocks."""
    session = AsyncMock()
    session.commit = AsyncMock()
    session.refresh = AsyncMock()
    session.flush = AsyncMock()
    session.add = MagicMock()
    return session


def _make_server_mock() -> MagicMock:
    """Server-like mock with all attributes needed by server_service internals."""
    s = MagicMock(spec=Server)
    s.id = 42
    s.name = "vpn-test"
    s.connection_type = "ssh"
    s.hostname = "10.0.0.1"
    s.ssh_port = 22
    s.ssh_user = "admin"
    s.ssh_private_key_encrypted = "encrypted-key"
    s.description = "test"
    s.is_active = True
    s.last_check_at = None
    s.last_check_status = None
    s.ec2_instance_id = None
    s.aws_role_arn = None
    s.aws_region_override = None
    s.deleted_at = None
    s.created_by = 1
    s.created_at = _dt()
    s.updated_at = _dt()
    return s


def _make_rule_mock() -> MagicMock:
    """IPTablesRule-like mock with all attributes needed by iptables_service."""
    r = MagicMock(spec=IPTablesRule)
    r.id = 7
    r.tunnel_id = 1
    r.chain = "FORWARD"
    r.protocol = "tcp"
    r.source_cidr = None
    r.dest_cidr = None
    r.sport = None
    r.dport = 443
    r.action = "ACCEPT"
    r.state_match = None
    r.comment = None
    r.position = None
    r.sync_status = "pending"
    r.sync_error = None
    r.created_by = 1
    r.deleted_at = None
    r.created_at = _dt()
    r.updated_at = _dt()
    return r


# ---------------------------------------------------------------------------
# server_service.create_server — refresh required for created_at / updated_at
# ---------------------------------------------------------------------------

class TestCreateServerRefresh:
    """create_server must call session.refresh(server) after commit.

    create_server uses select(Server.id) for uniqueness check, which requires
    a real Server class with SQLAlchemy column descriptors. We mock the
    session.execute() result to return None (no existing server) instead of
    patching the Server class itself.
    """

    async def test_refresh_called_after_commit(self):
        from app.schemas.server import ServerCreate
        from app.services import server_service

        session = _make_mock_session()
        user = _make_mock_user()

        # session.execute returns None for uniqueness check (no conflict)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=mock_result)

        with (
            patch(
                "app.services.server_service.validate_ssh_private_key",
            ),
            patch(
                "app.services.server_service.encrypt_ssh_key",
                return_value="encrypted-key",
            ),
            patch(
                "app.services.audit.log_action",
                new_callable=AsyncMock,
            ),
        ):
            data = ServerCreate(
                name="vpn-test",
                hostname="10.0.0.1",
                ssh_private_key="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
            )
            result = await server_service.create_server(session, data=data, user=user)

        # The fix: refresh must be called with the created server
        session.refresh.assert_called_once()
        # The single arg to refresh must be the returned server object
        assert session.refresh.call_args[0][0] is result

    async def test_refresh_called_after_commit_ordering(self):
        """session.refresh must be called AFTER session.commit, not before."""
        from app.schemas.server import ServerCreate
        from app.services import server_service

        session = _make_mock_session()
        user = _make_mock_user()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        session.execute = AsyncMock(return_value=mock_result)

        with (
            patch("app.services.server_service.validate_ssh_private_key"),
            patch("app.services.server_service.encrypt_ssh_key", return_value="enc"),
            patch("app.services.audit.log_action", new_callable=AsyncMock),
        ):
            data = ServerCreate(
                name="vpn-test",
                hostname="10.0.0.1",
                ssh_private_key="-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----",
            )
            await server_service.create_server(session, data=data, user=user)

        calls = session.mock_calls
        call_names = [str(c) for c in calls]
        commit_idx = next(i for i, n in enumerate(call_names) if "commit" in n)
        refresh_idx = next(i for i, n in enumerate(call_names) if "refresh" in n)
        assert refresh_idx > commit_idx, (
            "session.refresh() must be called AFTER session.commit()"
        )


# ---------------------------------------------------------------------------
# server_service.update_server — the confirmed-failing endpoint
# ---------------------------------------------------------------------------

class TestUpdateServerRefresh:
    """update_server must call session.refresh(server) after commit.

    This is the endpoint that produced the reported 500 error:
      MissingGreenlet: greenlet_spawn has not been called; can't call await_only()
    """

    async def test_refresh_called_after_commit(self):
        from app.schemas.server import ServerUpdate
        from app.services import server_service

        session = _make_mock_session()
        server = _make_server_mock()
        user = _make_mock_user()

        with (
            patch(
                "app.services.server_service.get_server",
                new_callable=AsyncMock,
                return_value=server,
            ),
            patch(
                "app.services.audit.log_action",
                new_callable=AsyncMock,
            ),
        ):
            data = ServerUpdate(hostname="10.0.0.2")
            await server_service.update_server(session, 42, data=data, user=user)

        # Without the fix this assertion fails: refresh is never called
        session.refresh.assert_called_once_with(server)

    async def test_refresh_after_commit_ordering(self):
        """refresh must come after commit in the call sequence."""
        from app.schemas.server import ServerUpdate
        from app.services import server_service

        session = _make_mock_session()
        server = _make_server_mock()
        user = _make_mock_user()

        with (
            patch("app.services.server_service.get_server", new_callable=AsyncMock, return_value=server),
            patch("app.services.audit.log_action", new_callable=AsyncMock),
        ):
            data = ServerUpdate(hostname="10.0.0.2")
            await server_service.update_server(session, 42, data=data, user=user)

        calls = session.mock_calls
        call_names = [str(c) for c in calls]
        commit_idx = next(i for i, n in enumerate(call_names) if "commit" in n)
        refresh_idx = next(i for i, n in enumerate(call_names) if "refresh" in n)
        assert refresh_idx > commit_idx, (
            "session.refresh() must be called AFTER session.commit() in update_server"
        )

    async def test_returned_server_is_the_refreshed_object(self):
        """update_server must return the same object passed to refresh."""
        from app.schemas.server import ServerUpdate
        from app.services import server_service

        session = _make_mock_session()
        server = _make_server_mock()
        user = _make_mock_user()

        with (
            patch("app.services.server_service.get_server", new_callable=AsyncMock, return_value=server),
            patch("app.services.audit.log_action", new_callable=AsyncMock),
        ):
            data = ServerUpdate(hostname="10.0.0.2")
            result = await server_service.update_server(session, 42, data=data, user=user)

        assert result is server
        # And the refresh was called with that same object
        session.refresh.assert_called_once_with(server)


# ---------------------------------------------------------------------------
# iptables_service.create_rule
# ---------------------------------------------------------------------------

class TestCreateIPTablesRuleRefresh:
    """create_rule must call session.refresh(rule) after commit.

    create_rule uses _get_active_tunnel (private helper) for tunnel lookup.
    We patch that private function directly and let the real IPTablesRule
    constructor run (no DB binding needed since session.add/flush are mocked).
    """

    async def test_refresh_called_after_commit(self):
        from app.schemas.iptables import IPTablesRuleCreate
        from app.services import iptables_service

        session = _make_mock_session()
        user = _make_mock_user()

        with (
            patch(
                "app.services.iptables_service._get_active_tunnel",
                new_callable=AsyncMock,
                return_value=MagicMock(id=1, deleted_at=None),
            ),
            patch(
                "app.services.iptables_service.require_lock",
                new_callable=AsyncMock,
            ),
            patch(
                "app.services.iptables_service.ssm.run_on_instances",
                new_callable=AsyncMock,
            ),
            patch(
                "app.services.audit.log_action",
                new_callable=AsyncMock,
            ),
        ):
            data = IPTablesRuleCreate(
                chain="FORWARD",
                protocol="tcp",
                dport=443,
                action="ACCEPT",
            )
            result = await iptables_service.create_rule(session, tunnel_id=1, data=data, user=user)

        # The fix: refresh must be called with the created rule
        session.refresh.assert_called_once()
        assert session.refresh.call_args[0][0] is result

    async def test_refresh_after_commit_ordering(self):
        from app.schemas.iptables import IPTablesRuleCreate
        from app.services import iptables_service

        session = _make_mock_session()
        user = _make_mock_user()

        with (
            patch("app.services.iptables_service._get_active_tunnel", new_callable=AsyncMock, return_value=MagicMock(id=1, deleted_at=None)),
            patch("app.services.iptables_service.require_lock", new_callable=AsyncMock),
            patch("app.services.iptables_service.ssm.run_on_instances", new_callable=AsyncMock),
            patch("app.services.audit.log_action", new_callable=AsyncMock),
        ):
            data = IPTablesRuleCreate(chain="FORWARD", protocol="tcp", dport=443, action="ACCEPT")
            await iptables_service.create_rule(session, tunnel_id=1, data=data, user=user)

        calls = session.mock_calls
        call_names = [str(c) for c in calls]
        commit_idx = next(i for i, n in enumerate(call_names) if "commit" in n)
        refresh_idx = next(i for i, n in enumerate(call_names) if "refresh" in n)
        assert refresh_idx > commit_idx


# ---------------------------------------------------------------------------
# iptables_service.update_rule
# ---------------------------------------------------------------------------

class TestUpdateIPTablesRuleRefresh:
    """update_rule must call session.refresh(rule) after commit."""

    async def test_refresh_called_after_commit(self):
        from app.schemas.iptables import IPTablesRuleUpdate
        from app.services import iptables_service

        session = _make_mock_session()
        rule = _make_rule_mock()
        user = _make_mock_user()

        with (
            patch(
                "app.services.iptables_service.get_rule",
                new_callable=AsyncMock,
                return_value=rule,
            ),
            patch(
                "app.services.iptables_service.require_lock",
                new_callable=AsyncMock,
            ),
            patch(
                "app.services.iptables_service.ssm.run_on_instances",
                new_callable=AsyncMock,
            ),
            patch(
                "app.services.audit.log_action",
                new_callable=AsyncMock,
            ),
        ):
            data = IPTablesRuleUpdate(comment="updated-comment")
            await iptables_service.update_rule(session, 7, data=data, user=user)

        session.refresh.assert_called_once_with(rule)

    async def test_refresh_after_commit_ordering(self):
        from app.schemas.iptables import IPTablesRuleUpdate
        from app.services import iptables_service

        session = _make_mock_session()
        rule = _make_rule_mock()
        user = _make_mock_user()

        with (
            patch("app.services.iptables_service.get_rule", new_callable=AsyncMock, return_value=rule),
            patch("app.services.iptables_service.require_lock", new_callable=AsyncMock),
            patch("app.services.iptables_service.ssm.run_on_instances", new_callable=AsyncMock),
            patch("app.services.audit.log_action", new_callable=AsyncMock),
        ):
            data = IPTablesRuleUpdate(comment="updated")
            await iptables_service.update_rule(session, 7, data=data, user=user)

        calls = session.mock_calls
        call_names = [str(c) for c in calls]
        commit_idx = next(i for i, n in enumerate(call_names) if "commit" in n)
        refresh_idx = next(i for i, n in enumerate(call_names) if "refresh" in n)
        assert refresh_idx > commit_idx


# ---------------------------------------------------------------------------
# iptables_service.retry_rule
# ---------------------------------------------------------------------------

class TestRetryIPTablesRuleRefresh:
    """retry_rule must call session.refresh(rule) after commit."""

    async def test_refresh_called_after_commit(self):
        from app.services import iptables_service

        session = _make_mock_session()
        rule = _make_rule_mock()
        rule.sync_status = "failed"
        user = _make_mock_user()

        with (
            patch(
                "app.services.iptables_service.get_rule",
                new_callable=AsyncMock,
                return_value=rule,
            ),
            patch(
                "app.services.iptables_service.require_lock",
                new_callable=AsyncMock,
            ),
            patch(
                "app.services.iptables_service.ssm.run_on_instances",
                new_callable=AsyncMock,
            ),
            patch(
                "app.services.audit.log_action",
                new_callable=AsyncMock,
            ),
        ):
            await iptables_service.retry_rule(session, 7, user=user)

        session.refresh.assert_called_once_with(rule)

    async def test_refresh_after_commit_ordering(self):
        from app.services import iptables_service

        session = _make_mock_session()
        rule = _make_rule_mock()
        rule.sync_status = "failed"
        user = _make_mock_user()

        with (
            patch("app.services.iptables_service.get_rule", new_callable=AsyncMock, return_value=rule),
            patch("app.services.iptables_service.require_lock", new_callable=AsyncMock),
            patch("app.services.iptables_service.ssm.run_on_instances", new_callable=AsyncMock),
            patch("app.services.audit.log_action", new_callable=AsyncMock),
        ):
            await iptables_service.retry_rule(session, 7, user=user)

        calls = session.mock_calls
        call_names = [str(c) for c in calls]
        commit_idx = next(i for i, n in enumerate(call_names) if "commit" in n)
        refresh_idx = next(i for i, n in enumerate(call_names) if "refresh" in n)
        assert refresh_idx > commit_idx


# ---------------------------------------------------------------------------
# Router-level: update_server returns 200 with updated_at in response body
# ---------------------------------------------------------------------------

class TestUpdateServerRouterResponse:
    """PATCH /api/v1/servers/{id} must return 200 with updated_at in the body.

    This is the exact endpoint that returned 500 in production. The test
    verifies the full contract: 200 status + JSON body includes updated_at.
    """

    async def test_update_returns_updated_at(self):
        """PATCH /api/v1/servers/{id} response includes updated_at timestamp."""
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        now = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        server = MagicMock()
        server.id = 1
        server.name = "vpn-primary"
        server.connection_type = "ssh"
        server.hostname = "10.0.1.51"
        server.ssh_port = 22
        server.ssh_user = "admin"
        server.description = None
        server.is_active = True
        server.last_check_at = None
        server.last_check_status = None
        server.ec2_instance_id = None
        server.aws_role_arn = None
        server.aws_region_override = None
        server.ssh_private_key_encrypted = "encrypted"
        server.deleted_at = None
        server.created_by = 1
        server.created_at = now
        server.updated_at = now

        mock_user = MagicMock()
        mock_user.id = 1
        mock_user.role = "admin"
        mock_user.is_active = True

        with patch(
            "app.services.server_service.update_server",
            new_callable=AsyncMock,
            return_value=server,
        ):
            async def _override_get_db():
                yield AsyncMock()

            async def _override_get_current_user():
                return mock_user

            app.dependency_overrides[get_db] = _override_get_db
            app.dependency_overrides[get_current_user] = _override_get_current_user

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.patch(
                    "/api/v1/servers/1",
                    json={"hostname": "10.0.1.51"},
                )

            app.dependency_overrides.clear()

        assert resp.status_code == 200
        body = resp.json()
        assert "updated_at" in body, "updated_at must be present in ServerDetail response"
        assert body["updated_at"] is not None
        assert body["hostname"] == "10.0.1.51"

    async def test_create_server_returns_updated_at(self):
        """POST /api/v1/servers/ response includes updated_at timestamp."""
        import httpx
        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        now = datetime(2024, 6, 15, 12, 0, 0, tzinfo=timezone.utc)
        server = MagicMock()
        server.id = 1
        server.name = "vpn-new"
        server.connection_type = "ssh"
        server.hostname = "10.0.1.50"
        server.ssh_port = 22
        server.ssh_user = "admin"
        server.description = None
        server.is_active = True
        server.last_check_at = None
        server.last_check_status = None
        server.ec2_instance_id = None
        server.aws_role_arn = None
        server.aws_region_override = None
        server.ssh_private_key_encrypted = "encrypted"
        server.deleted_at = None
        server.created_by = 1
        server.created_at = now
        server.updated_at = now

        mock_user = MagicMock()
        mock_user.id = 1
        mock_user.role = "admin"
        mock_user.is_active = True

        with patch(
            "app.services.server_service.create_server",
            new_callable=AsyncMock,
            return_value=server,
        ):
            async def _override_get_db():
                yield AsyncMock()

            async def _override_get_current_user():
                return mock_user

            app.dependency_overrides[get_db] = _override_get_db
            app.dependency_overrides[get_current_user] = _override_get_current_user

            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                resp = await client.post(
                    "/api/v1/servers/",
                    json={
                        "name": "vpn-new",
                        "hostname": "10.0.1.50",
                        "ssh_private_key": (
                            "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----"
                        ),
                    },
                )

            app.dependency_overrides.clear()

        assert resp.status_code == 201
        body = resp.json()
        assert "updated_at" in body
        assert body["updated_at"] is not None
