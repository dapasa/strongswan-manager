"""Tests for session revocation — iat claim, tokens_valid_after check, endpoints.

Covers:
- iat claim is present in tokens issued by create_access_token
- Token whose iat < tokens_valid_after → 401
- Token whose iat >= tokens_valid_after → 200
- Admin POST /users/{id}/revoke-sessions → 200
- Non-admin POST /users/{id}/revoke-sessions → 403
- POST /auth/logout-all for any authenticated user → 200
- Migration 0016 imports cleanly
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

os.environ.setdefault("AUTH_MODE", "local")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only-not-for-production")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_user(
    role: str = "admin",
    user_id: int = 1,
    tokens_valid_after: datetime | None = None,
) -> MagicMock:
    from app.db.models import User

    user = MagicMock(spec=User)
    user.id = user_id
    user.sub = f"local:{role}@test.com"
    user.email = f"{role}@test.com"
    user.display_name = f"Test {role.capitalize()}"
    user.role = role
    user.is_active = True
    user.tokens_valid_after = tokens_valid_after
    user.last_login_at = None
    user.created_at = datetime.now(timezone.utc)
    user.shortcut_member_id = None
    return user


async def _get_client(user: MagicMock | None = None) -> httpx.AsyncClient:
    """Build an async client with auth + db overrides."""
    from app.auth.dependencies import get_current_user
    from app.db.session import get_db
    from app.main import app

    mock_user = user or _make_mock_user()

    async def _override_get_db():
        yield AsyncMock()

    async def _override_get_current_user():
        return mock_user

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides[get_current_user] = _override_get_current_user

    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


# ---------------------------------------------------------------------------
# iat claim
# ---------------------------------------------------------------------------


class TestIatClaim:
    def test_iat_present_in_new_token(self):
        """create_access_token must include an 'iat' claim."""
        from app.auth.local import create_access_token, decode_access_token
        from app.config import get_settings

        get_settings.cache_clear()
        with patch.dict(
            os.environ,
            {
                "AUTH_MODE": "local",
                "JWT_SECRET_KEY": "test-secret-key-for-testing-only-not-for-production",
                "JWT_EXPIRE_MINUTES": "60",
            },
        ):
            get_settings.cache_clear()
            token = create_access_token(user_id=1, sub="local:test@test.com", role="viewer")
            payload = decode_access_token(token)

        assert "iat" in payload, "iat claim must be present"
        assert isinstance(payload["iat"], int), "iat must be an epoch-seconds integer"
        get_settings.cache_clear()

    def test_iat_is_close_to_now(self):
        """iat must be within a few seconds of the current time."""
        from app.auth.local import create_access_token, decode_access_token
        from app.config import get_settings

        get_settings.cache_clear()
        with patch.dict(
            os.environ,
            {
                "AUTH_MODE": "local",
                "JWT_SECRET_KEY": "test-secret-key-for-testing-only-not-for-production",
                "JWT_EXPIRE_MINUTES": "60",
            },
        ):
            get_settings.cache_clear()
            before = int(datetime.now(timezone.utc).timestamp())
            token = create_access_token(user_id=1, sub="local:test@test.com", role="viewer")
            after = int(datetime.now(timezone.utc).timestamp())
            payload = decode_access_token(token)

        assert before <= payload["iat"] <= after + 1
        get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Session revocation check in get_current_user
# ---------------------------------------------------------------------------


class TestRevocationCheck:
    def _make_token_with_iat(self, iat_dt: datetime) -> str:
        """Craft a valid local token with a specific iat datetime."""
        from jose import jwt

        payload = {
            "sub": "local:test@test.com",
            "uid": 1,
            "role": "viewer",
            "iat": iat_dt,
            "exp": datetime.now(timezone.utc) + timedelta(hours=8),
        }
        return jwt.encode(
            payload,
            "test-secret-key-for-testing-only-not-for-production",
            algorithm="HS256",
        )

    async def test_token_before_revocation_returns_401(self):
        """A token with iat earlier than tokens_valid_after must be rejected."""
        from app.config import get_settings

        get_settings.cache_clear()

        revoke_time = datetime.now(timezone.utc)
        # Token issued 10 minutes before revocation
        old_iat = revoke_time - timedelta(minutes=10)
        old_token = self._make_token_with_iat(old_iat)

        mock_user = _make_mock_user(tokens_valid_after=revoke_time)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        async def _override_get_db():
            yield mock_db

        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides.pop(get_current_user, None)

        try:
            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "local",
                    "JWT_SECRET_KEY": "test-secret-key-for-testing-only-not-for-production",
                },
            ):
                get_settings.cache_clear()
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    resp = await client.get(
                        "/api/v1/auth/me",
                        headers={"Authorization": f"Bearer {old_token}"},
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides[get_current_user] = lambda: mock_user
            get_settings.cache_clear()

        assert resp.status_code == 401
        assert "revoked" in resp.json()["detail"].lower()

    async def test_token_after_revocation_returns_200(self):
        """A token with iat >= tokens_valid_after must be accepted."""
        from app.config import get_settings

        get_settings.cache_clear()

        # Revocation happened 10 minutes ago; token is fresh
        revoke_time = datetime.now(timezone.utc) - timedelta(minutes=10)
        new_iat = datetime.now(timezone.utc)
        new_token = self._make_token_with_iat(new_iat)

        mock_user = _make_mock_user(tokens_valid_after=revoke_time)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        async def _override_get_db():
            yield mock_db

        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides.pop(get_current_user, None)

        try:
            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "local",
                    "JWT_SECRET_KEY": "test-secret-key-for-testing-only-not-for-production",
                },
            ):
                get_settings.cache_clear()
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    resp = await client.get(
                        "/api/v1/auth/me",
                        headers={"Authorization": f"Bearer {new_token}"},
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides[get_current_user] = lambda: mock_user
            get_settings.cache_clear()

        assert resp.status_code == 200

    async def test_no_revocation_set_accepts_any_token(self):
        """When tokens_valid_after is None, all valid tokens are accepted."""
        from app.config import get_settings

        get_settings.cache_clear()

        old_iat = datetime.now(timezone.utc) - timedelta(hours=24)
        old_token = self._make_token_with_iat(old_iat)

        mock_user = _make_mock_user(tokens_valid_after=None)
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        async def _override_get_db():
            yield mock_db

        app.dependency_overrides[get_db] = _override_get_db
        app.dependency_overrides.pop(get_current_user, None)

        try:
            with patch.dict(
                os.environ,
                {
                    "AUTH_MODE": "local",
                    "JWT_SECRET_KEY": "test-secret-key-for-testing-only-not-for-production",
                },
            ):
                get_settings.cache_clear()
                transport = httpx.ASGITransport(app=app)
                async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                    resp = await client.get(
                        "/api/v1/auth/me",
                        headers={"Authorization": f"Bearer {old_token}"},
                    )
        finally:
            app.dependency_overrides.pop(get_db, None)
            app.dependency_overrides[get_current_user] = lambda: mock_user
            get_settings.cache_clear()

        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Admin revoke-sessions endpoint RBAC
# ---------------------------------------------------------------------------


class TestAdminRevokeSessionsEndpoint:
    @patch("app.services.user_service.revoke_user_sessions", new_callable=AsyncMock)
    async def test_admin_can_revoke_sessions(self, mock_revoke):
        """Admin can call POST /users/{id}/revoke-sessions."""
        now = datetime.now(timezone.utc)
        target_user = MagicMock()
        target_user.id = 2
        target_user.email = "viewer@test.com"
        target_user.display_name = "Test Viewer"
        target_user.role = "viewer"
        target_user.is_active = True
        target_user.last_login_at = now
        target_user.created_at = now
        target_user.shortcut_member_id = None
        mock_revoke.return_value = target_user

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.post("/api/v1/users/2/revoke-sessions")

        assert resp.status_code == 200
        mock_revoke.assert_called_once()

    async def test_operator_cannot_revoke_sessions(self):
        """Operator cannot call POST /users/{id}/revoke-sessions."""
        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.post("/api/v1/users/2/revoke-sessions")
        assert resp.status_code == 403

    async def test_viewer_cannot_revoke_sessions(self):
        """Viewer cannot call POST /users/{id}/revoke-sessions."""
        viewer = _make_mock_user("viewer", user_id=4)
        client = await _get_client(viewer)
        async with client:
            resp = await client.post("/api/v1/users/2/revoke-sessions")
        assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Self-service logout-all endpoint
# ---------------------------------------------------------------------------


class TestLogoutAll:
    @patch("app.services.user_service.revoke_user_sessions", new_callable=AsyncMock)
    async def test_any_user_can_logout_all(self, mock_revoke):
        """Any authenticated user can call POST /auth/logout-all."""
        now = datetime.now(timezone.utc)
        viewer = _make_mock_user("viewer", user_id=5)
        viewer.created_at = now
        mock_revoke.return_value = viewer

        client = await _get_client(viewer)
        async with client:
            resp = await client.post("/api/v1/auth/logout-all")

        assert resp.status_code == 200
        mock_revoke.assert_called_once()

    @patch("app.services.user_service.revoke_user_sessions", new_callable=AsyncMock)
    async def test_admin_can_logout_all(self, mock_revoke):
        """Admin can also call POST /auth/logout-all for self."""
        now = datetime.now(timezone.utc)
        admin = _make_mock_user("admin", user_id=1)
        admin.created_at = now
        mock_revoke.return_value = admin

        client = await _get_client(admin)
        async with client:
            resp = await client.post("/api/v1/auth/logout-all")

        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# Migration import sanity
# ---------------------------------------------------------------------------


class TestMigrationImport:
    def test_migration_0016_imports_cleanly(self):
        """Migration 0016 must import without errors."""
        import importlib.util
        import pathlib

        path = (
            pathlib.Path(__file__).parent.parent
            / "alembic"
            / "versions"
            / "0016_add_tokens_valid_after.py"
        )
        spec = importlib.util.spec_from_file_location("migration_0016", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)

        assert hasattr(mod, "upgrade")
        assert hasattr(mod, "downgrade")
        assert mod.revision == "0016"
        assert mod.down_revision == "0015"
