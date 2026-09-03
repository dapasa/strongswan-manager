"""Tests for local authentication — password hashing, JWT, login endpoint."""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

# Ensure test env is set before any app import
os.environ.setdefault("AUTH_MODE", "local")
os.environ.setdefault("JWT_SECRET_KEY", "test-secret-key-for-testing-only-not-for-production")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_mock_user(role: str = "admin", email: str = "admin@test.com", user_id: int = 1, active: bool = True):
    from app.db.models import User

    user = MagicMock(spec=User)
    user.id = user_id
    user.sub = f"local:{email}"
    user.email = email
    user.display_name = "Test User"
    user.role = role
    user.is_active = active
    user.last_login_at = None
    return user


async def _get_local_client(user=None):
    """Build an async client with local-auth overrides (no real DB)."""
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
# Password helpers
# ---------------------------------------------------------------------------


class TestPasswordHelpers:
    def test_hash_and_verify_roundtrip(self):
        from app.auth.local import hash_password, verify_password

        h = hash_password("SuperSecret123!")
        assert verify_password("SuperSecret123!", h)

    def test_wrong_password_fails(self):
        from app.auth.local import hash_password, verify_password

        h = hash_password("correct")
        assert not verify_password("wrong", h)

    def test_hash_is_salted(self):
        from app.auth.local import hash_password

        h1 = hash_password("same")
        h2 = hash_password("same")
        # argon2id produces different hashes for the same input due to random salt
        assert h1 != h2

    def test_hash_not_plain_text(self):
        from app.auth.local import hash_password

        h = hash_password("mypassword")
        assert "mypassword" not in h


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


class TestJWTHelpers:
    def test_create_and_decode_roundtrip(self):
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
            token = create_access_token(user_id=42, sub="local:user@example.com", role="admin")
            payload = decode_access_token(token)

        assert payload["sub"] == "local:user@example.com"
        assert payload["uid"] == 42
        assert payload["role"] == "admin"
        get_settings.cache_clear()

    def test_expired_token_raises(self):
        from jose import jwt

        from app.auth.local import decode_access_token
        from app.exceptions import AuthenticationError

        # Craft an already-expired token
        payload = {
            "sub": "local:x@x.com",
            "uid": 1,
            "role": "viewer",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
        }
        token = jwt.encode(payload, "test-secret-key-for-testing-only-not-for-production", algorithm="HS256")

        with patch.dict(
            os.environ,
            {
                "AUTH_MODE": "local",
                "JWT_SECRET_KEY": "test-secret-key-for-testing-only-not-for-production",
            },
        ):
            from app.config import get_settings
            get_settings.cache_clear()
            with pytest.raises(AuthenticationError, match="expired"):
                decode_access_token(token)
            get_settings.cache_clear()

    def test_invalid_token_raises(self):
        from app.auth.local import decode_access_token
        from app.exceptions import AuthenticationError

        with patch.dict(
            os.environ,
            {
                "AUTH_MODE": "local",
                "JWT_SECRET_KEY": "test-secret-key-for-testing-only-not-for-production",
            },
        ):
            from app.config import get_settings
            get_settings.cache_clear()
            with pytest.raises(AuthenticationError):
                decode_access_token("not.a.valid.token")
            get_settings.cache_clear()


# ---------------------------------------------------------------------------
# Login endpoint tests (mocked DB — no real PostgreSQL needed)
# ---------------------------------------------------------------------------


class TestLoginEndpoint:
    async def test_valid_credentials_returns_token(self):
        """POST /api/v1/auth/token with correct credentials returns a token."""
        from app.auth.local import hash_password
        from app.config import get_settings

        get_settings.cache_clear()

        mock_user = _make_mock_user(role="admin", email="logintest@example.com", user_id=10)
        mock_user.password_hash = hash_password("ValidPass123!")

        # Patch DB execute to return the user
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)
        mock_db.commit = AsyncMock()
        mock_db.add = MagicMock()

        from app.auth.dependencies import get_current_user
        from app.db.session import get_db
        from app.main import app

        async def _override_get_db():
            yield mock_db

        app.dependency_overrides[get_db] = _override_get_db
        # Remove get_current_user override so the login endpoint uses the real flow
        app.dependency_overrides.pop(get_current_user, None)

        try:
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/auth/token",
                    json={"username": "logintest@example.com", "password": "ValidPass123!"},
                )
            assert response.status_code == 200, response.text
            data = response.json()
            assert "access_token" in data
            assert data["token_type"] == "bearer"
        finally:
            app.dependency_overrides.clear()
            get_settings.cache_clear()

    async def test_wrong_password_returns_401(self):
        """POST /api/v1/auth/token with wrong password returns 401."""
        from app.auth.local import hash_password
        from app.config import get_settings

        get_settings.cache_clear()

        mock_user = _make_mock_user(role="viewer", email="wrongpass@example.com")
        mock_user.password_hash = hash_password("CorrectPass123!")

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
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/auth/token",
                    json={"username": "wrongpass@example.com", "password": "WrongPass!"},
                )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()
            get_settings.cache_clear()

    async def test_unknown_user_returns_401(self):
        """POST /api/v1/auth/token with non-existent user returns 401."""
        from app.config import get_settings

        get_settings.cache_clear()

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
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
            transport = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
                response = await client.post(
                    "/api/v1/auth/token",
                    json={"username": "nobody@nowhere.com", "password": "whatever"},
                )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()
            get_settings.cache_clear()

    async def test_inactive_user_returns_401(self):
        """POST /api/v1/auth/token for an inactive user returns 401."""
        from app.auth.local import hash_password
        from app.config import get_settings

        get_settings.cache_clear()

        mock_user = _make_mock_user(role="viewer", email="inactive@example.com", active=False)
        mock_user.password_hash = hash_password("SomePass123!")

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
            transport = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
            async with transport as client:
                response = await client.post(
                    "/api/v1/auth/token",
                    json={"username": "inactive@example.com", "password": "SomePass123!"},
                )
            assert response.status_code == 401
        finally:
            app.dependency_overrides.clear()
            get_settings.cache_clear()


# ---------------------------------------------------------------------------
# get_current_user with local JWT (mocked DB)
# ---------------------------------------------------------------------------


class TestGetCurrentUserLocal:
    async def test_valid_token_resolves_user(self):
        """get_current_user resolves the user from a valid local JWT."""
        from app.auth.dependencies import get_current_user
        from app.auth.local import create_access_token
        from app.config import get_settings

        get_settings.cache_clear()

        mock_user = _make_mock_user(role="operator", email="resolve@example.com", user_id=77)

        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_user
        mock_db = AsyncMock()
        mock_db.execute = AsyncMock(return_value=mock_result)

        token = create_access_token(user_id=77, sub="local:resolve@example.com", role="operator")
        resolved = await get_current_user(token=token, db=mock_db)

        assert resolved.id == 77
        assert resolved.email == "resolve@example.com"
        assert resolved.role == "operator"
        get_settings.cache_clear()

    async def test_expired_token_raises(self):
        """get_current_user raises AuthenticationError for expired tokens."""
        from jose import jwt

        from app.auth.dependencies import get_current_user
        from app.config import get_settings
        from app.exceptions import AuthenticationError

        get_settings.cache_clear()

        expired_payload = {
            "sub": "local:expired@example.com",
            "uid": 9999,
            "role": "viewer",
            "exp": datetime.now(timezone.utc) - timedelta(seconds=1),
        }
        token = jwt.encode(
            expired_payload,
            "test-secret-key-for-testing-only-not-for-production",
            algorithm="HS256",
        )

        mock_db = AsyncMock()

        with pytest.raises(AuthenticationError):
            await get_current_user(token=token, db=mock_db)

        get_settings.cache_clear()

    async def test_get_me_endpoint_returns_user(self):
        """GET /auth/me returns the current user profile."""
        client = await _get_local_client()
        async with client:
            response = await client.get("/api/v1/auth/me")
        assert response.status_code == 200
        data = response.json()
        assert "email" in data
        assert "role" in data


# ---------------------------------------------------------------------------
# Role hierarchy (existing guards still work with local auth)
# ---------------------------------------------------------------------------


class TestRoleHierarchyWithLocalAuth:
    def test_admin_level_higher_than_viewer(self):
        from app.auth.dependencies import _ROLE_HIERARCHY

        assert _ROLE_HIERARCHY["admin"] > _ROLE_HIERARCHY["operator"] > _ROLE_HIERARCHY["viewer"]

    async def test_require_admin_rejects_operator(self):
        from app.auth.dependencies import require_admin
        from app.exceptions import AuthorizationError

        user = MagicMock()
        user.role = "operator"

        with pytest.raises(AuthorizationError, match="Admin"):
            await require_admin(current_user=user)

    async def test_require_operator_accepts_admin(self):
        from app.auth.dependencies import require_operator

        user = MagicMock()
        user.role = "admin"

        result = await require_operator(current_user=user)
        assert result is user

    async def test_require_operator_rejects_viewer(self):
        from app.auth.dependencies import require_operator
        from app.exceptions import AuthorizationError

        user = MagicMock()
        user.role = "viewer"

        with pytest.raises(AuthorizationError, match="Operator"):
            await require_operator(current_user=user)
