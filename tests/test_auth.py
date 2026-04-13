"""Tests for auth — OIDC validation and FastAPI dependencies."""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from jose import jwt

from app.exceptions import AuthenticationError, AuthorizationError


# ---------------------------------------------------------------------------
# OIDC — validate_token
# ---------------------------------------------------------------------------


class TestOIDC:
    async def test_validate_token_success(self):
        from app.auth.oidc import clear_jwks_cache, validate_token

        clear_jwks_cache()

        fake_jwks = {"keys": [{"kid": "test-key"}]}
        fake_claims = {"sub": "user-123", "email": "test@example.com", "name": "Test User"}

        with (
            patch("app.auth.oidc.fetch_jwks", new_callable=AsyncMock, return_value=fake_jwks),
            patch("app.auth.oidc.get_settings") as mock_settings,
            patch("jose.jwt.decode", return_value=fake_claims),
        ):
            settings = MagicMock()
            settings.oidc_audience = "test-audience"
            settings.oidc_issuer_url = "https://issuer.example.com"
            mock_settings.return_value = settings

            claims = await validate_token("fake-token")
            assert claims["sub"] == "user-123"
            assert claims["email"] == "test@example.com"

    async def test_validate_token_missing_sub(self):
        from app.auth.oidc import clear_jwks_cache, validate_token

        clear_jwks_cache()

        fake_jwks = {"keys": []}
        fake_claims = {"email": "test@example.com"}  # no sub

        with (
            patch("app.auth.oidc.fetch_jwks", new_callable=AsyncMock, return_value=fake_jwks),
            patch("app.auth.oidc.get_settings") as mock_settings,
            patch("jose.jwt.decode", return_value=fake_claims),
        ):
            settings = MagicMock()
            settings.oidc_audience = "test"
            settings.oidc_issuer_url = "https://issuer"
            mock_settings.return_value = settings

            with pytest.raises(AuthenticationError, match="sub"):
                await validate_token("fake-token")

    async def test_validate_token_jwt_error(self):
        from jose import JWTError

        from app.auth.oidc import clear_jwks_cache, validate_token

        clear_jwks_cache()

        with (
            patch("app.auth.oidc.fetch_jwks", new_callable=AsyncMock, return_value={"keys": []}),
            patch("app.auth.oidc.get_settings") as mock_settings,
            patch("jose.jwt.decode", side_effect=JWTError("bad token")),
        ):
            settings = MagicMock()
            settings.oidc_audience = "test"
            settings.oidc_issuer_url = "https://issuer"
            mock_settings.return_value = settings

            with pytest.raises(AuthenticationError, match="Invalid or expired"):
                await validate_token("bad-token")

    async def test_fetch_jwks_cache_ttl(self):
        import time

        from app.auth.oidc import _JWKS_TTL_SECONDS, clear_jwks_cache, fetch_jwks

        clear_jwks_cache()

        fake_openid = {"jwks_uri": "https://issuer/.well-known/jwks.json"}
        fake_jwks = {"keys": [{"kid": "k1"}]}

        call_count = 0

        async def mock_get(url):
            nonlocal call_count
            call_count += 1
            resp = MagicMock()
            resp.json.return_value = fake_jwks
            resp.raise_for_status = MagicMock()
            return resp

        with (
            patch("app.auth.oidc.fetch_openid_config", new_callable=AsyncMock, return_value=fake_openid),
            patch("app.auth.oidc.httpx.AsyncClient") as mock_client_cls,
        ):
            mock_client = AsyncMock()
            mock_client.get = mock_get
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock(return_value=False)
            mock_client_cls.return_value = mock_client

            # First call fetches
            result1 = await fetch_jwks()
            assert result1 == fake_jwks
            assert call_count == 1

            # Second call uses cache
            result2 = await fetch_jwks()
            assert result2 == fake_jwks
            assert call_count == 1  # still 1, cached

    async def test_clear_jwks_cache(self):
        from app.auth.oidc import _jwks, _jwks_fetched_at, _openid_config, clear_jwks_cache

        clear_jwks_cache()
        # After clearing, module-level vars should be None/0
        from app.auth import oidc

        assert oidc._jwks is None
        assert oidc._openid_config is None
        assert oidc._jwks_fetched_at == 0.0


# ---------------------------------------------------------------------------
# Auth dependencies
# ---------------------------------------------------------------------------


class TestAuthDependencies:
    async def test_require_admin_passes_for_admin(self):
        from app.auth.dependencies import require_admin

        user = MagicMock()
        user.role = "admin"

        result = await require_admin(current_user=user)
        assert result is user

    async def test_require_admin_rejects_viewer(self):
        from app.auth.dependencies import require_admin

        user = MagicMock()
        user.role = "viewer"

        with pytest.raises(AuthorizationError, match="Admin access required"):
            await require_admin(current_user=user)

    async def test_require_viewer_passes_for_any_active(self):
        from app.auth.dependencies import require_viewer

        user = MagicMock()
        user.role = "viewer"

        result = await require_viewer(current_user=user)
        assert result is user

    def test_role_hierarchy(self):
        from app.auth.dependencies import _ROLE_HIERARCHY

        assert _ROLE_HIERARCHY["admin"] > _ROLE_HIERARCHY["viewer"]
