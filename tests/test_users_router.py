"""Tests for users router (list, update, self-modification guards).

Verifies:
- Admin can list users
- Admin can update user role
- Admin can toggle active
- Admin cannot self-demote
- Admin cannot self-deactivate
- Operator cannot access users endpoints
- Viewer cannot access users endpoints
- Update nonexistent user returns 404
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from app.db.models import User


def _make_mock_user(role: str = "admin", user_id: int = 1) -> User:
    user = MagicMock(spec=User)
    user.id = user_id
    user.sub = f"test-{role}-sub"
    user.email = f"{role}@test.com"
    user.display_name = f"Test {role.capitalize()}"
    user.role = role
    user.is_active = True
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
# Admin can list users
# ---------------------------------------------------------------------------

class TestAdminListUsers:
    @patch("app.services.user_service.list_users", new_callable=AsyncMock)
    async def test_admin_can_list_users(self, mock_list):
        now = datetime.now(timezone.utc)
        mock_user_obj = MagicMock()
        mock_user_obj.id = 2
        mock_user_obj.email = "viewer@test.com"
        mock_user_obj.display_name = "Test Viewer"
        mock_user_obj.role = "viewer"
        mock_user_obj.is_active = True
        mock_user_obj.last_login_at = now
        mock_user_obj.created_at = now
        mock_list.return_value = ([mock_user_obj], 1)

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.get("/api/v1/users/")

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert len(data["items"]) == 1
        assert data["items"][0]["email"] == "viewer@test.com"
        assert data["items"][0]["role"] == "viewer"

    @patch("app.services.user_service.list_users", new_callable=AsyncMock)
    async def test_admin_can_list_users_with_pagination(self, mock_list):
        mock_list.return_value = ([], 0)

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.get("/api/v1/users/?page=2&page_size=10")

        assert resp.status_code == 200
        data = resp.json()
        assert data["page"] == 2
        assert data["page_size"] == 10
        assert data["has_next"] is False


# ---------------------------------------------------------------------------
# Admin can get single user
# ---------------------------------------------------------------------------

class TestAdminGetUser:
    @patch("app.services.user_service.get_user", new_callable=AsyncMock)
    async def test_admin_can_get_user(self, mock_get):
        now = datetime.now(timezone.utc)
        mock_user_obj = MagicMock()
        mock_user_obj.id = 2
        mock_user_obj.email = "viewer@test.com"
        mock_user_obj.display_name = "Test Viewer"
        mock_user_obj.role = "viewer"
        mock_user_obj.is_active = True
        mock_user_obj.last_login_at = now
        mock_user_obj.created_at = now
        mock_get.return_value = mock_user_obj

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.get("/api/v1/users/2")

        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == 2
        assert data["email"] == "viewer@test.com"


# ---------------------------------------------------------------------------
# Admin can update user role
# ---------------------------------------------------------------------------

class TestAdminUpdateUser:
    @patch("app.services.user_service.update_user", new_callable=AsyncMock)
    async def test_admin_can_change_user_role(self, mock_update):
        now = datetime.now(timezone.utc)
        mock_user_obj = MagicMock()
        mock_user_obj.id = 2
        mock_user_obj.email = "viewer@test.com"
        mock_user_obj.display_name = "Test Viewer"
        mock_user_obj.role = "operator"
        mock_user_obj.is_active = True
        mock_user_obj.last_login_at = now
        mock_user_obj.created_at = now
        mock_update.return_value = mock_user_obj

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.patch(
                "/api/v1/users/2",
                json={"role": "operator"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["role"] == "operator"

    @patch("app.services.user_service.update_user", new_callable=AsyncMock)
    async def test_admin_can_deactivate_user(self, mock_update):
        now = datetime.now(timezone.utc)
        mock_user_obj = MagicMock()
        mock_user_obj.id = 2
        mock_user_obj.email = "viewer@test.com"
        mock_user_obj.display_name = "Test Viewer"
        mock_user_obj.role = "viewer"
        mock_user_obj.is_active = False
        mock_user_obj.last_login_at = now
        mock_user_obj.created_at = now
        mock_update.return_value = mock_user_obj

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.patch(
                "/api/v1/users/2",
                json={"is_active": False},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["is_active"] is False


# ---------------------------------------------------------------------------
# Self-modification guards
# ---------------------------------------------------------------------------

class TestSelfModificationGuards:
    @patch("app.services.user_service.update_user", new_callable=AsyncMock)
    async def test_admin_cannot_self_demote(self, mock_update):
        from app.exceptions import ValidationError
        mock_update.side_effect = ValidationError("Cannot change your own role")

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.patch(
                "/api/v1/users/1",
                json={"role": "viewer"},
            )

        assert resp.status_code == 400
        assert "Cannot change your own role" in resp.json()["detail"]

    @patch("app.services.user_service.update_user", new_callable=AsyncMock)
    async def test_admin_cannot_self_deactivate(self, mock_update):
        from app.exceptions import ValidationError
        mock_update.side_effect = ValidationError("Cannot deactivate your own account")

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.patch(
                "/api/v1/users/1",
                json={"is_active": False},
            )

        assert resp.status_code == 400
        assert "Cannot deactivate your own account" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# Update nonexistent user returns 404
# ---------------------------------------------------------------------------

class TestUpdateNonexistentUser:
    @patch("app.services.user_service.update_user", new_callable=AsyncMock)
    async def test_update_nonexistent_user_404(self, mock_update):
        from app.exceptions import NotFoundError
        mock_update.side_effect = NotFoundError("User", 99999)

        admin = _make_mock_user("admin", user_id=1)
        client = await _get_client(admin)
        async with client:
            resp = await client.patch(
                "/api/v1/users/99999",
                json={"role": "operator"},
            )

        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Non-admin users cannot access users endpoints
# ---------------------------------------------------------------------------

class TestNonAdminCannotAccessUsers:
    async def test_operator_cannot_list_users(self):
        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.get("/api/v1/users/")
        assert resp.status_code == 403

    async def test_operator_cannot_get_user(self):
        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.get("/api/v1/users/1")
        assert resp.status_code == 403

    async def test_operator_cannot_update_user(self):
        operator = _make_mock_user("operator", user_id=3)
        client = await _get_client(operator)
        async with client:
            resp = await client.patch(
                "/api/v1/users/1",
                json={"role": "viewer"},
            )
        assert resp.status_code == 403

    async def test_viewer_cannot_list_users(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.get("/api/v1/users/")
        assert resp.status_code == 403

    async def test_viewer_cannot_get_user(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.get("/api/v1/users/1")
        assert resp.status_code == 403

    async def test_viewer_cannot_update_user(self):
        viewer = _make_mock_user("viewer", user_id=2)
        client = await _get_client(viewer)
        async with client:
            resp = await client.patch(
                "/api/v1/users/1",
                json={"role": "admin"},
            )
        assert resp.status_code == 403
