"""Shortcut REST API client for Tier 2 access request flow.

Creates stories, polls their state, reads history to find approvers,
and posts comments.  All calls are async (httpx.AsyncClient).

The caller is responsible for:
  - Checking that SHORTCUT_API_TOKEN is non-empty before calling these functions.
  - Handling ShortcutError (retrying on the next poller cycle).
"""

from __future__ import annotations

from typing import Any

import httpx

from app.logging_config import get_logger

logger = get_logger(__name__)

_BASE_URL = "https://api.app.shortcut.com/api/v3"
_TIMEOUT = 15.0  # seconds


class ShortcutError(Exception):
    """Raised when a Shortcut API call fails or returns an unexpected status."""

    def __init__(self, message: str, status_code: int | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code


def _client(token: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=_BASE_URL,
        headers={"Shortcut-Token": token, "Content-Type": "application/json"},
        timeout=_TIMEOUT,
    )


async def create_story(
    *,
    token: str,
    workflow_state_id: int,
    epic_id: int | None,
    group_id: str | None,
    requested_by_id: str | None,
    name: str,
    description: str,
    labels: list[str],
) -> dict[str, Any]:
    """Create a Shortcut story and return the response payload.

    If the API rejects ``requested_by_id`` (e.g. member not found), retries
    without it.  Callers should include an @mention in the description as a
    fallback, which the description string already does.

    Returns:
        The full Shortcut story dict (id, app_url, etc.).

    Raises:
        ShortcutError: on HTTP errors that are not the requested_by fallback.
    """
    payload: dict[str, Any] = {
        "workflow_state_id": workflow_state_id,
        "story_type": "chore",
        "name": name,
        "description": description,
        "labels": [{"name": lbl} for lbl in labels],
    }
    if epic_id:
        payload["epic_id"] = epic_id
    if group_id:
        payload["group_id"] = group_id
    if requested_by_id:
        payload["requested_by_id"] = requested_by_id

    async with _client(token) as c:
        resp = await c.post("/stories", json=payload)
        if resp.status_code == 422 and requested_by_id:
            # Member ID rejected — retry without it
            logger.warning(
                "shortcut_requested_by_rejected",
                requested_by_id=requested_by_id,
                detail=resp.text[:300],
            )
            payload.pop("requested_by_id", None)
            resp = await c.post("/stories", json=payload)

        if resp.status_code not in (200, 201):
            raise ShortcutError(
                f"POST /stories returned {resp.status_code}: {resp.text[:300]}",
                status_code=resp.status_code,
            )
        return resp.json()


async def get_story(*, token: str, story_id: int) -> dict[str, Any] | None:
    """Fetch a story by ID.  Returns None if the story is gone (404).

    Raises:
        ShortcutError: on non-404 HTTP errors.
    """
    async with _client(token) as c:
        resp = await c.get(f"/stories/{story_id}")
        if resp.status_code == 404:
            return None
        if resp.status_code != 200:
            raise ShortcutError(
                f"GET /stories/{story_id} returned {resp.status_code}: {resp.text[:300]}",
                status_code=resp.status_code,
            )
        return resp.json()


async def get_story_history(*, token: str, story_id: int) -> list[dict[str, Any]]:
    """Fetch a story's history entries.  Returns [] if the story is gone.

    Each entry has ``member_id``, ``created_at``, and ``actions`` list.
    Defensive: unexpected shapes are logged and skipped.

    Raises:
        ShortcutError: on non-404 HTTP errors.
    """
    async with _client(token) as c:
        resp = await c.get(f"/stories/{story_id}/history")
        if resp.status_code == 404:
            return []
        if resp.status_code != 200:
            raise ShortcutError(
                f"GET /stories/{story_id}/history returned {resp.status_code}: {resp.text[:300]}",
                status_code=resp.status_code,
            )
        data = resp.json()
        if not isinstance(data, list):
            logger.warning("shortcut_history_unexpected_shape", story_id=story_id)
            return []
        return data


async def post_comment(*, token: str, story_id: int, text: str) -> None:
    """Post a comment on a Shortcut story.  Logs a warning on failure, never raises.

    Comments are best-effort: a failed comment is not a reason to skip
    the grant/revoke action.
    """
    try:
        async with _client(token) as c:
            resp = await c.post(f"/stories/{story_id}/comments", json={"text": text})
            if resp.status_code not in (200, 201):
                logger.warning(
                    "shortcut_comment_failed",
                    story_id=story_id,
                    status=resp.status_code,
                )
    except Exception as exc:
        logger.warning("shortcut_comment_error", story_id=story_id, error=str(exc))


async def move_story(*, token: str, story_id: int, workflow_state_id: int) -> bool:
    """Move a Shortcut story to another workflow state.  Returns False on failure, never raises.

    Best-effort like post_comment: the access state in the database is the record,
    the card state only mirrors it.
    """
    try:
        async with _client(token) as c:
            resp = await c.put(f"/stories/{story_id}", json={"workflow_state_id": workflow_state_id})
            if resp.status_code != 200:
                logger.warning("shortcut_move_failed", story_id=story_id, status=resp.status_code)
                return False
            return True
    except Exception as exc:
        logger.warning("shortcut_move_error", story_id=story_id, error=str(exc))
        return False


def find_approver_in_history(
    history: list[dict[str, Any]],
    approved_state_id: int,
) -> str | None:
    """Return the member_id who made the most recent transition INTO approved state.

    Parses history entries defensively; malformed entries are skipped.

    Args:
        history: List of Shortcut history entry dicts (newest-last from the API).
        approved_state_id: The workflow_state_id that counts as "Approved".

    Returns:
        The Shortcut member UUID of the approver, or None if none found.
    """
    # History is ordered oldest-first from Shortcut; iterate in reverse to get latest.
    for entry in reversed(history):
        try:
            member_id: str | None = entry.get("member_id")
            if not member_id:
                continue
            actions = entry.get("actions", [])
            for action in actions:
                changes = action.get("changes", {})
                wf_change = changes.get("workflow_state_id", {})
                new_wf = wf_change.get("new")
                if new_wf == approved_state_id:
                    return member_id
        except Exception as exc:  # noqa: BLE001
            logger.warning("shortcut_history_parse_error", error=str(exc))
            continue
    return None
