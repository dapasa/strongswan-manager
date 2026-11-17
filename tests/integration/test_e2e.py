"""End-to-end integration scenarios for the strongswan-manager HTTP API.

Each scenario owns a throwaway tunnel (created by the fixture, deleted in
teardown even on failure).  Tests are independent and safe to re-run.

Requires SSM_IT_BASE_URL and SSM_IT_TOKEN — see conftest.py for full setup
instructions.  Run with::

    SSM_IT_BASE_URL=http://localhost:18000 SSM_IT_TOKEN=<token> \\
        .venv/bin/python -m pytest -q -m integration tests/integration/
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

import httpx
import pytest

# ---------------------------------------------------------------------------
# Timing constants
# ---------------------------------------------------------------------------

_SYNC_TIMEOUT_S: float = 90.0   # max seconds to wait for sync_status == "synced"
_SYNC_INTERVAL_S: float = 3.0   # polling interval between status checks


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


async def _poll_tunnel_synced(
    client: httpx.AsyncClient,
    tunnel_id: int,
    *,
    timeout: float = _SYNC_TIMEOUT_S,
    interval: float = _SYNC_INTERVAL_S,
) -> dict[str, Any]:
    """Poll ``GET /api/v1/tunnels/{id}`` until ``sync_status == 'synced'``.

    Fails the test immediately when ``sync_status`` becomes ``'failed'``.
    Raises ``pytest.fail.Exception`` when the timeout is exceeded.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = await client.get(f"/api/v1/tunnels/{tunnel_id}")
        r.raise_for_status()
        data: dict[str, Any] = r.json()
        s = data["sync_status"]
        if s == "synced":
            return data
        if s == "failed":
            pytest.fail(
                f"Tunnel {tunnel_id} reached sync_status=failed: {data.get('sync_error')}"
            )
        await asyncio.sleep(interval)
    pytest.fail(
        f"Tunnel {tunnel_id} did not reach sync_status=synced within {timeout}s"
    )
    raise AssertionError("unreachable")  # satisfy type checkers


async def _poll_rule_synced(
    client: httpx.AsyncClient,
    rule_id: int,
    *,
    timeout: float = _SYNC_TIMEOUT_S,
    interval: float = _SYNC_INTERVAL_S,
) -> dict[str, Any]:
    """Poll ``GET /api/v1/iptables/{id}`` until ``sync_status == 'synced'``."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        r = await client.get(f"/api/v1/iptables/{rule_id}")
        r.raise_for_status()
        data: dict[str, Any] = r.json()
        s = data["sync_status"]
        if s == "synced":
            return data
        if s == "failed":
            pytest.fail(
                f"IPTables rule {rule_id} reached sync_status=failed: {data.get('sync_error')}"
            )
        await asyncio.sleep(interval)
    pytest.fail(
        f"IPTables rule {rule_id} did not reach sync_status=synced within {timeout}s"
    )
    raise AssertionError("unreachable")


async def _list_servers(client: httpx.AsyncClient) -> list[dict[str, Any]]:
    """Return all items from ``GET /api/v1/servers/``."""
    r = await client.get("/api/v1/servers/")
    r.raise_for_status()
    return r.json()["items"]  # type: ignore[no-any-return]


async def _assert_drift_in_sync(
    client: httpx.AsyncClient,
    tunnel_id: int,
    *,
    servers: list[dict[str, Any]],
) -> None:
    """Assert every server in *servers* reports ``in_sync`` drift for *tunnel_id*."""
    assert servers, "No active servers found — cannot validate drift"
    for server in servers:
        sid: int = server["id"]
        dr = await client.get(
            f"/api/v1/servers/{sid}/drift", params={"tunnel_id": tunnel_id}
        )
        dr.raise_for_status()
        report = dr.json()
        entries = [t for t in report["tunnels"] if t["tunnel_id"] == tunnel_id]
        assert entries, (
            f"Server {sid} drift report has no entry for tunnel {tunnel_id}"
        )
        status = entries[0]["status"]
        assert status == "in_sync", (
            f"Server {sid}: drift status={status!r} for tunnel {tunnel_id}"
        )


# ---------------------------------------------------------------------------
# Scenario 1 — create, wait for sync, verify drift
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_1_create_sync_drift(
    throwaway_tunnel: dict[str, Any],
    client: httpx.AsyncClient,
) -> None:
    """Create a tunnel → sync_status becomes synced → drift in_sync on every server."""
    tunnel_id: int = throwaway_tunnel["id"]

    await _poll_tunnel_synced(client, tunnel_id)

    servers = await _list_servers(client)
    await _assert_drift_in_sync(client, tunnel_id, servers=servers)


# ---------------------------------------------------------------------------
# Scenario 2 — PATCH non-PSK field, re-sync, re-check drift
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_2_patch_non_psk_then_drift(
    throwaway_tunnel: dict[str, Any],
    client: httpx.AsyncClient,
) -> None:
    """PATCH dpd_delay → synced → drift still in_sync on every server."""
    tunnel_id: int = throwaway_tunnel["id"]

    await _poll_tunnel_synced(client, tunnel_id)

    patch_r = await client.patch(f"/api/v1/tunnels/{tunnel_id}", json={"dpd_delay": 45})
    assert patch_r.status_code == 200, (
        f"PATCH failed: HTTP {patch_r.status_code}\n{patch_r.text}"
    )

    await _poll_tunnel_synced(client, tunnel_id)

    servers = await _list_servers(client)
    await _assert_drift_in_sync(client, tunnel_id, servers=servers)


# ---------------------------------------------------------------------------
# Scenario 3 — invalid proposal → 422, drift unchanged
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_3_invalid_proposal_422_drift_unchanged(
    throwaway_tunnel: dict[str, Any],
    client: httpx.AsyncClient,
) -> None:
    """PATCH with invalid proposal keyword → 422; drift for the tunnel unchanged."""
    tunnel_id: int = throwaway_tunnel["id"]

    await _poll_tunnel_synced(client, tunnel_id)

    servers = await _list_servers(client)
    await _assert_drift_in_sync(client, tunnel_id, servers=servers)

    # ``foo`` is not a recognised strongSwan proposal keyword → must be 422
    patch_r = await client.patch(
        f"/api/v1/tunnels/{tunnel_id}", json={"ike_proposals": "aes256-foo"}
    )
    assert patch_r.status_code == 422, (
        f"Expected 422 for unrecognised proposal keyword, got {patch_r.status_code}"
    )

    # The rejected PATCH must not have changed the node state
    await _assert_drift_in_sync(client, tunnel_id, servers=servers)


# ---------------------------------------------------------------------------
# Scenario 4 — PSK rotation
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_4_rotate_psk_synced_no_psk_in_audit(
    throwaway_tunnel: dict[str, Any],
    client: httpx.AsyncClient,
) -> None:
    """Rotate PSK → response has psk + psk_rotated_at; synced; plaintext PSK absent in audit log."""
    tunnel_id: int = throwaway_tunnel["id"]

    await _poll_tunnel_synced(client, tunnel_id)

    # Server generates a fresh PSK when body is ``{}``
    rotate_r = await client.post(f"/api/v1/tunnels/{tunnel_id}/rotate-psk", json={})
    assert rotate_r.status_code == 200, (
        f"rotate-psk failed: HTTP {rotate_r.status_code}\n{rotate_r.text}"
    )
    rotate_data: dict[str, Any] = rotate_r.json()
    assert "psk" in rotate_data, "rotate-psk response must contain the new PSK"
    assert rotate_data.get("psk_rotated_at") is not None, (
        "psk_rotated_at must be set after rotation"
    )
    new_psk: str = rotate_data["psk"]  # kept only for audit-log check; never asserted literally

    # Wait for all nodes to receive the new PSK
    await _poll_tunnel_synced(client, tunnel_id)

    # Every server must report in_sync for this tunnel
    servers = await _list_servers(client)
    await _assert_drift_in_sync(client, tunnel_id, servers=servers)

    # Audit log must NOT contain the plaintext PSK in any field
    audit_r = await client.get(
        "/api/v1/audit/", params={"entity_type": "tunnel", "page_size": 100}
    )
    audit_r.raise_for_status()
    all_entries: list[dict[str, Any]] = audit_r.json()["items"]
    tunnel_entries = [e for e in all_entries if e.get("entity_id") == tunnel_id]

    # Do NOT embed new_psk in the assertion message
    exposed = any(new_psk in json.dumps(entry) for entry in tunnel_entries)
    assert not exposed, (
        "Plaintext PSK must not appear in any audit log entry for this tunnel"
    )


# ---------------------------------------------------------------------------
# Scenario 5 — live status
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_5_live_status_contains_tunnel(
    throwaway_tunnel: dict[str, Any],
    client: httpx.AsyncClient,
) -> None:
    """Live status contains the tunnel with overall DOWN or UNKNOWN; no server_errors."""
    tunnel_id: int = throwaway_tunnel["id"]
    tunnel_name: str = throwaway_tunnel["name"]

    r = await client.get("/api/v1/tunnels/status/live")
    r.raise_for_status()
    data = r.json()

    # All servers must have responded (server_errors should be empty)
    assert data.get("server_errors") == {}, (
        f"server_errors must be empty; got: {data.get('server_errors')}"
    )

    # Our tunnel must appear in the response
    matches = [t for t in data["tunnels"] if t["tunnel_id"] == tunnel_id]
    assert matches, (
        f"Tunnel id={tunnel_id} name={tunnel_name!r} not found in live status response"
    )

    # start_action=none with an absent peer → DOWN or UNKNOWN (never UP)
    overall = matches[0]["overall"]
    assert overall in ("DOWN", "UNKNOWN"), (
        f"Passive tunnel with absent peer must be DOWN or UNKNOWN; got {overall!r}"
    )


# ---------------------------------------------------------------------------
# Scenario 6 — iptables rule lifecycle
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_6_iptables_rule_lifecycle(
    throwaway_tunnel: dict[str, Any],
    client: httpx.AsyncClient,
) -> None:
    """Create iptables rule → synced → delete → rule absent from tunnel's iptables list."""
    tunnel_id: int = throwaway_tunnel["id"]

    await _poll_tunnel_synced(client, tunnel_id)

    # POST /api/v1/iptables/?tunnel_id= (note: tunnel_id is a query param here)
    rule_payload: dict[str, Any] = {
        "chain": "FORWARD",
        "protocol": "all",
        "action": "ACCEPT",
        "comment": "it-integration-test",
    }
    create_r = await client.post(
        "/api/v1/iptables/",
        params={"tunnel_id": tunnel_id},
        json=rule_payload,
    )
    assert create_r.status_code == 201, (
        f"IPTables rule creation failed: HTTP {create_r.status_code}\n{create_r.text}"
    )
    rule_id: int = create_r.json()["id"]

    await _poll_rule_synced(client, rule_id)

    # Rule must be visible in the tunnel's nested list
    list_r = await client.get(f"/api/v1/tunnels/{tunnel_id}/iptables")
    list_r.raise_for_status()
    present_ids = [rule["id"] for rule in list_r.json()]
    assert rule_id in present_ids, (
        f"Rule {rule_id} not found in tunnel {tunnel_id} iptables list after creation"
    )

    # Delete the rule
    del_r = await client.delete(f"/api/v1/iptables/{rule_id}")
    assert del_r.status_code == 204, (
        f"IPTables rule deletion failed: HTTP {del_r.status_code}"
    )

    # Rule must be gone from the tunnel's nested list
    list2_r = await client.get(f"/api/v1/tunnels/{tunnel_id}/iptables")
    list2_r.raise_for_status()
    remaining_ids = [rule["id"] for rule in list2_r.json()]
    assert rule_id not in remaining_ids, (
        f"Rule {rule_id} still in tunnel {tunnel_id} iptables list after deletion"
    )


# ---------------------------------------------------------------------------
# Scenario 7 — delete tunnel, verify drift is clean
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_7_delete_tunnel_drift_clean(
    throwaway_tunnel: dict[str, Any],
    client: httpx.AsyncClient,
) -> None:
    """Delete tunnel → drift shows no entry and no orphan config file for it.

    The ``throwaway_tunnel`` fixture teardown accepts a 404 on its own delete
    attempt, so this test can call DELETE itself without double-cleanup errors.
    """
    tunnel_id: int = throwaway_tunnel["id"]
    tunnel_name: str = throwaway_tunnel["name"]

    await _poll_tunnel_synced(client, tunnel_id)

    # Collect servers while the tunnel is still active
    servers = await _list_servers(client)

    # Delete the tunnel; fixture teardown will get 404 and handle it gracefully
    del_r = await client.delete(f"/api/v1/tunnels/{tunnel_id}")
    assert del_r.status_code == 204, (
        f"Tunnel deletion failed: HTTP {del_r.status_code}"
    )

    # Drift check on each server: no active entry for the deleted tunnel,
    # and no orphan config file carrying the tunnel name
    for server in servers:
        sid: int = server["id"]
        dr = await client.get(f"/api/v1/servers/{sid}/drift")
        dr.raise_for_status()
        report = dr.json()

        stale_entries = [t for t in report["tunnels"] if t["tunnel_id"] == tunnel_id]
        assert not stale_entries, (
            f"Server {sid} drift still references deleted tunnel {tunnel_id}"
        )

        orphan_matches = [f for f in report["orphan_files"] if tunnel_name in f]
        assert not orphan_matches, (
            f"Server {sid} has orphan config file(s) for deleted tunnel "
            f"name={tunnel_name!r}: {orphan_matches}"
        )


# ---------------------------------------------------------------------------
# Scenario 8 — dashboard and reconciler health checks
# ---------------------------------------------------------------------------


@pytest.mark.integration
async def test_8_dashboard_and_reconciler(
    client: httpx.AsyncClient,
) -> None:
    """Dashboard summary and reconciler status respond 200 with the expected keys."""
    # --- dashboard ---
    dash_r = await client.get("/api/v1/dashboard/summary")
    assert dash_r.status_code == 200, (
        f"Dashboard summary failed: HTTP {dash_r.status_code}"
    )
    dash_data = dash_r.json()
    expected_dash_keys = {
        "active_tunnels",
        "active_routes",
        "active_iptables_rules",
        "failed_syncs",
        "pending_operations",
    }
    missing_dash = expected_dash_keys - set(dash_data)
    assert not missing_dash, f"Dashboard response missing keys: {missing_dash}"

    # --- reconciler ---
    rec_r = await client.get("/api/v1/reconciler/status")
    assert rec_r.status_code == 200, (
        f"Reconciler status failed: HTTP {rec_r.status_code}"
    )
    rec_data = rec_r.json()
    expected_rec_keys = {"enabled", "interval_seconds", "max_attempts"}
    missing_rec = expected_rec_keys - set(rec_data)
    assert not missing_rec, f"Reconciler status missing keys: {missing_rec}"
