"""Integration test infrastructure for strongswan-manager.

These tests talk to a REAL dev manager + its VPN nodes via the HTTP API.
They are excluded from the default ``pytest -q tests`` run by marker.

HOW TO RUN
----------
1. Open an SSM port-forward to the dev manager's port 8000::

       aws ssm start-session --target <instance-id> \\
         --document-name AWS-StartPortForwardingSession \\
         --parameters '{"portNumber":["8000"],"localPortNumber":["18000"]}'

2. Obtain a short-lived admin bearer token from the manager (e.g. via
   ``POST /api/v1/auth/token`` or the CLI helper in scripts/).

3. Set env vars and run only the integration suite::

       SSM_IT_BASE_URL=http://localhost:18000 SSM_IT_TOKEN=<token> \\
           .venv/bin/python -m pytest -q -m integration tests/integration/

Env vars
--------
SSM_IT_BASE_URL
    Full base URL of the port-forwarded API, e.g. ``http://localhost:18000``.
    Trailing slash is stripped automatically.
SSM_IT_TOKEN
    Admin bearer token.  When either var is absent every test is skipped.

Design notes
------------
- Every test that creates a tunnel uses the ``throwaway_tunnel`` fixture,
  which always deletes it in the ``finally`` block — even when the test fails.
- Tunnel names are prefixed ``it-`` with a random 8-hex suffix so runs are
  safe to repeat without manual cleanup.
- Peer IPs come from RFC 5737 documentation ranges (192.0.2.0/24,
  203.0.113.0/24); ``start_action="none"`` prevents strongSwan from ever
  initiating a connection to the non-existent peer.
- PSKs are generated with ``secrets.token_urlsafe(32)`` per run; they are
  never printed in assertion messages.
- HTTP timeout is 120 s to accommodate SSM fan-out latency; the sync-status
  poll loops for up to 90 s with a 3-second interval.
"""

from __future__ import annotations

import os
import random
import secrets
from typing import Any, AsyncGenerator

import httpx
import pytest

# ---------------------------------------------------------------------------
# Configuration from env vars
# ---------------------------------------------------------------------------

BASE_URL: str = os.environ.get("SSM_IT_BASE_URL", "").rstrip("/")
TOKEN: str = os.environ.get("SSM_IT_TOKEN", "")

_HTTP_TIMEOUT = httpx.Timeout(120.0)


# ---------------------------------------------------------------------------
# Autouse skip guard
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _require_integration_env() -> None:
    """Skip every test in this package when env vars are absent."""
    if not BASE_URL or not TOKEN:
        pytest.skip(
            "Integration env vars not set. "
            "Export SSM_IT_BASE_URL and SSM_IT_TOKEN, then re-run with -m integration."
        )


# ---------------------------------------------------------------------------
# HTTP client
# ---------------------------------------------------------------------------


@pytest.fixture
async def client() -> AsyncGenerator[httpx.AsyncClient, None]:
    """Authenticated httpx.AsyncClient against the SSM-forwarded manager API."""
    async with httpx.AsyncClient(
        base_url=BASE_URL,
        headers={"Authorization": f"Bearer {TOKEN}"},
        timeout=_HTTP_TIMEOUT,
    ) as ac:
        yield ac


# ---------------------------------------------------------------------------
# Throwaway tunnel fixture
# ---------------------------------------------------------------------------


@pytest.fixture
async def throwaway_tunnel(client: httpx.AsyncClient) -> AsyncGenerator[dict[str, Any], None]:
    """Create a throwaway tunnel for one test; always delete it in teardown.

    Properties:
      name         — ``it-<hex8>``  (unique per run)
      peer_ip      — ``192.0.2.{2..254}``  (TEST-NET-1, RFC 5737)
      remote_cidrs — ``203.0.113.0/24``  (TEST-NET-3, RFC 5737)
      start_action — ``none``  (passive; strongSwan will NOT initiate)
      psk          — ``secrets.token_urlsafe(32)`` generated per test; never logged

    Yields the JSON dict from ``POST /api/v1/tunnels/`` (TunnelDetail shape).

    If teardown cannot delete the tunnel it calls ``pytest.fail`` with the
    tunnel name so a human can clean up manually.
    """
    suffix = secrets.token_hex(4)
    name = f"it-{suffix}"
    last_octet = random.randint(2, 254)
    peer_ip = f"192.0.2.{last_octet}"
    psk = secrets.token_urlsafe(32)

    payload: dict[str, Any] = {
        "name": name,
        "peer_ip": peer_ip,
        "local_cidrs": ["10.0.0.0/24"],
        "remote_cidrs": ["203.0.113.0/24"],
        "psk": psk,
        "start_action": "none",
        "ike_version": "2",
    }

    r = await client.post("/api/v1/tunnels/", json=payload)
    assert r.status_code == 201, (
        f"Throwaway tunnel creation failed: HTTP {r.status_code}\n{r.text}"
    )
    tunnel_data: dict[str, Any] = r.json()
    tunnel_id: int = tunnel_data["id"]

    try:
        yield tunnel_data
    finally:
        del_r = await client.delete(f"/api/v1/tunnels/{tunnel_id}")
        if del_r.status_code not in (204, 404):
            pytest.fail(
                f"[CLEANUP REQUIRED] Could not delete tunnel name={name!r} id={tunnel_id}: "
                f"HTTP {del_r.status_code}"
            )
