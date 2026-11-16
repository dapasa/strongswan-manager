"""Tests for the automatic tunnel reconciler."""
from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from app.exceptions import InfrastructureError
from app.utils.fan_out import FanOutResult


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_tunnel(tunnel_id: int, sync_status: str):
    t = MagicMock()
    t.id = tunnel_id
    t.sync_status = sync_status
    t.deleted_at = None
    t.psk_encrypted = "enc_psk"
    t.sync_error = None
    t.sync_details = None
    return t


def _mock_execute_scalars(values: list):
    """Return a mock execute() result whose .scalars().all() yields `values`."""
    scalars = MagicMock()
    scalars.all.return_value = values
    result = MagicMock()
    result.scalars.return_value = scalars
    return result


def _mock_execute_scalar_one_or_none(value):
    """Return a mock execute() result whose .scalar_one_or_none() yields `value`."""
    result = MagicMock()
    result.scalar_one_or_none.return_value = value
    return result


def _make_session_factory(session):
    """Create a mock session factory that always yields the given session."""
    @asynccontextmanager
    async def factory():
        yield session
    return factory


def _make_settings(*, enabled=True, interval=300, max_attempts=5):
    s = MagicMock()
    s.reconciler_enabled = enabled
    s.reconciler_interval_seconds = interval
    s.reconciler_max_attempts = max_attempts
    return s


# ---------------------------------------------------------------------------
# _process_tunnel — per-tunnel logic
# ---------------------------------------------------------------------------

class TestProcessTunnel:
    """Unit tests for _process_tunnel."""

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="plain_psk")
    async def test_failed_tunnel_is_synced(self, mock_decrypt, mock_sync, mock_audit, mock_lock):
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "failed")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
        mock_sync.return_value = FanOutResult(total=2, succeeded=2, failed=0)

        state: dict[int, int] = {}
        await _process_tunnel(state, 1, session, _make_settings())

        assert state[1] == 1
        assert tunnel.sync_status == "synced"
        mock_decrypt.assert_awaited_once_with(tunnel.psk_encrypted)
        mock_sync.assert_awaited_once()
        mock_audit.assert_awaited_once()
        session.commit.assert_awaited_once()

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="plain_psk")
    async def test_partial_tunnel_is_synced(self, mock_decrypt, mock_sync, mock_audit, mock_lock):
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(2, "partial")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
        mock_sync.return_value = FanOutResult(total=2, succeeded=2, failed=0)

        state: dict[int, int] = {}
        await _process_tunnel(state, 2, session, _make_settings())

        assert tunnel.sync_status == "synced"
        session.commit.assert_awaited_once()

    async def test_skips_when_status_is_pending(self):
        """Tunnel with sync_status='pending' (in-flight manual retry) is skipped."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "pending")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)

        state: dict[int, int] = {}
        await _process_tunnel(state, 1, session, _make_settings())

        assert 1 not in state
        session.commit.assert_not_awaited()

    async def test_skips_when_status_is_synced(self):
        """Tunnel that became synced between scan and processing is skipped."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "synced")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)

        state: dict[int, int] = {}
        await _process_tunnel(state, 1, session, _make_settings())

        assert 1 not in state
        session.commit.assert_not_awaited()

    async def test_skips_when_tunnel_deleted(self):
        """Deleted tunnel is skipped."""
        from app.services.reconciler import _process_tunnel

        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(None)

        state: dict[int, int] = {}
        await _process_tunnel(state, 99, session, _make_settings())

        assert 99 not in state
        session.commit.assert_not_awaited()

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=False)
    async def test_skips_when_advisory_lock_held(self, mock_lock):
        """Skips tunnel when the advisory lock is already held (another operation in progress)."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "failed")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)

        state: dict[int, int] = {}
        await _process_tunnel(state, 1, session, _make_settings())

        assert 1 not in state
        session.commit.assert_not_awaited()

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="psk")
    async def test_infrastructure_error_marks_failed(self, mock_decrypt, mock_sync, mock_audit, mock_lock):
        """InfrastructureError (e.g. no active servers) marks tunnel as failed."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "failed")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
        mock_sync.side_effect = InfrastructureError("SSH", "No active servers registered")

        state: dict[int, int] = {}
        await _process_tunnel(state, 1, session, _make_settings())

        assert state[1] == 1
        assert tunnel.sync_status == "failed"
        assert "No active servers" in tunnel.sync_error
        mock_audit.assert_awaited_once()
        session.commit.assert_awaited_once()

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="psk")
    async def test_attempt_counter_increments(self, mock_decrypt, mock_sync, mock_audit, mock_lock):
        """Attempt counter increments on each call."""
        from app.services.reconciler import _process_tunnel

        mock_sync.return_value = FanOutResult(total=1, succeeded=0, failed=1)

        state: dict[int, int] = {}
        settings = _make_settings(max_attempts=5)

        for expected in range(1, 4):
            tunnel = _make_tunnel(1, "failed")
            session = AsyncMock()
            session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
            await _process_tunnel(state, 1, session, settings)
            assert state[1] == expected

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="psk")
    async def test_partial_sync_result_recorded(self, mock_decrypt, mock_sync, mock_audit, mock_lock):
        """Partial fan-out result sets sync_status=partial."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "failed")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
        mock_sync.return_value = FanOutResult(total=2, succeeded=1, failed=1)

        state: dict[int, int] = {}
        await _process_tunnel(state, 1, session, _make_settings())

        assert tunnel.sync_status == "partial"
        session.commit.assert_awaited_once()

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="psk")
    async def test_audit_actor_is_system_reconciler(self, mock_decrypt, mock_sync, mock_audit, mock_lock):
        """Audit log new_state includes actor=system:reconciler."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "failed")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
        mock_sync.return_value = FanOutResult(total=1, succeeded=1, failed=0)

        state: dict[int, int] = {}
        await _process_tunnel(state, 1, session, _make_settings())

        call_kwargs = mock_audit.call_args.kwargs
        assert call_kwargs["user_id"] is None
        assert call_kwargs["action"] == "retry"
        assert call_kwargs["new_state"]["actor"] == "system:reconciler"


# ---------------------------------------------------------------------------
# reconcile_once — scan and dispatch
# ---------------------------------------------------------------------------

class TestReconcileOnce:
    """Unit tests for reconcile_once."""

    @patch("app.services.reconciler._process_tunnel", new_callable=AsyncMock)
    async def test_dispatches_partial_and_failed_tunnels(self, mock_process):
        from app.services.reconciler import reconcile_once

        session = AsyncMock()
        # First call: returns candidate IDs; subsequent calls are for _process_tunnel
        session.execute.return_value = _mock_execute_scalars([10, 20])

        factory = _make_session_factory(session)
        state: dict[int, int] = {}
        settings = _make_settings(max_attempts=5)

        await reconcile_once(state, factory, settings)

        assert mock_process.await_count == 2
        called_ids = {call.args[1] for call in mock_process.call_args_list}
        assert called_ids == {10, 20}

    @patch("app.services.reconciler._process_tunnel", new_callable=AsyncMock)
    async def test_no_candidates_skips_processing(self, mock_process):
        from app.services.reconciler import reconcile_once

        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalars([])

        factory = _make_session_factory(session)
        state: dict[int, int] = {}

        await reconcile_once(state, factory, _make_settings())

        mock_process.assert_not_awaited()

    @patch("app.services.reconciler._process_tunnel", new_callable=AsyncMock)
    async def test_respects_max_attempts(self, mock_process):
        from app.services.reconciler import reconcile_once

        session = AsyncMock()
        # Tunnel 10 is exhausted; tunnel 20 is still eligible
        session.execute.return_value = _mock_execute_scalars([10, 20])

        factory = _make_session_factory(session)
        # Tunnel 10 has already hit max attempts
        state = {10: 5}
        settings = _make_settings(max_attempts=5)

        await reconcile_once(state, factory, settings)

        called_ids = {call.args[1] for call in mock_process.call_args_list}
        assert 10 not in called_ids
        assert 20 in called_ids

    @patch("app.services.reconciler._process_tunnel", new_callable=AsyncMock)
    async def test_all_max_attempts_reached(self, mock_process):
        from app.services.reconciler import reconcile_once

        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalars([1, 2])

        factory = _make_session_factory(session)
        state = {1: 5, 2: 5}
        settings = _make_settings(max_attempts=5)

        await reconcile_once(state, factory, settings)

        mock_process.assert_not_awaited()


# ---------------------------------------------------------------------------
# reconciler_loop — disabled flag
# ---------------------------------------------------------------------------

class TestReconcilerLoop:
    """Tests for reconciler_loop lifecycle behavior."""

    async def test_disabled_returns_immediately(self):
        """When reconciler_enabled=False, the loop returns without sleeping."""
        from app.services.reconciler import reconciler_loop

        factory = MagicMock()
        settings = _make_settings(enabled=False)

        # Should return immediately (no asyncio.sleep, no session)
        await reconciler_loop(factory, settings)

        factory.assert_not_called()

    @patch("app.services.reconciler.reconcile_once", new_callable=AsyncMock)
    @patch("app.services.reconciler.asyncio.sleep", new_callable=AsyncMock)
    async def test_enabled_calls_reconcile_once(self, mock_sleep, mock_reconcile):
        """Loop calls reconcile_once after each sleep, then stops on CancelledError."""
        from app.services.reconciler import reconciler_loop

        # After the first reconcile_once, raise CancelledError on the next sleep
        mock_sleep.side_effect = [None, asyncio.CancelledError()]

        factory = MagicMock()
        settings = _make_settings(enabled=True, interval=60, max_attempts=3)

        with pytest.raises(asyncio.CancelledError):
            await reconciler_loop(factory, settings)

        assert mock_reconcile.await_count == 1


# ---------------------------------------------------------------------------
# _process_tunnel — log event distinction
# ---------------------------------------------------------------------------


class TestProcessTunnelLogEvents:
    """Verify that distinct log events are emitted for synced vs still-failing."""

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="psk")
    @patch("app.services.reconciler.logger")
    async def test_logs_synced_on_full_success(
        self, mock_logger, mock_decrypt, mock_sync, mock_audit, mock_lock
    ):
        """Full fan-out success logs reconciler_tunnel_synced (info)."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "failed")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
        mock_sync.return_value = FanOutResult(total=2, succeeded=2, failed=0)

        await _process_tunnel({}, 1, session, _make_settings())

        info_events = [c.args[0] for c in mock_logger.info.call_args_list]
        assert "reconciler_tunnel_synced" in info_events
        warning_events = [c.args[0] for c in mock_logger.warning.call_args_list]
        assert "reconciler_tunnel_still_failing" not in warning_events

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="psk")
    @patch("app.services.reconciler.logger")
    async def test_logs_still_failing_on_partial(
        self, mock_logger, mock_decrypt, mock_sync, mock_audit, mock_lock
    ):
        """Partial fan-out result logs reconciler_tunnel_still_failing (warning)."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "failed")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
        mock_sync.return_value = FanOutResult(total=2, succeeded=1, failed=1)

        await _process_tunnel({}, 1, session, _make_settings())

        warning_events = [c.args[0] for c in mock_logger.warning.call_args_list]
        assert "reconciler_tunnel_still_failing" in warning_events
        info_events = [c.args[0] for c in mock_logger.info.call_args_list]
        assert "reconciler_tunnel_synced" not in info_events

    @patch("app.services.reconciler.acquire_advisory_lock", new_callable=AsyncMock, return_value=True)
    @patch("app.services.reconciler.audit.log_action", new_callable=AsyncMock)
    @patch("app.services.reconciler.ipsec_config.sync_tunnel_config", new_callable=AsyncMock)
    @patch("app.services.reconciler.kms.decrypt_psk", new_callable=AsyncMock, return_value="psk")
    @patch("app.services.reconciler.logger")
    async def test_logs_still_failing_on_total_failure(
        self, mock_logger, mock_decrypt, mock_sync, mock_audit, mock_lock
    ):
        """Total fan-out failure (all servers fail) logs reconciler_tunnel_still_failing."""
        from app.services.reconciler import _process_tunnel

        tunnel = _make_tunnel(1, "failed")
        session = AsyncMock()
        session.execute.return_value = _mock_execute_scalar_one_or_none(tunnel)
        mock_sync.return_value = FanOutResult(total=2, succeeded=0, failed=2)

        await _process_tunnel({}, 1, session, _make_settings())

        warning_events = [c.args[0] for c in mock_logger.warning.call_args_list]
        assert "reconciler_tunnel_still_failing" in warning_events
