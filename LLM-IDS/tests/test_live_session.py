"""
=============================================================================
test_live_session.py — Test suite for sniffer/live_session.py
=============================================================================

Coverage areas
--------------
  1. start() / stop() lifecycle    (sniffer wired up, worker thread managed)
  2. Failure to start               (sniffer failure -> nothing left running)
  3. Double-start is a no-op        (idempotent while already running)
  4. Classify loop integration      (a real flow, popped and saved for real,
                                     using the real FlowTracker + a throwaway DB)
  5. Fail-safe on a bad flow        (one exception doesn't kill the loop)
  5b. Sniff-thread failures         (a mid-capture adapter failure is
                                     surfaced via last_error, not swallowed)
  6. Fast stop                      (stop() doesn't block for a full
                                     expiry_check_interval)
  7. Flush on stop                  (in-progress flows are classified when
                                     capture stops, not silently dropped)
  8. session.results                (in-memory, session-scoped result list
                                     the dashboard reads instead of the DB)
  9. results_snapshot()             (safe copy for concurrent UI-thread
                                     reads while a background thread appends)

PacketSniffer itself is mocked (via sniffer.live_session.PacketSniffer) so
no real capture/privileges are involved — but the FlowTracker and database
writes are real, exercised through a temp DB file.

Run
---
    pytest tests/test_live_session.py -v
"""

import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from sniffer.live_session import LiveCaptureSession
from storage import db

# ---------------------------------------------------------------------------
# Fixtures / fakes
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    db_path = tmp_path / "test_flows.db"
    monkeypatch.setattr(config, "DB_PATH", str(db_path))
    db.init_db()
    return db_path


class FakeLLM:
    def __init__(self, fail_on_call=None, delay=0):
        self.calls = 0
        self._fail_on_call = fail_on_call
        self._delay = delay

    def classify(self, features):
        self.calls += 1
        if self._delay:
            time.sleep(self._delay)
        if self._fail_on_call == self.calls:
            raise RuntimeError("simulated classification failure")
        return {"classification": "Benign", "confidence": 0.9, "explanation": "ok"}


def _wait_for_flush(session, timeout=3):
    """Background flush after stop() isn't synchronous anymore — poll for
    it to finish instead of asserting immediately."""
    deadline = time.time() + timeout
    while session.flush_running and time.time() < deadline:
        time.sleep(0.02)


def _make_session(**overrides):
    kwargs = dict(
        interface="eth0",
        interface_label="Ethernet",
        llm_client=FakeLLM(),
        expiry_check_interval=0.05,
        flow_timeout_seconds=60,
    )
    kwargs.update(overrides)
    return LiveCaptureSession(**kwargs)


# ===========================================================================
# 1. start() / stop() lifecycle
# ===========================================================================

class TestLifecycle:

    @patch("sniffer.live_session.PacketSniffer")
    def test_start_marks_session_running(self, mock_sniffer_cls, temp_db):
        mock_sniffer_cls.return_value.start_async.return_value = None
        session = _make_session()
        session.start()
        try:
            assert session.running is True
            assert session.started_at is not None
            mock_sniffer_cls.return_value.start_async.assert_called_once()
        finally:
            session.stop()

    @patch("sniffer.live_session.PacketSniffer")
    def test_stop_marks_session_not_running_and_stops_sniffer(self, mock_sniffer_cls, temp_db):
        mock_sniffer_cls.return_value.start_async.return_value = None
        session = _make_session()
        session.start()
        session.stop()
        assert session.running is False
        mock_sniffer_cls.return_value.stop_async.assert_called_once()


# ===========================================================================
# 2. Failure to start
# ===========================================================================

class TestStartFailure:

    @patch("sniffer.live_session.PacketSniffer")
    def test_sniffer_failure_propagates_and_leaves_nothing_running(self, mock_sniffer_cls, temp_db):
        mock_sniffer_cls.return_value.start_async.side_effect = PermissionError("denied")
        session = _make_session()
        with pytest.raises(PermissionError):
            session.start()
        assert session.running is False
        assert session.started_at is None


# ===========================================================================
# 3. Double-start is a no-op
# ===========================================================================

class TestDoubleStart:

    @patch("sniffer.live_session.PacketSniffer")
    def test_starting_an_already_running_session_does_not_restart_sniffer(self, mock_sniffer_cls, temp_db):
        mock_sniffer_cls.return_value.start_async.return_value = None
        session = _make_session()
        session.start()
        try:
            session.start()  # second call — must be a no-op
            assert mock_sniffer_cls.return_value.start_async.call_count == 1
        finally:
            session.stop()


# ===========================================================================
# 4. Classify loop integration (real FlowTracker + real DB write)
# ===========================================================================

class TestClassifyLoopIntegration:

    @patch("sniffer.live_session.PacketSniffer")
    def test_a_closed_flow_is_classified_and_saved(self, mock_sniffer_cls, temp_db):
        mock_sniffer_cls.return_value.start_async.return_value = None
        llm = FakeLLM()
        session = _make_session(llm_client=llm)
        session.start()
        try:
            # Simulate what the (mocked) sniffer would normally feed in.
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "S")
            session.tracker.add_packet("10.0.0.2", "10.0.0.1", 80, 5000, "TCP", 100, "SA")
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "FA")

            # Give the background classify loop a couple of cycles to run.
            deadline = time.time() + 2
            while session.flows_classified == 0 and time.time() < deadline:
                time.sleep(0.05)

            assert session.flows_classified == 1
            assert llm.calls == 1
            assert session.tracker.active_flow_count() == 0

            saved = db.get_recent_results()
            assert len(saved) == 1
            assert saved[0]["classification"] == "Benign"
        finally:
            session.stop()


# ===========================================================================
# 5. Fail-safe on a bad flow
# ===========================================================================

class TestFailSafeOnBadFlow:

    @patch("sniffer.live_session.PacketSniffer")
    def test_one_bad_flow_does_not_kill_the_loop(self, mock_sniffer_cls, temp_db):
        mock_sniffer_cls.return_value.start_async.return_value = None
        llm = FakeLLM(fail_on_call=1)  # first classify() call raises
        session = _make_session(llm_client=llm)
        session.start()
        try:
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "FA")

            deadline = time.time() + 2
            while session.last_error is None and time.time() < deadline:
                time.sleep(0.05)
            assert session.last_error is not None
            assert session.running is True  # thread survived the exception

            # A second, healthy flow should still get processed afterward.
            session.tracker.add_packet("10.0.0.3", "10.0.0.4", 6000, 443, "TCP", 100, "FA")
            deadline = time.time() + 2
            while session.flows_classified == 0 and time.time() < deadline:
                time.sleep(0.05)
            assert session.flows_classified == 1
        finally:
            session.stop()


# ===========================================================================
# 5b. Sniff-thread failures are surfaced (regression test: a mid-capture
#     adapter failure used to be silently swallowed)
# ===========================================================================

class TestSniffErrorSurfacing:

    @patch("sniffer.live_session.PacketSniffer")
    def test_sniff_error_is_surfaced_as_last_error(self, mock_sniffer_cls, temp_db):
        mock_sniffer = mock_sniffer_cls.return_value
        mock_sniffer.start_async.return_value = None
        mock_sniffer.sniff_error = None  # nothing wrong yet

        session = _make_session(expiry_check_interval=0.05)
        session.start()
        try:
            assert session.last_error is None

            # Simulate the adapter dying mid-capture.
            mock_sniffer.sniff_error = OSError("adapter disconnected")

            deadline = time.time() + 2
            while session.last_error is None and time.time() < deadline:
                time.sleep(0.02)

            assert session.last_error is not None
            assert "adapter disconnected" in session.last_error
        finally:
            session.stop()

    @patch("sniffer.live_session.PacketSniffer")
    def test_a_real_classification_error_is_not_overwritten_by_a_stale_check(self, mock_sniffer_cls, temp_db):
        """Once last_error is set (by either cause), the loop's sniff_error
        check must not keep clobbering it — the first recorded error is
        what matters, not whichever one happened to be checked most
        recently."""
        mock_sniffer = mock_sniffer_cls.return_value
        mock_sniffer.start_async.return_value = None
        mock_sniffer.sniff_error = None

        llm = FakeLLM(fail_on_call=1)
        session = _make_session(llm_client=llm, expiry_check_interval=0.05)
        session.start()
        try:
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "FA")
            deadline = time.time() + 2
            while session.last_error is None and time.time() < deadline:
                time.sleep(0.02)
            first_error = session.last_error
            assert first_error is not None

            mock_sniffer.sniff_error = OSError("a different failure")
            time.sleep(0.2)  # let a few more loop iterations pass
            assert session.last_error == first_error
        finally:
            session.stop()


# ===========================================================================
# 6. Fast stop (regression test: stop() must not block for a full
#    expiry_check_interval)
# ===========================================================================

class TestFastStop:

    @patch("sniffer.live_session.PacketSniffer")
    def test_stop_returns_quickly_even_with_a_long_interval(self, mock_sniffer_cls, temp_db):
        """Before the fix, the background loop used time.sleep(interval) and
        only checked the stop flag after waking up — so stop() could block
        for nearly the full interval. With a long interval and no active
        flows, stop() must still return almost immediately."""
        session = _make_session(expiry_check_interval=10)  # deliberately long
        session.start()
        start = time.time()
        session.stop()
        elapsed = time.time() - start
        assert elapsed < 2, f"stop() took {elapsed:.2f}s — should be near-instant"

    @patch("sniffer.live_session.PacketSniffer")
    def test_stop_returns_quickly_even_with_many_slow_active_flows(self, mock_sniffer_cls, temp_db):
        """Regression test: stop() must never block on classifying whatever
        flows were still active — that work (a real LLM call per flow) now
        happens in a background thread. Simulates a slow LLM (0.3s/call)
        across several active flows; stop() itself must still return almost
        instantly regardless."""
        llm = FakeLLM(delay=0.3)
        session = _make_session(llm_client=llm, expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            for port in range(5):
                session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000 + port, 80, "TCP", 100, "S")

            start = time.time()
            session.stop()
            elapsed = time.time() - start

            assert elapsed < 1, f"stop() took {elapsed:.2f}s — must not wait on flow classification"
            # The flows are still expected to get classified — just later.
            assert session.flush_running or session.flows_classified > 0
        finally:
            _wait_for_flush(session)


# ===========================================================================
# 7. Flush on stop (regression test: in-progress flows must not be
#    silently discarded when capture stops — but classifying them must
#    happen in the background, not block stop() itself)
# ===========================================================================

class TestFlushOnStop:

    @patch("sniffer.live_session.PacketSniffer")
    def test_active_unfinished_flow_is_classified_on_stop(self, mock_sniffer_cls, temp_db):
        """A flow with no FIN/RST and well within its timeout window is
        still 'active', not 'finished' — pop_finished_flows() would never
        return it on its own. stop() must flush it anyway, since there's no
        more capture coming to close or time it out naturally."""
        # Long interval so the periodic loop never fires during this test —
        # everything must come from stop()'s flush, not the loop.
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "S")
            assert session.tracker.active_flow_count() == 1
            assert session.flows_classified == 0  # not yet processed by the loop

            session.stop()
            assert session.tracker.active_flow_count() == 0  # handed off synchronously
            _wait_for_flush(session)

            assert session.flows_classified == 1
            assert len(db.get_recent_results()) == 1
        finally:
            if session.running:
                session.stop()
            _wait_for_flush(session)

    @patch("sniffer.live_session.PacketSniffer")
    def test_multiple_active_flows_are_all_flushed(self, mock_sniffer_cls, temp_db):
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            for port in range(5):
                session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000 + port, 80, "TCP", 100, "S")
            session.stop()
            _wait_for_flush(session)
            assert session.flows_classified == 5
        finally:
            if session.running:
                session.stop()
            _wait_for_flush(session)

    @patch("sniffer.live_session.PacketSniffer")
    def test_stop_with_no_active_flows_does_not_raise(self, mock_sniffer_cls, temp_db):
        session = _make_session(expiry_check_interval=10)
        session.start()
        session.stop()  # must not raise
        assert session.flows_classified == 0
        assert session.flush_running is False

    @patch("sniffer.live_session.PacketSniffer")
    def test_flush_progress_is_pollable_via_flush_done_and_flush_total(self, mock_sniffer_cls, temp_db):
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            for port in range(3):
                session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000 + port, 80, "TCP", 100, "S")

            session.stop()
            assert session.flush_total == 3

            _wait_for_flush(session)
            assert session.flush_done == 3
            assert session.flush_running is False
        finally:
            if session.running:
                session.stop()
            _wait_for_flush(session)


# ===========================================================================
# 8. session.results (dashboard's in-memory, session-scoped view)
# ===========================================================================

class TestResultsAccumulation:

    @patch("sniffer.live_session.PacketSniffer")
    def test_results_starts_empty(self, mock_sniffer_cls, temp_db):
        session = _make_session()
        assert session.results == []

    @patch("sniffer.live_session.PacketSniffer")
    def test_classified_flow_is_recorded_in_results(self, mock_sniffer_cls, temp_db):
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "S")
            session.stop()
            _wait_for_flush(session)

            assert len(session.results) == 1
            entry = session.results[0]
            assert entry["flow_id"] == "10.0.0.1:5000->10.0.0.2:80/TCP"
            assert entry["classification"] == "Benign"
            assert "confidence" in entry
            assert "explanation" in entry
        finally:
            if session.running:
                session.stop()
            _wait_for_flush(session)

    @patch("sniffer.live_session.PacketSniffer")
    def test_result_entry_carries_id_and_features_for_report_and_feedback(self, mock_sniffer_cls, temp_db):
        """The dashboard's Flow tools (incident report, analyst feedback)
        must be able to act on a session-scoped entry directly, without a
        separate database-wide lookup — so each entry needs the same real
        row id save_result() produced, plus the feature data a report is
        built from."""
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "S")
            session.stop()
            _wait_for_flush(session)

            entry = session.results[0]
            assert isinstance(entry["id"], int)

            # The id must correspond to a real row (feedback references it
            # via a foreign key).
            saved = db.get_result_by_id(entry["id"])
            assert saved is not None
            assert saved["flow_id"] == entry["flow_id"]

            # features_json must be usable by report_generator as-is.
            assert entry["features_json"]["flow_id"] == entry["flow_id"]
        finally:
            if session.running:
                session.stop()
            _wait_for_flush(session)

    @patch("sniffer.live_session.PacketSniffer")
    def test_failed_classification_is_not_recorded_in_results(self, mock_sniffer_cls, temp_db):
        """A flow whose classify() call raises must not produce a
        half-formed entry in results — only successful classifications
        should show up in the dashboard's table."""
        llm = FakeLLM(fail_on_call=1)
        session = _make_session(llm_client=llm, expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "S")
            session.stop()
            _wait_for_flush(session)

            assert session.results == []
            assert session.last_error is not None
        finally:
            if session.running:
                session.stop()


# ===========================================================================
# 9. results_snapshot() (safe concurrent read while the classify loop or
#    flush thread may be appending)
# ===========================================================================

class TestResultsSnapshot:

    @patch("sniffer.live_session.PacketSniffer")
    def test_snapshot_of_empty_session_is_empty_list(self, mock_sniffer_cls, temp_db):
        session = _make_session()
        assert session.results_snapshot() == []

    @patch("sniffer.live_session.PacketSniffer")
    def test_snapshot_reflects_classified_flows(self, mock_sniffer_cls, temp_db):
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "S")
            session.stop()
            _wait_for_flush(session)

            snapshot = session.results_snapshot()
            assert len(snapshot) == 1
            assert snapshot[0]["flow_id"] == "10.0.0.1:5000->10.0.0.2:80/TCP"
        finally:
            if session.running:
                session.stop()
            _wait_for_flush(session)

    @patch("sniffer.live_session.PacketSniffer")
    def test_snapshot_is_a_copy_not_a_live_reference(self, mock_sniffer_cls, temp_db):
        """Mutating the returned list must not affect the session's own
        internal results list — callers (the dashboard) shouldn't be able
        to corrupt session state just by touching what they were handed."""
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "S")
            session.stop()
            _wait_for_flush(session)

            snapshot = session.results_snapshot()
            snapshot.append({"flow_id": "fabricated", "classification": "Attack"})

            assert len(session.results) == 1
            assert len(session.results_snapshot()) == 1
        finally:
            if session.running:
                session.stop()
            _wait_for_flush(session)

    @patch("sniffer.live_session.PacketSniffer")
    def test_snapshot_taken_concurrently_with_appends_does_not_raise(self, mock_sniffer_cls, temp_db):
        """The regression this guards against: reading self.results while a
        background thread appends to it. Fires many classifications back to
        back and repeatedly snapshots from the 'UI thread' at the same
        time — must never raise, regardless of interleaving."""
        session = _make_session(expiry_check_interval=0.01, flow_timeout_seconds=600)
        session.start()
        try:
            for port in range(30):
                session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000 + port, 80, "TCP", 100, "FA")

            errors = []

            def _poll_snapshots():
                deadline = time.time() + 1
                while time.time() < deadline:
                    try:
                        session.results_snapshot()
                    except Exception as exc:
                        errors.append(exc)

            poller = threading.Thread(target=_poll_snapshots)
            poller.start()
            poller.join()

            assert errors == []
        finally:
            session.stop()
            _wait_for_flush(session)
            _wait_for_flush(session)
