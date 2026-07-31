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
  6. Fast stop                      (stop() doesn't block for a full
                                     expiry_check_interval)
  7. Flush on stop                  (in-progress flows are classified when
                                     capture stops, not silently dropped)
  8. session.results                (in-memory, session-scoped result list
                                     the dashboard reads instead of the DB)

PacketSniffer itself is mocked (via sniffer.live_session.PacketSniffer) so
no real capture/privileges are involved — but the FlowTracker and database
writes are real, exercised through a temp DB file.

Run
---
    pytest tests/test_live_session.py -v
"""

import sys
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
    def __init__(self, fail_on_call=None):
        self.calls = 0
        self._fail_on_call = fail_on_call

    def classify(self, features):
        self.calls += 1
        if self._fail_on_call == self.calls:
            raise RuntimeError("simulated classification failure")
        return {"classification": "Benign", "confidence": 0.9, "explanation": "ok"}


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


# ===========================================================================
# 7. Flush on stop (regression test: in-progress flows must not be
#    silently discarded when capture stops)
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

            assert session.flows_classified == 1
            assert session.tracker.active_flow_count() == 0
            assert len(db.get_recent_results()) == 1
        finally:
            if session.running:
                session.stop()

    @patch("sniffer.live_session.PacketSniffer")
    def test_multiple_active_flows_are_all_flushed(self, mock_sniffer_cls, temp_db):
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            for port in range(5):
                session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000 + port, 80, "TCP", 100, "S")
            session.stop()
            assert session.flows_classified == 5
        finally:
            if session.running:
                session.stop()

    @patch("sniffer.live_session.PacketSniffer")
    def test_stop_with_no_active_flows_does_not_raise(self, mock_sniffer_cls, temp_db):
        session = _make_session(expiry_check_interval=10)
        session.start()
        session.stop()  # must not raise
        assert session.flows_classified == 0

    @patch("sniffer.live_session.PacketSniffer")
    def test_progress_callback_invoked_once_per_flushed_flow(self, mock_sniffer_cls, temp_db):
        session = _make_session(expiry_check_interval=10, flow_timeout_seconds=600)
        session.start()
        try:
            for port in range(3):
                session.tracker.add_packet("10.0.0.1", "10.0.0.2", 5000 + port, 80, "TCP", 100, "S")

            calls = []
            session.stop(progress_callback=lambda done, total: calls.append((done, total)))

            assert calls == [(1, 3), (2, 3), (3, 3)]
        finally:
            if session.running:
                session.stop()


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

            assert len(session.results) == 1
            entry = session.results[0]
            assert entry["flow_id"] == "10.0.0.1:5000->10.0.0.2:80/TCP"
            assert entry["classification"] == "Benign"
            assert "confidence" in entry
            assert "explanation" in entry
        finally:
            if session.running:
                session.stop()

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

            assert session.results == []
            assert session.last_error is not None
        finally:
            if session.running:
                session.stop()
