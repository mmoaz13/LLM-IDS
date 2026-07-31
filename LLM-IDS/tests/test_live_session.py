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
