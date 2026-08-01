"""
=============================================================================
test_main.py — Test suite for main.py
=============================================================================

Coverage areas
--------------
  1. _classify_and_save()          (classifies, saves, prints — the shared
                                     helper used by both the main loop and
                                     the Ctrl+C flush)
  2. Ctrl+C flushes remaining flows (regression test: flows still active —
                                     not yet closed/timed out — at interrupt
                                     time used to be silently dropped, same
                                     class of bug pcap_reader.py had before
                                     pop_all_flows())

PacketSniffer and FlowTracker are patched at the main.py import site so no
real network access or threading surprises are involved — a real FlowTracker
instance is still used underneath so pop_all_flows() behavior is genuine,
not mocked.

Run
---
    pytest tests/test_main.py -v
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
import main
from sniffer.flow_tracker import Flow, FlowTracker, PacketRecord
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
    def classify(self, features):
        return {"classification": "Benign", "confidence": 0.9, "explanation": "looks fine"}


def _make_flow(sport=5000):
    return Flow(
        key=("10.0.0.1", "10.0.0.2", sport, 80, "TCP"),
        start_time=1000.0,
        last_seen=1000.5,
        packets=[PacketRecord(timestamp=1000.0, size=100, direction="fwd", tcp_flags="S")],
    )


# ===========================================================================
# 1. _classify_and_save()
# ===========================================================================

class TestClassifyAndSave:

    def test_classifies_and_saves_the_flow(self, temp_db):
        main._classify_and_save(_make_flow(), FakeLLM())
        results = db.get_recent_results()
        assert len(results) == 1
        assert results[0]["classification"] == "Benign"

    def test_prints_the_verdict(self, temp_db, capsys):
        main._classify_and_save(_make_flow(), FakeLLM())
        captured = capsys.readouterr()
        assert "Benign" in captured.out
        assert "10.0.0.1:5000->10.0.0.2:80/TCP" in captured.out


# ===========================================================================
# 2. Ctrl+C flushes remaining flows (regression test)
# ===========================================================================

class TestFlushOnInterrupt:

    @patch("main.LLMClient")
    @patch("main.PacketSniffer")
    @patch("main.FlowTracker")
    @patch("main.time.sleep")
    def test_active_flow_is_classified_when_interrupted(
        self, mock_sleep, mock_tracker_cls, mock_sniffer_cls, mock_llm_cls, temp_db, capsys
    ):
        """A flow that never closes (no FIN/RST) and hasn't timed out is
        still 'active', not 'finished' — pop_finished_flows() alone would
        never return it. Ctrl+C must flush it anyway, since there's no more
        capture coming to close or time it out naturally."""
        real_tracker = FlowTracker(timeout_seconds=600)
        real_tracker.add_packet("10.0.0.1", "10.0.0.2", 5000, 80, "TCP", 100, "S")
        mock_tracker_cls.return_value = real_tracker

        mock_sniffer_cls.return_value.start = MagicMock()
        mock_llm_cls.return_value = FakeLLM()
        mock_sleep.side_effect = KeyboardInterrupt()

        main.main()

        results = db.get_recent_results()
        assert len(results) == 1
        assert real_tracker.active_flow_count() == 0

        captured = capsys.readouterr()
        assert "Stopping" in captured.out

    @patch("main.LLMClient")
    @patch("main.PacketSniffer")
    @patch("main.FlowTracker")
    @patch("main.time.sleep")
    def test_no_active_flows_prints_plain_stopping_message(
        self, mock_sleep, mock_tracker_cls, mock_sniffer_cls, mock_llm_cls, temp_db, capsys
    ):
        mock_tracker_cls.return_value = FlowTracker(timeout_seconds=600)
        mock_sniffer_cls.return_value.start = MagicMock()
        mock_llm_cls.return_value = FakeLLM()
        mock_sleep.side_effect = KeyboardInterrupt()

        main.main()  # must not raise, must not try to classify anything

        assert db.get_recent_results() == []
        captured = capsys.readouterr()
        assert "Stopping" in captured.out

    @patch("main.LLMClient")
    @patch("main.PacketSniffer")
    @patch("main.FlowTracker")
    @patch("main.time.sleep")
    def test_multiple_active_flows_are_all_flushed(
        self, mock_sleep, mock_tracker_cls, mock_sniffer_cls, mock_llm_cls, temp_db
    ):
        real_tracker = FlowTracker(timeout_seconds=600)
        for port in range(4):
            real_tracker.add_packet("10.0.0.1", "10.0.0.2", 5000 + port, 80, "TCP", 100, "S")
        mock_tracker_cls.return_value = real_tracker

        mock_sniffer_cls.return_value.start = MagicMock()
        mock_llm_cls.return_value = FakeLLM()
        mock_sleep.side_effect = KeyboardInterrupt()

        main.main()

        assert len(db.get_recent_results()) == 4
