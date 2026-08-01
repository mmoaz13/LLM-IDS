"""
=============================================================================
test_db.py — Test suite for storage/db.py
=============================================================================

Coverage areas
--------------
  1. Schema setup           (init_db creates the table, is safe to call twice)
  2. Save / read round trip (save_result -> get_recent_results returns it)
  3. features_json integrity (regression test: must be real JSON, not repr())
  4. Ordering and limits    (most recent first, limit is respected)

Each test gets its own throwaway SQLite file via monkeypatching
config.DB_PATH, so tests never touch the project's real storage/flows.db
and can run in any order.

Run
---
    pytest tests/test_db.py -v

Requirements
------------
    pip install pytest
"""

import json
import sqlite3
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import config
from storage import db

# ---------------------------------------------------------------------------
# Fixtures / helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def temp_db(tmp_path, monkeypatch):
    """Point config.DB_PATH at a throwaway file for the duration of a test."""
    db_path = tmp_path / "test_flows.db"
    monkeypatch.setattr(config, "DB_PATH", str(db_path))
    db.init_db()
    return db_path


def _connect_raw(db_path):
    """Direct sqlite3 connection for test setup that db.py's public API
    doesn't expose (e.g. back-dating a row's timestamp)."""
    return sqlite3.connect(str(db_path))


def _sample_features(flow_id="10.0.0.1:5000->10.0.0.2:80/TCP", protocol="TCP",
                      src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=5000, dst_port=80):
    return {
        "flow_id": flow_id,
        "statistics": {"duration_seconds": 1.0, "packet_count": 4, "byte_count": 400,
                        "avg_packet_size": 100.0, "packets_per_second": 4.0,
                        "fwd_packet_count": 2, "rev_packet_count": 2},
        "protocol_info": {"protocol": protocol, "src_ip": src_ip, "dst_ip": dst_ip,
                           "src_port": src_port, "dst_port": dst_port},
        "flags": {"syn_count": 1, "ack_count": 3, "fin_count": 0, "rst_count": 0,
                  "psh_count": 1, "urg_count": 0, "syn_without_ack": False},
    }


def _sample_verdict(classification="Benign", confidence=0.9, explanation="Looks fine."):
    return {"classification": classification, "confidence": confidence, "explanation": explanation}


# ===========================================================================
# 1. Schema setup
# ===========================================================================

class TestSchemaSetup:

    def test_init_db_creates_file(self, temp_db):
        assert temp_db.exists()

    def test_init_db_is_idempotent(self, temp_db):
        """Calling init_db a second time (e.g. dashboard + pipeline both
        starting up) must not raise or wipe existing data."""
        db.save_result(_sample_features(), _sample_verdict())
        db.init_db()  # should be a no-op, not recreate the table
        results = db.get_recent_results()
        assert len(results) == 1

    def test_wal_mode_is_enabled(self, temp_db):
        """This project routinely has several writers active against the
        same file at once (main.py, Live Capture's classify loop, its
        flush thread, Simulate Attacks) plus the dashboard reading —
        WAL mode is what keeps those from blocking each other."""
        with sqlite3.connect(str(temp_db)) as conn:
            mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode.lower() == "wal"


# ===========================================================================
# 2. Save / read round trip
# ===========================================================================

class TestSaveAndRead:

    def test_saved_result_is_retrievable(self, temp_db):
        db.save_result(_sample_features(), _sample_verdict(classification="Attack", confidence=0.95))
        results = db.get_recent_results()

        assert len(results) == 1
        row = results[0]
        assert row["flow_id"] == "10.0.0.1:5000->10.0.0.2:80/TCP"
        assert row["classification"] == "Attack"
        assert row["confidence"] == 0.95
        assert row["src_ip"] == "10.0.0.1"
        assert row["dst_port"] == 80
        assert row["protocol"] == "TCP"

    def test_multiple_results_all_saved(self, temp_db):
        for i in range(5):
            db.save_result(_sample_features(flow_id=f"flow-{i}"), _sample_verdict())
        results = db.get_recent_results(limit=10)
        assert len(results) == 5

    def test_save_result_returns_the_new_rows_id(self, temp_db):
        row_id = db.save_result(_sample_features(), _sample_verdict())
        fetched = db.get_result_by_id(row_id)
        assert fetched is not None
        assert fetched["flow_id"] == "10.0.0.1:5000->10.0.0.2:80/TCP"

    def test_save_result_ids_increase_with_each_call(self, temp_db):
        first_id = db.save_result(_sample_features(flow_id="a"), _sample_verdict())
        second_id = db.save_result(_sample_features(flow_id="b"), _sample_verdict())
        assert second_id > first_id


# ===========================================================================
# 3. features_json integrity (regression test for str()-vs-json.dumps() bug)
# ===========================================================================

class TestFeaturesJsonIntegrity:

    def test_features_json_is_valid_parseable_json(self, temp_db):
        features = _sample_features()
        db.save_result(features, _sample_verdict())
        row = db.get_recent_results()[0]

        # This must not raise — a Python repr() string (e.g. with single
        # quotes and `True`/`False`) is not valid JSON and would fail here.
        parsed = json.loads(row["features_json"])
        assert parsed == features

    def test_features_json_round_trips_nested_structures(self, temp_db):
        features = _sample_features()
        features["flags"]["syn_without_ack"] = True  # Python bool -> JSON true
        db.save_result(features, _sample_verdict())
        row = db.get_recent_results()[0]

        parsed = json.loads(row["features_json"])
        assert parsed["flags"]["syn_without_ack"] is True
        assert parsed["statistics"]["packet_count"] == 4


# ===========================================================================
# 4. Ordering and limits
# ===========================================================================

class TestOrderingAndLimits:

    def test_results_ordered_most_recent_first(self, temp_db):
        db.save_result(_sample_features(flow_id="oldest"), _sample_verdict())
        time.sleep(0.01)
        db.save_result(_sample_features(flow_id="newest"), _sample_verdict())

        results = db.get_recent_results()
        assert results[0]["flow_id"] == "newest"
        assert results[-1]["flow_id"] == "oldest"

    def test_limit_is_respected(self, temp_db):
        for i in range(10):
            db.save_result(_sample_features(flow_id=f"flow-{i}"), _sample_verdict())
        results = db.get_recent_results(limit=3)
        assert len(results) == 3

    def test_no_results_returns_empty_list(self, temp_db):
        assert db.get_recent_results() == []


# ===========================================================================
# 5. get_result_by_id
# ===========================================================================

class TestGetResultById:

    def test_returns_the_matching_row(self, temp_db):
        db.save_result(_sample_features(flow_id="target"), _sample_verdict())
        [row] = db.get_recent_results()
        fetched = db.get_result_by_id(row["id"])
        assert fetched["flow_id"] == "target"

    def test_missing_id_returns_none(self, temp_db):
        assert db.get_result_by_id(9999) is None


# ===========================================================================
# 6. query_results (used by the NL "Ask" feature and the dashboard's flow search)
# ===========================================================================

class TestQueryResults:

    def test_no_filters_returns_everything_up_to_limit(self, temp_db):
        for i in range(3):
            db.save_result(_sample_features(flow_id=f"flow-{i}"), _sample_verdict())
        results = db.query_results({}, limit=10)
        assert len(results) == 3

    def test_filters_by_classification(self, temp_db):
        db.save_result(_sample_features(flow_id="a"), _sample_verdict(classification="Attack"))
        db.save_result(_sample_features(flow_id="b"), _sample_verdict(classification="Benign"))
        results = db.query_results({"classification": "Attack"}, limit=10)
        assert [r["flow_id"] for r in results] == ["a"]

    def test_filters_by_protocol(self, temp_db):
        db.save_result(_sample_features(flow_id="tcp-flow", protocol="TCP"), _sample_verdict())
        db.save_result(_sample_features(flow_id="udp-flow", protocol="UDP"), _sample_verdict())
        results = db.query_results({"protocol": "UDP"}, limit=10)
        assert [r["flow_id"] for r in results] == ["udp-flow"]

    def test_filters_by_src_ip(self, temp_db):
        db.save_result(_sample_features(flow_id="a", src_ip="1.2.3.4"), _sample_verdict())
        db.save_result(_sample_features(flow_id="b", src_ip="5.6.7.8"), _sample_verdict())
        results = db.query_results({"src_ip": "1.2.3.4"}, limit=10)
        assert [r["flow_id"] for r in results] == ["a"]

    def test_filters_by_dst_ip(self, temp_db):
        db.save_result(_sample_features(flow_id="a", dst_ip="9.9.9.9"), _sample_verdict())
        db.save_result(_sample_features(flow_id="b", dst_ip="8.8.8.8"), _sample_verdict())
        results = db.query_results({"dst_ip": "9.9.9.9"}, limit=10)
        assert [r["flow_id"] for r in results] == ["a"]

    def test_port_filter_matches_either_src_or_dst_port(self, temp_db):
        db.save_result(_sample_features(flow_id="src-match", src_port=2222, dst_port=80), _sample_verdict())
        db.save_result(_sample_features(flow_id="dst-match", src_port=5000, dst_port=2222), _sample_verdict())
        db.save_result(_sample_features(flow_id="no-match", src_port=5000, dst_port=80), _sample_verdict())
        results = db.query_results({"port": 2222}, limit=10)
        assert {r["flow_id"] for r in results} == {"src-match", "dst-match"}

    def test_since_minutes_ago_excludes_older_rows(self, temp_db):
        db.save_result(_sample_features(flow_id="old"), _sample_verdict())
        with _connect_raw(temp_db) as conn:
            conn.execute("UPDATE flow_results SET timestamp = ? WHERE flow_id = 'old'",
                         (time.time() - 3600,))  # 1 hour ago
            conn.commit()
        db.save_result(_sample_features(flow_id="recent"), _sample_verdict())

        results = db.query_results({"since_minutes_ago": 10}, limit=10)
        assert [r["flow_id"] for r in results] == ["recent"]

    def test_combined_filters_are_and_ed_together(self, temp_db):
        db.save_result(_sample_features(flow_id="match", protocol="TCP"),
                        _sample_verdict(classification="Attack"))
        db.save_result(_sample_features(flow_id="wrong-protocol", protocol="UDP"),
                        _sample_verdict(classification="Attack"))
        db.save_result(_sample_features(flow_id="wrong-classification", protocol="TCP"),
                        _sample_verdict(classification="Benign"))
        results = db.query_results({"classification": "Attack", "protocol": "TCP"}, limit=10)
        assert [r["flow_id"] for r in results] == ["match"]

    def test_limit_is_respected(self, temp_db):
        for i in range(5):
            db.save_result(_sample_features(flow_id=f"flow-{i}"), _sample_verdict())
        results = db.query_results({}, limit=2)
        assert len(results) == 2

    def test_values_are_parameterized_not_interpolated(self, temp_db):
        """A filter value containing SQL syntax must be treated as a literal
        string to match against, never executed."""
        db.save_result(_sample_features(flow_id="a", src_ip="1.2.3.4"), _sample_verdict())
        malicious = "1.2.3.4' OR '1'='1"
        results = db.query_results({"src_ip": malicious}, limit=10)
        assert results == []  # no row has that literal src_ip, so nothing matches


# ===========================================================================
# 6b. query_results 'search' filter (free-text flow picker)
# ===========================================================================

class TestQueryResultsSearch:

    def test_search_matches_substring_of_flow_id(self, temp_db):
        db.save_result(
            _sample_features(flow_id="10.0.0.1:5000->10.0.0.2:80/TCP", src_ip="10.0.0.1", dst_ip="10.0.0.2"),
            _sample_verdict(),
        )
        db.save_result(
            _sample_features(flow_id="9.9.9.9:1234->8.8.8.8:53/UDP", src_ip="9.9.9.9", dst_ip="8.8.8.8"),
            _sample_verdict(),
        )
        results = db.query_results({"search": "10.0.0.1"}, limit=10)
        assert len(results) == 1
        assert "10.0.0.1" in results[0]["flow_id"]

    def test_search_matches_src_ip(self, temp_db):
        db.save_result(_sample_features(flow_id="a", src_ip="203.0.113.5"), _sample_verdict())
        db.save_result(_sample_features(flow_id="b", src_ip="192.168.1.1"), _sample_verdict())
        results = db.query_results({"search": "203.0.113.5"}, limit=10)
        assert [r["flow_id"] for r in results] == ["a"]

    def test_search_matches_dst_port_substring(self, temp_db):
        db.save_result(_sample_features(flow_id="a", dst_port=8443), _sample_verdict())
        db.save_result(_sample_features(flow_id="b", dst_port=80), _sample_verdict())
        results = db.query_results({"search": "8443"}, limit=10)
        assert [r["flow_id"] for r in results] == ["a"]

    def test_search_combined_with_classification_filter(self, temp_db):
        db.save_result(_sample_features(flow_id="a", src_ip="10.0.0.9"),
                        _sample_verdict(classification="Attack"))
        db.save_result(_sample_features(flow_id="b", src_ip="10.0.0.9"),
                        _sample_verdict(classification="Benign"))
        results = db.query_results({"search": "10.0.0.9", "classification": "Attack"}, limit=10)
        assert [r["flow_id"] for r in results] == ["a"]

    def test_blank_search_is_ignored(self, temp_db):
        db.save_result(_sample_features(flow_id="a"), _sample_verdict())
        db.save_result(_sample_features(flow_id="b"), _sample_verdict())
        results = db.query_results({"search": "   "}, limit=10)
        assert len(results) == 2

    def test_no_match_returns_empty_list(self, temp_db):
        db.save_result(_sample_features(flow_id="a"), _sample_verdict())
        results = db.query_results({"search": "nothing-matches-this"}, limit=10)
        assert results == []

    def test_search_term_is_parameterized_not_interpolated(self, temp_db):
        db.save_result(_sample_features(flow_id="a", src_ip="1.2.3.4"), _sample_verdict())
        malicious = "%' OR '1'='1"
        results = db.query_results({"search": malicious}, limit=10)
        assert results == []  # treated as a literal substring, not SQL


# ===========================================================================
# 7. Feedback (human-in-the-loop corrections)
# ===========================================================================

class TestFeedback:

    def test_save_and_summarize_feedback(self, temp_db):
        db.save_result(_sample_features(), _sample_verdict())
        [row] = db.get_recent_results()

        db.save_feedback(row["id"], row["classification"], "correct")
        db.save_feedback(row["id"], row["classification"], "false_positive", note="too aggressive")

        summary = db.get_feedback_summary()
        assert summary == {"correct": 1, "false_positive": 1}

    def test_empty_feedback_summary_is_empty_dict(self, temp_db):
        assert db.get_feedback_summary() == {}

    def test_feedback_note_defaults_to_empty_string(self, temp_db):
        db.save_result(_sample_features(), _sample_verdict())
        [row] = db.get_recent_results()
        db.save_feedback(row["id"], row["classification"], "correct")
        # No exception, and the summary still reflects the row
        assert db.get_feedback_summary()["correct"] == 1
