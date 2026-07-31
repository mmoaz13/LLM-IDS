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


def _sample_features(flow_id="10.0.0.1:5000->10.0.0.2:80/TCP"):
    return {
        "flow_id": flow_id,
        "statistics": {"duration_seconds": 1.0, "packet_count": 4, "byte_count": 400,
                        "avg_packet_size": 100.0, "packets_per_second": 4.0,
                        "fwd_packet_count": 2, "rev_packet_count": 2},
        "protocol_info": {"protocol": "TCP", "src_ip": "10.0.0.1", "dst_ip": "10.0.0.2",
                           "src_port": 5000, "dst_port": 80},
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
