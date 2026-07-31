"""Lightweight SQLite layer that decouples the dashboard from the detection
pipeline — the pipeline only ever writes here, the dashboard only ever reads.
This means you can swap the dashboard tech later without touching detection
logic at all.
"""

import json
import sqlite3
import time
from contextlib import contextmanager

import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS flow_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    flow_id TEXT NOT NULL,
    src_ip TEXT, dst_ip TEXT,
    src_port INTEGER, dst_port INTEGER,
    protocol TEXT,
    classification TEXT NOT NULL,
    confidence REAL,
    explanation TEXT,
    features_json TEXT
);
"""


@contextmanager
def _connect():
    conn = sqlite3.connect(config.DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    with _connect() as conn:
        conn.execute(SCHEMA)
        conn.commit()


def save_result(features: dict, verdict: dict):
    proto = features["protocol_info"]
    with _connect() as conn:
        conn.execute(
            """INSERT INTO flow_results
               (timestamp, flow_id, src_ip, dst_ip, src_port, dst_port, protocol,
                classification, confidence, explanation, features_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                time.time(), features["flow_id"],
                proto["src_ip"], proto["dst_ip"], proto["src_port"], proto["dst_port"], proto["protocol"],
                verdict["classification"], verdict["confidence"], verdict["explanation"],
                json.dumps(features),
            ),
        )
        conn.commit()


def get_recent_results(limit: int = 100):
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM flow_results ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]