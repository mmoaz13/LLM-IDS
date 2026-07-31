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

FEEDBACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    result_id INTEGER NOT NULL,
    original_classification TEXT NOT NULL,
    feedback_type TEXT NOT NULL,
    note TEXT,
    timestamp REAL NOT NULL,
    FOREIGN KEY (result_id) REFERENCES flow_results (id)
);
"""

# The three human-in-the-loop verdicts the dashboard can record against a
# classification. Kept here (not enforced with a SQL CHECK) since the only
# caller is the dashboard's own fixed set of buttons.
FEEDBACK_TYPES = {"correct", "false_positive", "false_negative"}


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
        conn.execute(FEEDBACK_SCHEMA)
        conn.commit()


def save_result(features: dict, verdict: dict) -> int:
    """Returns the new row's id, so callers that need to reference this
    exact flow later (e.g. attaching feedback to it) don't have to look it
    back up."""
    proto = features["protocol_info"]
    with _connect() as conn:
        cursor = conn.execute(
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
        return cursor.lastrowid


def get_recent_results(limit: int = 100):
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM flow_results ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]


def get_result_by_id(result_id: int):
    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute(
            "SELECT * FROM flow_results WHERE id = ?", (result_id,)
        ).fetchone()
        return dict(row) if row else None


def query_results(filters: dict, limit: int = 50):
    """Filtered read used by the NL query feature and the dashboard's flow
    search. `filters` is a dict with any of: classification, protocol,
    src_ip, dst_ip, port (matches either src_port or dst_port),
    since_minutes_ago, search (free-text substring match against flow_id,
    src_ip, dst_ip, src_port, or dst_port). All values are bound as SQL
    parameters — filters may originate from LLM output or raw user input, so
    nothing from `filters` is ever concatenated into the query string
    itself, only the column layout (which we control) determines the
    query's shape.
    """
    clauses = []
    params = []

    if filters.get("classification"):
        clauses.append("classification = ?")
        params.append(filters["classification"])
    if filters.get("protocol"):
        clauses.append("protocol = ?")
        params.append(filters["protocol"])
    if filters.get("src_ip"):
        clauses.append("src_ip = ?")
        params.append(filters["src_ip"])
    if filters.get("dst_ip"):
        clauses.append("dst_ip = ?")
        params.append(filters["dst_ip"])
    if filters.get("port"):
        clauses.append("(src_port = ? OR dst_port = ?)")
        params.extend([filters["port"], filters["port"]])
    if filters.get("since_minutes_ago"):
        cutoff = time.time() - (filters["since_minutes_ago"] * 60)
        clauses.append("timestamp >= ?")
        params.append(cutoff)
    search = (filters.get("search") or "").strip()
    if search:
        like_term = f"%{search}%"
        clauses.append(
            "(flow_id LIKE ? OR src_ip LIKE ? OR dst_ip LIKE ? "
            "OR CAST(src_port AS TEXT) LIKE ? OR CAST(dst_port AS TEXT) LIKE ?)"
        )
        params.extend([like_term] * 5)

    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(limit)

    with _connect() as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            f"SELECT * FROM flow_results {where} ORDER BY timestamp DESC LIMIT ?",
            params,
        ).fetchall()
        return [dict(r) for r in rows]


def save_feedback(result_id: int, original_classification: str, feedback_type: str, note: str = ""):
    with _connect() as conn:
        conn.execute(
            """INSERT INTO feedback
               (result_id, original_classification, feedback_type, note, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (result_id, original_classification, feedback_type, note, time.time()),
        )
        conn.commit()


def get_feedback_summary() -> dict:
    """Counts of each feedback_type recorded so far, e.g.
    {"correct": 12, "false_positive": 3, "false_negative": 1}."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT feedback_type, COUNT(*) FROM feedback GROUP BY feedback_type"
        ).fetchall()
        return {feedback_type: count for feedback_type, count in rows}
