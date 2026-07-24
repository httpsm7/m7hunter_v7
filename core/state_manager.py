#!/usr/bin/env python3
# core/state_manager.py — SQLite-Backed State + Resume Manager
# Blueprint: SQLite checkpointing, strict resume support, partial output tracking
# MilkyWay Intelligence | Author: Sharlix | AUTHORIZED USE ONLY

import sqlite3, json, time, os, threading
from datetime import datetime
from core.error_handler import get_handler

DB_PATH = os.path.expanduser("~/.m7hunter/state.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id    TEXT PRIMARY KEY,
    target     TEXT NOT NULL,
    started_at REAL,
    updated_at REAL,
    status     TEXT DEFAULT 'running',
    args_json  TEXT
);
CREATE TABLE IF NOT EXISTS stages (
    scan_id    TEXT,
    stage_name TEXT,
    status     TEXT DEFAULT 'pending',
    started_at REAL,
    finished_at REAL,
    findings_n INTEGER DEFAULT 0,
    output_file TEXT,
    error_msg  TEXT,
    PRIMARY KEY (scan_id, stage_name)
);
CREATE TABLE IF NOT EXISTS findings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id    TEXT,
    vuln_type  TEXT,
    url        TEXT,
    severity   TEXT,
    confidence REAL,
    detail     TEXT,
    payload    TEXT,
    tool       TEXT,
    timestamp  REAL,
    verified   INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS checkpoints (
    scan_id    TEXT,
    key        TEXT,
    value_json TEXT,
    updated_at REAL,
    PRIMARY KEY (scan_id, key)
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_stages_scan   ON stages(scan_id);
"""

class StateManager:
    """
    Blueprint: SQLite state manager.
    - Persists completed stages, partial outputs, resume markers
    - Thread-safe via connection-per-thread pattern
    - All findings flushed here at stage end
    """

    def __init__(self, db_path: str = DB_PATH):
        self._path = db_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        try:
            with self._conn() as c:
                c.executescript(SCHEMA)
        except Exception as e:
            get_handler().capture("state_manager", e, "_init_db")

    # ── Scan lifecycle ────────────────────────────────────────────────
    def create_scan(self, scan_id: str, target: str, args: dict = None) -> str:
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT OR REPLACE INTO scans(scan_id,target,started_at,updated_at,args_json) VALUES(?,?,?,?,?)",
                    (scan_id, target, time.time(), time.time(), json.dumps(args or {}))
                )
        except Exception as e:
            get_handler().capture("state_manager", e, "create_scan")
        return scan_id

    def finish_scan(self, scan_id: str, status: str = "completed"):
        self._exec("UPDATE scans SET status=?,updated_at=? WHERE scan_id=?",
                   (status, time.time(), scan_id))

    # ── Stage lifecycle ───────────────────────────────────────────────
    def stage_start(self, scan_id: str, stage: str):
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT OR REPLACE INTO stages(scan_id,stage_name,status,started_at) VALUES(?,?,?,?)",
                    (scan_id, stage, "running", time.time())
                )
        except Exception as e:
            get_handler().capture("state_manager", e, f"stage_start:{stage}")

    def stage_done(self, scan_id: str, stage: str, findings_n: int = 0,
                   output_file: str = "", error: str = ""):
        status = "failed" if error else "done"
        self._exec(
            "UPDATE stages SET status=?,finished_at=?,findings_n=?,output_file=?,error_msg=? "
            "WHERE scan_id=? AND stage_name=?",
            (status, time.time(), findings_n, output_file, error, scan_id, stage)
        )

    def is_stage_done(self, scan_id: str, stage: str) -> bool:
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT status FROM stages WHERE scan_id=? AND stage_name=?",
                    (scan_id, stage)
                ).fetchone()
                return row is not None and row["status"] == "done"
        except Exception as e:
            get_handler().capture("state_manager", e, f"is_stage_done:{stage}")
            return False

    def get_pending_stages(self, scan_id: str, all_stages: list) -> list:
        """Return stages not yet completed — for resume."""
        done = set()
        try:
            with self._conn() as c:
                rows = c.execute(
                    "SELECT stage_name FROM stages WHERE scan_id=? AND status='done'",
                    (scan_id,)
                ).fetchall()
                done = {r["stage_name"] for r in rows}
        except Exception as e:
            get_handler().capture("state_manager", e, "get_pending_stages")
        return [s for s in all_stages if s not in done]

    # ── Findings persistence ──────────────────────────────────────────
    def persist_finding(self, scan_id: str, finding: dict):
        try:
            with self._conn() as c:
                c.execute(
                    "INSERT INTO findings(scan_id,vuln_type,url,severity,confidence,"
                    "detail,payload,tool,timestamp,verified) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (scan_id,
                     finding.get("vuln_type", ""),
                     finding.get("url", ""),
                     finding.get("severity", "info"),
                     finding.get("confidence", 0.0),
                     finding.get("detail", ""),
                     finding.get("payload", ""),
                     finding.get("tool", ""),
                     time.time(),
                     1 if finding.get("verified") else 0)
                )
        except Exception as e:
            get_handler().capture("state_manager", e, "persist_finding")

    def persist_findings_bulk(self, scan_id: str, findings: list):
        try:
            rows = [
                (scan_id, f.get("vuln_type",""), f.get("url",""),
                 f.get("severity","info"), f.get("confidence",0.0),
                 f.get("detail",""), f.get("payload",""), f.get("tool",""),
                 time.time(), 1 if f.get("verified") else 0)
                for f in findings
            ]
            with self._conn() as c:
                c.executemany(
                    "INSERT INTO findings(scan_id,vuln_type,url,severity,confidence,"
                    "detail,payload,tool,timestamp,verified) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    rows
                )
        except Exception as e:
            get_handler().capture("state_manager", e, "persist_findings_bulk")

    def get_findings(self, scan_id: str, severity: str = None) -> list:
        try:
            with self._conn() as c:
                if severity:
                    rows = c.execute(
                        "SELECT * FROM findings WHERE scan_id=? AND severity=? ORDER BY confidence DESC",
                        (scan_id, severity)
                    ).fetchall()
                else:
                    rows = c.execute(
                        "SELECT * FROM findings WHERE scan_id=? ORDER BY confidence DESC",
                        (scan_id,)
                    ).fetchall()
                return [dict(r) for r in rows]
        except Exception as e:
            get_handler().capture("state_manager", e, "get_findings")
            return []

    # ── Checkpoint key/value ──────────────────────────────────────────
    def save_checkpoint(self, scan_id: str, key: str, value):
        self._exec(
            "INSERT OR REPLACE INTO checkpoints(scan_id,key,value_json,updated_at) VALUES(?,?,?,?)",
            (scan_id, key, json.dumps(value), time.time())
        )

    def load_checkpoint(self, scan_id: str, key: str, default=None):
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT value_json FROM checkpoints WHERE scan_id=? AND key=?",
                    (scan_id, key)
                ).fetchone()
                return json.loads(row["value_json"]) if row else default
        except Exception as e:
            get_handler().capture("state_manager", e, f"load_checkpoint:{key}")
            return default

    # ── Resume support ────────────────────────────────────────────────
    def find_resumable_scan(self, target: str) -> dict | None:
        """Find the most recent incomplete scan for a target."""
        try:
            with self._conn() as c:
                row = c.execute(
                    "SELECT * FROM scans WHERE target=? AND status='running' ORDER BY updated_at DESC LIMIT 1",
                    (target,)
                ).fetchone()
                return dict(row) if row else None
        except Exception as e:
            get_handler().capture("state_manager", e, "find_resumable_scan")
            return None

    def scan_summary(self, scan_id: str) -> dict:
        try:
            with self._conn() as c:
                scan = c.execute("SELECT * FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
                stages = c.execute("SELECT * FROM stages WHERE scan_id=?", (scan_id,)).fetchall()
                total = c.execute("SELECT COUNT(*) as n FROM findings WHERE scan_id=?", (scan_id,)).fetchone()
                return {
                    "scan": dict(scan) if scan else {},
                    "stages": [dict(s) for s in stages],
                    "total_findings": total["n"] if total else 0
                }
        except Exception as e:
            get_handler().capture("state_manager", e, "scan_summary")
            return {}

    # ── Utility ───────────────────────────────────────────────────────
    def _exec(self, sql: str, params: tuple = ()):
        try:
            with self._conn() as c:
                c.execute(sql, params)
        except Exception as e:
            get_handler().capture("state_manager", e, f"_exec:{sql[:40]}")
