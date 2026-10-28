"""Plane 7 storage. SQLite for the demo floor; the schema is plain SQL so moving to
Postgres/TimescaleDB is a connection-string change plus `create_hypertable`.

Every incident persists with the narrative and commands *as they were rendered*, and
every command render and view is written to an audit table.
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

from nids.models import Incident

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    ts_start REAL NOT NULL,
    ts_end REAL NOT NULL,
    src_ip TEXT NOT NULL,
    dst_ip TEXT,
    attack_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    body TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS incidents_ts ON incidents(ts_start);
CREATE INDEX IF NOT EXISTS incidents_src ON incidents(src_ip, ts_start);
CREATE TABLE IF NOT EXISTS narratives (
    incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id),
    body TEXT NOT NULL,
    validation_passed INTEGER NOT NULL,
    source TEXT NOT NULL,
    reasons TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS rendered_commands (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    intent TEXT NOT NULL,
    command TEXT,
    rollback TEXT,
    dry_run TEXT,
    refused_reason TEXT,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS command_views (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    viewer TEXT NOT NULL,
    viewed_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id),
    command_id INTEGER REFERENCES rendered_commands(id),
    decision TEXT NOT NULL CHECK (decision IN ('approved', 'rejected')),
    viewer TEXT NOT NULL,
    note TEXT NOT NULL,
    decided_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS llm_cache (
    fingerprint TEXT PRIMARY KEY,
    body TEXT NOT NULL,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS egress_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    backend TEXT NOT NULL,
    payload TEXT NOT NULL,
    sent_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at REAL NOT NULL,
    source TEXT NOT NULL,
    flows INTEGER NOT NULL,
    alerts INTEGER NOT NULL,
    incidents INTEGER NOT NULL,
    stats TEXT NOT NULL
);
"""


class Store:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)

    # ---------------------------------------------------------------- writes
    def save_incident(self, inc: Incident) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?)",
            (inc.incident_id, inc.ts_start, inc.ts_end, inc.src_ip, inc.dst_ip, inc.attack_type, inc.severity,
             inc.model_dump_json()),
        )
        self.db.commit()

    def save_narrative(self, incident_id: str, body: dict, passed: bool, source: str, reasons: list[str]) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO narratives VALUES (?,?,?,?,?,?)",
            (incident_id, json.dumps(body), int(passed), source, json.dumps(reasons), time.time()),
        )
        self.db.commit()

    def save_command(self, incident_id: str, intent: str, command: str | None, rollback: str | None,
                     dry_run: str | None, refused: str | None) -> None:
        self.db.execute(
            "INSERT INTO rendered_commands (incident_id, intent, command, rollback, dry_run, refused_reason, created_at)"
            " VALUES (?,?,?,?,?,?,?)",
            (incident_id, intent, command, rollback, dry_run, refused, time.time()),
        )
        self.db.commit()

    def log_view(self, incident_id: str, viewer: str) -> None:
        self.db.execute("INSERT INTO command_views (incident_id, viewer, viewed_at) VALUES (?,?,?)",
                        (incident_id, viewer, time.time()))
        self.db.commit()

    def record_decision(self, incident_id: str, command_id: int | None, decision: str, viewer: str,
                        note: str = "") -> None:
        """A human decision on a rendered command. Recording 'approved' executes nothing."""
        if decision not in ("approved", "rejected"):
            raise ValueError(f"unknown decision {decision!r}")
        self.db.execute(
            "INSERT INTO approvals (incident_id, command_id, decision, viewer, note, decided_at) VALUES (?,?,?,?,?,?)",
            (incident_id, command_id, decision, viewer[:40], note[:500], time.time()),
        )
        self.db.commit()

    def log_egress(self, incident_id: str, backend: str, payload: str) -> None:
        self.db.execute("INSERT INTO egress_log (incident_id, backend, payload, sent_at) VALUES (?,?,?,?)",
                        (incident_id, backend, payload, time.time()))
        self.db.commit()

    def cache_get(self, fp: str) -> dict | None:
        row = self.db.execute("SELECT body FROM llm_cache WHERE fingerprint=?", (fp,)).fetchone()
        return json.loads(row["body"]) if row else None

    def cache_put(self, fp: str, body: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO llm_cache VALUES (?,?,?)", (fp, json.dumps(body), time.time()))
        self.db.commit()

    def save_run(self, source: str, flows: int, alerts: int, incidents: int, stats: dict) -> None:
        self.db.execute("INSERT INTO runs (started_at, source, flows, alerts, incidents, stats) VALUES (?,?,?,?,?,?)",
                        (time.time(), source, flows, alerts, incidents, json.dumps(stats)))
        self.db.commit()

    # ---------------------------------------------------------------- reads
    def recent_source(self, src_ip: str, ts: float, horizon: float = 86400.0) -> bool:
        row = self.db.execute(
            "SELECT 1 FROM incidents WHERE src_ip=? AND ts_start < ? AND ts_start >= ? LIMIT 1",
            (src_ip, ts - 1.0, ts - horizon),
        ).fetchone()
        return row is not None

    def incidents(self, limit: int = 200) -> list[dict]:
        rows = self.db.execute(
            """SELECT i.body AS incident, n.body AS narrative, n.validation_passed, n.source, n.reasons
               FROM incidents i LEFT JOIN narratives n USING (incident_id)
               ORDER BY i.ts_start DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [
            {
                "incident": json.loads(r["incident"]),
                "narrative": json.loads(r["narrative"]) if r["narrative"] else None,
                "validation_passed": bool(r["validation_passed"]),
                "narrative_source": r["source"],
                "validation_reasons": json.loads(r["reasons"]) if r["reasons"] else [],
            }
            for r in rows
        ]

    def latest_command(self, incident_id: str) -> dict | None:
        row = self.db.execute(
            "SELECT * FROM rendered_commands WHERE incident_id=? ORDER BY id DESC LIMIT 1", (incident_id,)
        ).fetchone()
        return dict(row) if row else None

    def decisions(self, incident_id: str) -> list[dict]:
        rows = self.db.execute(
            "SELECT * FROM approvals WHERE incident_id=? ORDER BY id DESC", (incident_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    def audit(self, limit: int = 500) -> list[dict]:
        """Every human touch on a command, newest first: views and decisions."""
        rows = self.db.execute(
            """SELECT viewed_at AS at, incident_id, viewer, 'viewed command' AS action, '' AS note
                 FROM command_views
               UNION ALL
               SELECT decided_at, incident_id, viewer, decision, note FROM approvals
               ORDER BY at DESC LIMIT ?""",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]

    def runs(self, limit: int = 50) -> list[dict]:
        rows = self.db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "stats": json.loads(r["stats"])} for r in rows]

    def last_run(self) -> dict | None:
        row = self.db.execute("SELECT * FROM runs ORDER BY id DESC LIMIT 1").fetchone()
        return {**dict(row), "stats": json.loads(row["stats"])} if row else None
