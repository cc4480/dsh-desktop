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
CREATE TABLE IF NOT EXISTS incident_status (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('open', 'acknowledged', 'closed')),
    viewer TEXT NOT NULL,
    note TEXT NOT NULL,
    at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS study_responses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analyst TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    version TEXT NOT NULL CHECK (version IN ('A', 'B', 'C')),
    answer_what TEXT NOT NULL,
    answer_action TEXT NOT NULL,
    correct_what INTEGER NOT NULL,
    correct_action INTEGER NOT NULL,
    seconds_what REAL NOT NULL,
    seconds_action REAL NOT NULL,
    actionability INTEGER NOT NULL,
    confidence INTEGER NOT NULL,
    at REAL NOT NULL
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


CACHE_TTL = 7 * 86400.0  # a cached narrative older than this is regenerated


class Store:
    def __init__(self, path: str | Path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self._migrate()

    def close(self) -> None:
        self.db.close()

    def __enter__(self) -> "Store":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def __del__(self) -> None:  # last resort for callers that never close explicitly
        try:
            self.db.close()
        except Exception:
            pass

    def _migrate(self) -> None:
        """Additive column migrations, so an existing database keeps working."""
        cols = {r["name"] for r in self.db.execute("PRAGMA table_info(narratives)")}
        for col, decl in (("template", "TEXT"), ("latency_ms", "REAL")):
            if col not in cols:
                self.db.execute(f"ALTER TABLE narratives ADD COLUMN {col} {decl}")
        self.db.commit()

    # ---------------------------------------------------------------- writes
    def save_incident(self, inc: Incident) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?,?,?)",
            (inc.incident_id, inc.ts_start, inc.ts_end, inc.src_ip, inc.dst_ip, inc.attack_type, inc.severity,
             inc.model_dump_json()),
        )
        self.db.commit()

    def save_narrative(self, incident_id: str, body: dict, passed: bool, source: str, reasons: list[str],
                       template: dict | None = None, latency_ms: float | None = None) -> None:
        self.db.execute(
            "INSERT OR REPLACE INTO narratives (incident_id, body, validation_passed, source, reasons, created_at,"
            " template, latency_ms) VALUES (?,?,?,?,?,?,?,?)",
            (incident_id, json.dumps(body), int(passed), source, json.dumps(reasons), time.time(),
             json.dumps(template or body), latency_ms),
        )
        self.db.commit()

    def set_status(self, incident_id: str, status: str, viewer: str, note: str = "") -> None:
        if status not in ("open", "acknowledged", "closed"):
            raise ValueError(f"unknown status {status!r}")
        self.db.execute("INSERT INTO incident_status (incident_id, status, viewer, note, at) VALUES (?,?,?,?,?)",
                        (incident_id, status, viewer[:40], note[:500], time.time()))
        self.db.commit()

    def status_of(self, incident_id: str) -> str:
        row = self.db.execute("SELECT status FROM incident_status WHERE incident_id=? ORDER BY id DESC LIMIT 1",
                              (incident_id,)).fetchone()
        return row["status"] if row else "open"

    def get_incident(self, incident_id: str) -> dict | None:
        row = self.db.execute("SELECT body FROM incidents WHERE incident_id=?", (incident_id,)).fetchone()
        return json.loads(row["body"]) if row else None

    def save_study_response(self, **r) -> None:
        self.db.execute(
            "INSERT INTO study_responses (analyst, incident_id, version, answer_what, answer_action, correct_what,"
            " correct_action, seconds_what, seconds_action, actionability, confidence, at)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (r["analyst"][:40], r["incident_id"], r["version"], r["answer_what"], r["answer_action"],
             int(r["correct_what"]), int(r["correct_action"]), float(r["seconds_what"]), float(r["seconds_action"]),
             int(r["actionability"]), int(r["confidence"]), time.time()),
        )
        self.db.commit()

    def study_responses(self, analyst: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM study_responses", ()
        if analyst:
            q, args = q + " WHERE analyst=?", (analyst,)
        return [dict(r) for r in self.db.execute(q + " ORDER BY id", args).fetchall()]

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

    def cache_get(self, fp: str, max_age: float = CACHE_TTL) -> dict | None:
        row = self.db.execute("SELECT body FROM llm_cache WHERE fingerprint=? AND created_at >= ?",
                              (fp, time.time() - max_age)).fetchone()
        return json.loads(row["body"]) if row else None

    def cache_put(self, fp: str, body: dict) -> None:
        self.db.execute("INSERT OR REPLACE INTO llm_cache VALUES (?,?,?)", (fp, json.dumps(body), time.time()))
        self.db.commit()

    def save_run(self, source: str, flows: int, alerts: int, incidents: int, stats: dict) -> None:
        if stats.get("live"):  # watch mode keeps one rolling row per source, not one per pass
            self.db.execute("DELETE FROM runs WHERE source=? AND json_extract(stats, '$.live') = 1", (source,))
        self.db.execute("INSERT INTO runs (started_at, source, flows, alerts, incidents, stats) VALUES (?,?,?,?,?,?)",
                        (time.time(), source, flows, alerts, incidents, json.dumps(stats)))
        self.db.commit()

    # ---------------------------------------------------------------- reads
    def recent_source(self, src_ip: str, ts: float, horizon: float = 86400.0, closed_only: bool = False) -> bool:
        """Did this source cause an earlier incident in the last 24 h? (severity modifier)

        closed_only: in watch mode an ongoing incident is re-stored every pass and must not
        count as its own predecessor.
        """
        q = "SELECT 1 FROM incidents i WHERE src_ip=? AND ts_start < ? AND ts_start >= ?"
        if closed_only:
            q += (" AND (SELECT status FROM incident_status s WHERE s.incident_id = i.incident_id"
                  " ORDER BY s.id DESC LIMIT 1) = 'closed'")
        return self.db.execute(q + " LIMIT 1", (src_ip, ts - 1.0, ts - horizon)).fetchone() is not None

    def open_incidents(self) -> list[dict]:
        rows = self.db.execute(
            """SELECT body FROM incidents i WHERE COALESCE((SELECT status FROM incident_status s
                 WHERE s.incident_id = i.incident_id ORDER BY s.id DESC LIMIT 1), 'open') != 'closed'"""
        ).fetchall()
        return [json.loads(r["body"]) for r in rows]

    def incidents(self, limit: int = 200) -> list[dict]:
        rows = self.db.execute(
            """SELECT i.body AS incident, n.body AS narrative, n.validation_passed, n.source, n.reasons,
                      n.template, n.latency_ms,
                      (SELECT status FROM incident_status s WHERE s.incident_id = i.incident_id
                        ORDER BY s.id DESC LIMIT 1) AS status
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
                "template": json.loads(r["template"]) if r["template"] else None,
                "latency_ms": r["latency_ms"],
                "status": r["status"] or "open",
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
        """Every human (and system) touch, newest first: command views, decisions, status changes."""
        rows = self.db.execute(
            """SELECT viewed_at AS at, incident_id, viewer, 'viewed command' AS action, '' AS note
                 FROM command_views
               UNION ALL
               SELECT decided_at, incident_id, viewer, decision, note FROM approvals
               UNION ALL
               SELECT at, incident_id, viewer, 'status: ' || status, note FROM incident_status
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
