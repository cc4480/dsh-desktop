"""Live mode: follow Zeek's current logs, detect continuously, keep incidents up to date.

    python -m nids watch /opt/zeek/logs/current --interval 10

Each pass:
  1. read whatever Zeek appended to each log since the last pass (rotation-safe: a new
     inode or a shrunken file is read from the start)
  2. score only the new flows with the per-flow engines (anomaly, supervised)
  3. run the rules and the correlator over a retention buffer (default 1 h of log time)
  4. reconcile with stored incidents: an episode that is still going keeps its incident
     id and is updated in place (counts, timeline, severity); a new one is explained and
     rendered; the narrative is regenerated only when severity changes
  5. close incidents whose correlation window has passed with no new activity

"Now" is the newest timestamp in the logs, not the wall clock, so replaying a capture
behaves exactly like live traffic.
"""
from __future__ import annotations

import logging
import os
import signal
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from nids import anomaly, rules, supervised
from nids.assets import AssetRegistry
from nids.models import SEVERITY_ORDER, Alert, Incident
from nids.pipeline import Config, Models, Responder, attach_context, detect, run_stats
from nids.sensing import zeek
from nids.sensing.zeek import LineParser, LogBundle
from nids.storage import Store

log = logging.getLogger("nids.watch")
LOGS = ("conn", "dns", "http", "ssl", "notice", "weird")
DEFAULT_CORRELATION_WINDOW = 300.0


@dataclass
class Tail:
    """Follows one log file across appends and rotations."""

    path: Path
    inode: int | None = None
    offset: int = 0
    parser: LineParser = field(default_factory=LineParser)
    partial: str = ""

    def read(self) -> list[dict]:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            return []
        if self.inode != st.st_ino or st.st_size < self.offset:  # rotated or truncated
            self.inode, self.offset, self.parser, self.partial = st.st_ino, 0, LineParser(), ""
        if st.st_size == self.offset:
            return []
        with self.path.open(encoding="utf-8", errors="replace") as fh:
            fh.seek(self.offset)
            chunk = fh.read()
            self.offset = fh.tell()
        text = self.partial + chunk
        lines = text.split("\n")
        self.partial = lines.pop()  # an unterminated last line waits for the next pass
        return [r for r in (self.parser.parse(line) for line in lines) if r is not None]


class Watcher:
    def __init__(self, logdir: Path, cfg: Config, retention: float = 3600.0,
                 log: Callable[[str], None] = log.info):
        self.logdir = Path(logdir)
        self.cfg = cfg
        self.retention = retention
        self.log = log
        self.rule_set = rules.load_rules(cfg.rules_path)
        self.windows = {r.attack_type: r.correlation_window for r in self.rule_set}
        self.assets = AssetRegistry.load(cfg.assets_path)
        self.store = Store(cfg.db_path)
        self.models = Models.load(cfg)
        self.responder = Responder(cfg, self.store, self.assets, self.rule_set)
        self.tails = {name: Tail(self.logdir / f"{name}.log") for name in LOGS}
        self.buffer = LogBundle(flows=[])
        self.point_alerts: list[Alert] = []
        self.now = 0.0
        self.passes = 0

    # ------------------------------------------------------------------ ingest
    def ingest(self) -> int:
        new = {name: t.read() for name, t in self.tails.items()}
        flows = zeek.read_conn(new["conn"])
        self.buffer.flows += flows
        self.buffer.dns += zeek.read_dns(new["dns"])
        self.buffer.http += zeek.read_http(new["http"])
        self.buffer.tls += zeek.read_ssl(new["ssl"])
        self.buffer.notices += zeek.parse_notices(new["notice"], "notice") + zeek.parse_notices(new["weird"], "weird")
        if self.models.anomaly is not None:
            self.point_alerts += anomaly.detect(self.models.anomaly, flows)
        if self.models.supervised is not None:
            self.point_alerts += supervised.detect(self.models.supervised, flows)
        stamps = [r.ts for lst in (flows, self.buffer.dns[-1:], self.buffer.http[-1:]) for r in lst]
        if stamps:
            self.now = max(self.now, max(stamps))
        self._prune()
        return len(flows)

    def _prune(self) -> None:
        cutoff = self.now - self.retention
        b = self.buffer
        b.flows = sorted((f for f in b.flows if f.ts >= cutoff), key=lambda f: f.ts)
        b.dns = [r for r in b.dns if r.ts >= cutoff]
        b.http = [r for r in b.http if r.ts >= cutoff]
        b.tls = [r for r in b.tls if r.ts >= cutoff]
        b.notices = [r for r in b.notices if r.ts >= cutoff]
        self.point_alerts = [a for a in self.point_alerts if a.ts_start >= cutoff]

    # ------------------------------------------------------------------ reconcile
    def _match(self, inc: Incident, stored: list[Incident]) -> Incident | None:
        window = self.windows.get(inc.attack_type, DEFAULT_CORRELATION_WINDOW)
        for s in stored:
            if (s.src_ip, s.dst_ip, s.attack_type) == (inc.src_ip, inc.dst_ip, inc.attack_type) \
                    and inc.ts_start <= s.ts_end + window and inc.ts_end >= s.ts_start:
                return s
        return None

    def step(self) -> dict:
        n_new = self.ingest()
        self.passes += 1
        if not self.buffer.flows and not self.buffer.notices:
            return {"new_flows": 0, "new": 0, "updated": 0, "closed": 0, "reopened": 0}
        det = detect(self.buffer, self.rule_set, self.assets, self.models, point_alerts=self.point_alerts,
                     recent_sources=lambda src, ts: self.store.recent_source(src, ts, closed_only=True))
        attach_context(det, self.buffer.flows)
        horizon = self.now - self.retention - max(self.windows.values(), default=DEFAULT_CORRELATION_WINDOW)
        rows = [r for r in self.store.incidents(limit=5000) if r["incident"]["ts_end"] >= horizon]
        stored = [Incident.model_validate(r["incident"]) for r in rows]
        status = {r["incident"]["incident_id"]: r["status"] for r in rows}
        new = updated = reopened = 0
        for inc in det.incidents:
            prev = self._match(inc, stored)
            if prev is None:
                # Never stored before: raise it, even if it already ended (the first pass after
                # a start or restart covers history; re-detections match stored incidents).
                self.responder.respond(inc)
                new += 1
                self.log(f"NEW      {inc.severity:<13} {inc.incident_id} {inc.attack_type} {inc.src_ip} -> {inc.dst_ip or '*'}")
                stored.append(inc)
                continue
            grew = inc.ts_end > prev.ts_end + 1e-6 or inc.flow_count > prev.flow_count
            escalated = SEVERITY_ORDER.index(inc.severity) > SEVERITY_ORDER.index(prev.severity)
            if not grew and not escalated:
                continue  # the same history re-detected from the buffer: nothing new
            # Same episode: keep its id and earliest start; history beyond the retention
            # buffer is gone, so counts and severity never go down.
            inc.incident_id = prev.incident_id
            inc.ts_start = min(prev.ts_start, inc.ts_start)
            inc.detected_at = min(prev.detected_at, inc.detected_at) if prev.detected_at else inc.detected_at
            inc.flow_count = max(prev.flow_count, inc.flow_count)
            if not escalated:
                inc.severity, inc.severity_reasons = prev.severity, prev.severity_reasons
            self.responder.respond(inc, explain=escalated)
            updated += 1
            if escalated:
                self.log(f"SEVERITY {prev.severity} -> {inc.severity}  {inc.incident_id}")
            if status.get(prev.incident_id) == "closed" and inc.ts_end > prev.ts_end + 1e-6:
                self.store.set_status(prev.incident_id, "open", "system", "activity resumed")
                reopened += 1
                self.log(f"REOPENED {prev.incident_id}")
            for i, s in enumerate(stored):  # later passes compare against the updated record
                if s.incident_id == inc.incident_id:
                    stored[i] = inc
        closed = 0
        for s in stored:
            window = self.windows.get(s.attack_type, DEFAULT_CORRELATION_WINDOW)
            if status.get(s.incident_id, "open") != "closed" and self.now - s.ts_end > window:
                self.store.set_status(s.incident_id, "closed", "system", f"no activity for {window:.0f}s")
                status[s.incident_id] = "closed"
                closed += 1
                self.log(f"CLOSED   {s.incident_id}")
        stats = run_stats(self.buffer, det, self.models, self.cfg, self.responder, det.timing_ms)
        stats.update({"live": 1, "passes": self.passes, "log_time": self.now, "retention_s": self.retention})
        self.store.save_run(str(self.logdir / "conn.log"), len(self.buffer.flows), len(det.alerts),
                            len(det.incidents), stats)
        return {"new_flows": n_new, "new": new, "updated": updated, "closed": closed, "reopened": reopened}


MAX_CONSECUTIVE_FAILURES = 20


def watch(logdir: Path, cfg: Config, interval: float = 10.0, retention: float = 3600.0, once: bool = False,
          stop: threading.Event | None = None) -> None:
    """Run passes until stopped. A failing pass is logged and retried; a persistent failure exits non-zero.

    SIGTERM and SIGINT finish the current pass and then close the store, so a service manager or the
    dashboard can stop it without leaving a half-written pass.
    """
    stop = stop or threading.Event()
    if threading.current_thread() is threading.main_thread():
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, lambda *_: stop.set())
    w = Watcher(logdir, cfg, retention)
    log.info("watching %s every %.0fs (retention %.0fs, pid %d); engines %s", logdir, interval, retention,
             os.getpid(), w.models.status())
    failures = 0
    try:
        while not stop.is_set():
            t0 = time.perf_counter()
            try:
                r = w.step()
                failures = 0
            except Exception:  # one bad pass must not end live detection
                failures += 1
                log.exception("pass %d failed (%d in a row)", w.passes, failures)
                if failures >= MAX_CONSECUTIVE_FAILURES:
                    raise SystemExit(f"giving up after {failures} consecutive failed passes") from None
                r = None
            if r and (r["new_flows"] or r["new"] or r["closed"]):
                log.info("pass %d: +%d flows, %d new, %d updated, %d closed (%.0f ms)", w.passes, r["new_flows"],
                         r["new"], r["updated"], r["closed"], (time.perf_counter() - t0) * 1000)
            if once:
                return
            # Back off while failing, but stay responsive to a stop request.
            stop.wait(max(0.0, interval * min(failures + 1, 6) - (time.perf_counter() - t0)))
    finally:
        w.store.close()
        log.info("stopped after %d passes", w.passes)
