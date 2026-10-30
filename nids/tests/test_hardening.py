"""Production-hardening behaviour: model integrity, LLM resilience, store concurrency, watch survival."""
import sqlite3
import threading

import joblib
import pytest
import requests

from nids import integrity, pipeline
from nids.assets import AssetRegistry
from nids.explain import llm
from nids.models import Incident
from nids.storage import Store
from nids.watch import Watcher, watch


# --------------------------------------------------------------------------- model integrity
def test_unsigned_or_modified_model_is_refused(tmp_path, monkeypatch):
    monkeypatch.delenv("NIDS_MODEL_KEY", raising=False)
    p = tmp_path / "m.joblib"
    joblib.dump({"x": 1}, p)
    with pytest.raises(ValueError, match="unsigned"):
        integrity.verify(p)
    integrity.sign(p)
    integrity.verify(p)
    p.write_bytes(p.read_bytes() + b"tamper")
    with pytest.raises(ValueError, match="changed after training"):
        integrity.verify(p)


def test_hmac_key_must_match(tmp_path, monkeypatch):
    p = tmp_path / "m.joblib"
    joblib.dump({"x": 1}, p)
    monkeypatch.setenv("NIDS_MODEL_KEY", "k1")
    integrity.sign(p)
    integrity.verify(p)
    monkeypatch.setenv("NIDS_MODEL_KEY", "k2")
    with pytest.raises(ValueError):
        integrity.verify(p)
    monkeypatch.delenv("NIDS_MODEL_KEY")  # a plain digest cannot stand in for a keyed one
    with pytest.raises(ValueError):
        integrity.verify(p)


def test_pipeline_reports_unsigned_model_instead_of_loading_it(tmp_path):
    p = tmp_path / "anomaly.joblib"
    joblib.dump({"not": "a model"}, p)
    models = pipeline.Models.load(pipeline.Config(model_path=p, profile_path=None, supervised_path=None))
    assert models.anomaly is None and "unsigned" in models.status()["anomaly"]


# --------------------------------------------------------------------------- DeepSeek resilience
class _Resp:
    def __init__(self, status, body=None, headers=None):
        self.status_code, self._body, self.headers = status, body or {}, headers or {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code}", response=self)

    def json(self):
        return self._body


OK = _Resp(200, {"choices": [{"message": {"content": "{}"}}]})


def _post_seq(monkeypatch, responses):
    calls = []

    def post(url, **kw):
        calls.append(url)
        r = responses[min(len(calls) - 1, len(responses) - 1)]
        if isinstance(r, Exception):
            raise r
        return r

    monkeypatch.setattr(llm.requests, "post", post)
    return calls


def test_transient_errors_are_retried_with_backoff(monkeypatch):
    waits = []
    calls = _post_seq(monkeypatch, [_Resp(429, headers={"Retry-After": "7"}), requests.Timeout(), _Resp(503), OK])
    r = llm._post_with_backoff("u", {}, {}, 1, attempts=4, sleep=waits.append)
    assert r is OK and len(calls) == 4
    assert waits == [7.0, 2.0, 4.0]


def test_client_errors_are_not_retried(monkeypatch):
    calls = _post_seq(monkeypatch, [_Resp(401)])
    with pytest.raises(requests.HTTPError):
        llm._post_with_backoff("u", {}, {}, 1, sleep=lambda s: None)
    assert len(calls) == 1


def test_gives_up_after_the_last_attempt(monkeypatch):
    _post_seq(monkeypatch, [_Resp(500)])
    with pytest.raises(requests.HTTPError):
        llm._post_with_backoff("u", {}, {}, 1, attempts=3, sleep=lambda s: None)


def _incident():
    return Incident(incident_id="INC-1", ts_start=1.0, ts_end=2.0, src_ip="203.0.113.9", dst_ip="192.168.1.20",
                    attack_type="Brute Force", attack_id="T1110", rule_ids=["BRUTE_FORCE"], confidence=0.9,
                    severity="high", flow_count=30, alert_count=1, asset_criticality=3, direction="inbound",
                    evidence={"src_ip": "203.0.113.9", "flow_count": 30, "rule_match": "BRUTE_FORCE"})


def test_circuit_breaker_stops_calling_a_failing_service(monkeypatch):
    calls = []

    def chat(system, user):
        calls.append(1)
        raise requests.ConnectionError("down")

    ex = llm.Explainer(AssetRegistry.load(pipeline.Config().assets_path), "deepseek", "m", chat=chat)
    for _ in range(llm.BREAKER_FAILURES + 4):
        res = ex.explain(_incident(), ["block_source_ip", "no_action"], "block_source_ip")
        assert res.source == "template"
    assert len(calls) == llm.BREAKER_FAILURES  # then paused: later incidents never touch the network
    assert "paused" in res.reasons[0]


# --------------------------------------------------------------------------- store concurrency
def test_store_uses_wal_and_busy_timeout(tmp_path):
    s = Store(tmp_path / "n.db")
    assert s.db.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    assert s.db.execute("PRAGMA busy_timeout").fetchone()[0] >= 5000


def test_reader_is_not_blocked_by_an_open_write(tmp_path):
    writer, reader = Store(tmp_path / "n.db"), Store(tmp_path / "n.db")
    writer.db.execute("BEGIN IMMEDIATE")
    writer.db.execute("INSERT INTO egress_log (incident_id, backend, payload, sent_at) VALUES ('a','b','c',1)")
    assert reader.egress() == []  # reads the last committed state, no "database is locked"
    writer.db.commit()
    assert len(reader.egress()) == 1
    with pytest.raises(sqlite3.OperationalError):
        sqlite3.connect(str(tmp_path / "n.db")).execute("SELECT * FROM nonexistent")


# --------------------------------------------------------------------------- watch survival
def test_watch_survives_a_failing_pass_and_stops_cleanly(tmp_path, monkeypatch):
    (tmp_path / "logs").mkdir()
    cfg = pipeline.Config(db_path=tmp_path / "n.db", model_path=None, profile_path=None, supervised_path=None)
    stop, seen = threading.Event(), []

    def step(self):
        seen.append(len(seen))
        if len(seen) == 1:
            raise RuntimeError("transient")
        if len(seen) >= 3:
            stop.set()
        return {"new_flows": 0, "new": 0, "updated": 0, "closed": 0, "reopened": 0}

    monkeypatch.setattr(Watcher, "step", step)
    watch(tmp_path / "logs", cfg, interval=0.01, stop=stop)
    assert len(seen) == 3  # the first pass failed, the loop carried on, and stop ended it


# --------------------------------------------------------------------------- login throttle
def test_login_throttle_locks_then_expires():
    from nids.auth import LoginThrottle

    now = [0.0]
    t = LoginThrottle(clock=lambda: now[0])
    for _ in range(LoginThrottle.MAX_FAILURES):
        assert not t.locked("Alice")
        t.fail("alice")  # case-insensitive
    assert t.locked("ALICE") and not t.locked("bob")
    now[0] += LoginThrottle.WINDOW + 1
    assert not t.locked("alice")
    t.fail("alice")
    t.ok("alice")
    assert not t.locked("alice") and not t.failures["alice"]
