"""Sensing, response, auth, study, LLM plumbing and the supervised adapter."""
import json
import shutil
import sqlite3
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from pydantic import ValidationError

from nids import auth, pipeline, rules, study, supervised
from nids.assets import AssetRegistry
from nids.explain import prompt as P
from nids.explain.llm import SCHEMA, Explainer, ollama_chat
from nids.lab.generate import INJECTION_UA
from nids.models import Flow, Incident
from nids.response.policy import PolicyEngine
from nids.sensing import zeek
from nids.sensing.community_id import community_id
from nids.storage import Store

ROOT = Path(__file__).resolve().parents[1]
ASSETS = AssetRegistry.load(ROOT / "config" / "assets.yaml")


def _incident(**kw) -> Incident:
    base = dict(incident_id="INC-2026-10-28-abc123", ts_start=1_793_178_120.0, ts_end=1_793_178_125.0,
                src_ip="192.168.1.105", dst_ip="192.168.1.10", attack_type="Brute Force", attack_id="T1110",
                rule_ids=["BRUTE_FORCE"], confidence=0.9, severity="high", flow_count=40, alert_count=1,
                evidence={"dst_port": 22, "flow_count": 40, "handshake_ratio": 1.0, "src_ip": "192.168.1.105"})
    return Incident(**{**base, **kw})


# ------------------------------------------------------------------ sensing
def test_community_id_matches_the_spec_reference_vector():
    # From the community-id-spec README; Wireshark computes the same value.
    assert community_id("128.232.110.120", 34855, "66.35.250.204", 80, "tcp") == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="
    assert community_id("66.35.250.204", 80, "128.232.110.120", 34855, "tcp") == "1:LQU9qZlK+B5F3KDmev6m5PMibrg="


def test_http_and_tls_are_reduced_to_numbers_and_enums(lab):
    bundle = zeek.read_dir(lab / "demo")
    assert bundle.http and bundle.tls and bundle.notices and bundle.health.capture_loss_pct is not None
    dumped = json.dumps([h.model_dump() for h in bundle.http])
    assert "IGNORE" not in dumped and "Mozilla" not in dumped and "gobuster" not in dumped
    assert {h.ua_category for h in bundle.http} >= {"browser", "scanner"}
    assert {t.validation_status for t in bundle.tls} >= {"ok", "self_signed"}
    assert all(f.community_id and f.community_id.startswith("1:") for f in bundle.flows[:100])
    assert zeek.ua_category("sqlmap/1.8") == "scanner" and zeek.ua_category("curl/8") == "cli"


def test_rule_filters_are_validated(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("- {id: X, source: conn, filter: {user_agent: [x]}, group_by: [src_ip], window: 1,"
                   " correlation_window: 1, when: [{feature: flow_count, op: '>', value: 1}], confidence: 0.5,"
                   " attack_type: x, attack_id: T0, default_intent: no_action, allowed_intents: [no_action]}\n")
    with pytest.raises(ValidationError):
        rules.load_rules(bad)


# ------------------------------------------------------------------ response
def test_nftables_and_ipv6_rendering():
    nft = PolicyEngine(ASSETS, firewall="nftables")
    r = nft.render("block_source_ip", _incident(src_ip="2001:db8::66"))
    assert r.command == ('sudo nft add rule inet filter input ip6 saddr 2001:db8::66 drop '
                         'comment "nids-INC-2026-10-28-abc123"')
    assert "handle" in r.rollback and "nids-INC-2026-10-28-abc123" in r.rollback
    ipt = PolicyEngine.from_config(ROOT / "config" / "policy.yaml", ASSETS)
    assert ipt.render("block_source_ip", _incident(src_ip="2001:db8::66")).command.startswith("sudo ip6tables")
    with pytest.raises(ValueError):
        PolicyEngine(ASSETS, firewall="nftables", nft={"table": "filter; rm -rf /"})
    with pytest.raises(ValueError):
        PolicyEngine(ASSETS, firewall="pf")


# ------------------------------------------------------------------ auth
def test_users_roles_and_password_hashing(tmp_path):
    path = tmp_path / "users.yaml"
    auth.add_user(path, "alice", "correct horse battery", "approver")
    auth.add_user(path, "bob", "another long password", "analyst")
    assert "correct horse" not in path.read_text()
    assert auth.authenticate("alice", "correct horse battery", path) == "approver"
    assert auth.authenticate("alice", "wrong password!!", path) is None
    assert auth.authenticate("mallory", "anything at all", path) is None
    assert auth.can("approver", "approve") and not auth.can("analyst", "approve") and auth.can("analyst", "triage")
    with pytest.raises(ValueError):
        auth.add_user(path, "bad name!", "long enough password", "analyst")
    with pytest.raises(ValueError):
        auth.add_user(path, "carol", "short", "analyst")


# ------------------------------------------------------------------ study
def _rows(n=6):
    rows = []
    for k in range(n):
        inc = _incident(incident_id=f"INC-{k}", attack_type=["Brute Force", "Network Service Discovery"][k % 2])
        t = {"summary": "template", "technical_evidence": ["flow_count=40"]}
        rows.append({"incident": inc.model_dump(), "template": t, "narrative": {**t, "summary": "llm"},
                     "validation_passed": True, "narrative_source": "llm"})
    return rows


def test_study_is_blind_balanced_and_graded():
    rows = _rows(30)
    items = study.assign("alice", rows, {})
    assert len({it.incident_id for it in items}) == 30  # each incident once
    assert items == study.assign("alice", rows, {})  # stable for the analyst
    versions = [it.version for a in ("a", "b", "c", "d", "e", "f") for it in study.assign(a, rows, {})]
    assert {v: versions.count(v) > 30 for v in "ABC"} == {"A": True, "B": True, "C": True}
    raw = next(it for it in items if it.version == "A").body
    assert raw["kind"] == "raw" and "rule_match" in raw["fields"]  # a real alert names its signature
    resp = [dict(analyst=a, version=v, correct_what=1, correct_action=int(v != "A"), seconds_what=s,
                 seconds_action=s, actionability=3 + (v == "C"), confidence=3)
            for a in ("x", "y") for v, s in (("A", 30.0), ("B", 20.0), ("C", 15.0))]
    rep = study.report(resp)
    assert rep["deltas"]["C-A"]["median_seconds_what"] == -15.0 and rep["deltas"]["B-A"]["accuracy_action"] == 1.0
    assert "fewer than 8 analysts" in rep["warning"] and "C LLM narrative" in study.to_markdown(rep)


# ------------------------------------------------------------------ LLM plumbing
def test_ollama_gets_the_schema_and_trusted_context(monkeypatch):
    sent = {}

    class Resp:
        def raise_for_status(self):
            pass

        def json(self):
            return {"message": {"content": "{}"}}

    def fake_post(url, json=None, timeout=None, **_):
        sent.update(json)
        return Resp()

    monkeypatch.setattr("nids.explain.llm.requests.post", fake_post)
    ollama_chat("llama3.1:8b")("sys", "user")
    assert sent["format"] == SCHEMA and SCHEMA["properties"]["remediation_intent"]["enum"]
    ctx = P.context(_incident())
    assert "T1110 Brute Force (Credential Access)" in ctx and "Runbook BRUTE_FORCE" in ctx
    msg = P.user_message(P.safe_evidence(_incident()), P.classification(_incident(), ["no_action"]), ctx)
    assert msg.index("<CONTEXT>") < msg.index("<CLASSIFICATION>") < msg.index("<EVIDENCE>")
    assert INJECTION_UA[:20] not in msg


def test_llm_latency_template_and_cache_expiry(tmp_path):
    store = Store(tmp_path / "c.db")
    calls = []

    def chat(system, user):
        calls.append(1)
        return json.dumps({"summary": "Password guessing against an internal host.", "attack_type": "x",
                           "severity_level": "high", "technical_evidence": ["handshake_ratio=1.0"],
                           "remediation_intent": "block_source_ip"})

    ex = Explainer(ASSETS, backend="ollama", chat=chat, cache_get=store.cache_get, cache_put=store.cache_put)
    allowed = ["block_source_ip", "no_action"]
    first = ex.explain(_incident(), allowed, "block_source_ip")
    assert first.source == "llm" and first.latency_ms is not None and first.template.summary != first.narrative.summary
    assert ex.explain(_incident(), allowed, "block_source_ip").source == "cache" and len(calls) == 1
    store.db.execute("UPDATE llm_cache SET created_at = ?", (time.time() - 8 * 86400,))
    assert ex.explain(_incident(), allowed, "block_source_ip").source == "llm" and len(calls) == 2


def test_old_database_is_migrated(tmp_path):
    db = tmp_path / "old.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE narratives (incident_id TEXT PRIMARY KEY, body TEXT NOT NULL, validation_passed "
                "INTEGER NOT NULL, source TEXT NOT NULL, reasons TEXT NOT NULL, created_at REAL NOT NULL)")
    con.commit()
    con.close()
    store = Store(db)
    store.save_narrative("INC-1", {"summary": "x"}, False, "template", [], template={"summary": "t"}, latency_ms=12.0)
    cols = {r[1] for r in store.db.execute("PRAGMA table_info(narratives)")}
    assert {"template", "latency_ms"} <= cols


# ------------------------------------------------------------------ supervised adapter
def _cic_frame(seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for day in ("monday", "tuesday", "wednesday", "thursday", "friday"):
        for i in range(400):
            attack = day != "monday" and i % 3 == 0
            fwd = int(rng.integers(1, 3) if attack else rng.integers(4, 40))
            bwd = 0 if attack else int(rng.integers(4, 60))
            dur = float(rng.uniform(0, 2e3) if attack else rng.uniform(1e4, 5e6))
            rows.append({"Flow Duration": dur, "Total Fwd Packets": fwd, "Total Backward Packets": bwd,
                         "Flow Packets/s": (fwd + bwd) / (dur / 1e6), "Fwd Packets/s": fwd / (dur / 1e6),
                         "Bwd Packets/s": bwd / (dur / 1e6), "Down/Up Ratio": bwd / fwd,
                         "FIN Flag Count": 0.0 if attack else 1.0, "SYN Flag Count": 1.0, "RST Flag Count": 0.0,
                         "ACK Flag Count": 0.0 if attack else 1.0, "Total Length of Fwd Packets": 0.0,
                         "Label": "DDoS" if attack else "BENIGN", "__day": day})
    df = pd.DataFrame(rows)
    df["__y"] = (df["Label"] != "BENIGN").astype(int)
    return df


def test_supervised_model_trains_on_zeek_features_and_scores_live_flows(tmp_path, lab):
    sys.path.insert(0, str(ROOT / "ml"))
    import joblib
    import train_supervised as ts

    report, model, cols = ts.temporal(_cic_frame(), deployable=True, zeek=True)
    assert cols == supervised.ZEEK_CIC_FEATURES and report["test"]["pr_auc"] > 0.9
    path = tmp_path / "supervised.joblib"
    joblib.dump({"model": model, "features": cols}, path)
    m = supervised.SupervisedModel.load(path)
    flows = zeek.read_conn(lab / "demo" / "conn.log")
    flood = [f for f in flows if f.src_ip == "192.168.1.105" and f.conn_state == "S0"][:200]
    benign = [f for f in flows if f.src_ip.startswith("192.168.1.1") and f.conn_state == "SF"][:200]
    assert m.predict(flood).mean() > 0.9 and m.predict(benign).mean() < 0.5
    alerts = supervised.detect(m, flood)
    assert alerts and all(a.engine == "supervised" for a in alerts)

    joblib.dump({"model": model, "features": ["Total Length of Fwd Packets"]}, tmp_path / "bad.joblib")
    with pytest.raises(ValueError, match="cannot produce"):
        supervised.SupervisedModel.load(tmp_path / "bad.joblib")


# ------------------------------------------------------------------ forensics
@pytest.mark.skipif(not (shutil.which("tshark") or shutil.which("tcpdump")), reason="no tshark/tcpdump")
def test_pcap_extraction_keeps_only_the_incident(tmp_path):
    scapy = pytest.importorskip("scapy.all")
    from nids import forensics

    inc = _incident(ts_start=1000.0, ts_end=1060.0)
    flows = [Flow(ts=1000, uid="C1", src_ip="192.168.1.105", src_port=40000, dst_ip="192.168.1.10", dst_port=22,
                  proto="tcp", community_id=community_id("192.168.1.105", 40000, "192.168.1.10", 22, "tcp"))]
    f = forensics.build(inc, flows, {"C1"})
    pkts = []
    for t, s, d, port in ([(1010 + i, "192.168.1.105", "192.168.1.10", 22) for i in range(20)]
                          + [(400 + i, "192.168.1.105", "192.168.1.10", 22) for i in range(5)]
                          + [(1010 + i, "192.168.1.5", "192.168.1.10", 22) for i in range(5)]):
        p = scapy.Ether() / scapy.IP(src=s, dst=d) / scapy.TCP(sport=40000, dport=port, flags="S")
        p.time = t
        pkts.append(p)
    scapy.wrpcap(str(tmp_path / "cap.pcap"), pkts)
    ok, msg = forensics.extract(f, tmp_path / "cap.pcap", tmp_path / "out.pcap")
    assert ok, msg
    kept = scapy.rdpcap(str(tmp_path / "out.pcap"))
    assert len(kept) == (20 if shutil.which("tshark") else 25)  # tcpdump has no time filter


# ------------------------------------------------------------------ JA4
# Real values from the FoxIO package's own test baselines (zeek/testing/Baseline/tests.ja4-tls*).
REAL_JA4 = ["t13d1517h2_8daaf6152771_cb7bf5808d99", "q13d0310h3_55b375c5d22e_cd85d2d88918"]


def test_reader_keeps_real_ja4_values(tmp_path):
    log = tmp_path / "ssl.log"
    log.write_text("\n".join(json.dumps({
        "ts": 1.0 + i, "uid": f"C{i}", "id.orig_h": "10.0.0.1", "id.resp_h": "10.0.0.2", "id.resp_p": 443,
        "version": "TLSv13", "established": True, "ja4": j, "ja4s": "t130200_1301_234ea6891581"})
        for i, j in enumerate(REAL_JA4)) + "\n")
    assert [t.ja4 for t in zeek.read_ssl(log)] == REAL_JA4


def test_fingerprint_novelty_uses_ja4_and_says_when_it_cannot_tell():
    from nids.profile import Profile

    p = Profile(ja4_seen={REAL_JA4[0]})
    assert p.is_new_fingerprint(REAL_JA4[0]) is False
    assert p.is_new_fingerprint("t12d190900_d83cc789557e_7af1ed941c26") is True
    assert p.is_new_fingerprint("") is None  # sensor without the JA4 package
    # Baseline captured without JA4 but live traffic has it: cannot say, rather than "all new".
    assert Profile().is_new_fingerprint(REAL_JA4[0]) is None


def test_unseen_tls_client_fires_for_the_implant_only(lab, config):
    incidents = pipeline.run(lab / "demo", config())
    fired = {i.src_ip for i in incidents if i.rule_ids == ["NEW_TLS_FINGERPRINT"]}
    assert fired == {"192.168.1.60"}


def test_sensor_image_installs_ja4_and_not_the_archived_ja3():
    dockerfile = (ROOT / "lab" / "sensor" / "Dockerfile").read_text()
    installs = [line for line in dockerfile.splitlines() if "zkg install" in line]
    assert len(installs) == 1 and "zeek/foxio/ja4" in installs[0]
    assert "@load packages" in dockerfile and "community-id-logging" in dockerfile
