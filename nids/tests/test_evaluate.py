"""Evaluation harness and the hopping-window fix it depends on."""
import json

import numpy as np

from nids import evaluate, pipeline, rules
from nids.anomaly import _edges, _proportions
from nids.models import Flow


def _report(lab, config):
    return evaluate.evaluate(lab / "demo", None, config())


def test_ensemble_detects_everything_with_no_false_incidents(lab, config):
    r = _report(lab, config)
    inc = r["incident_level"]
    assert inc["ensemble"]["episodes_detected"] == inc["ensemble"]["episodes"] == 8
    assert inc["ensemble"]["false_incidents"] == 0
    assert inc["ensemble"]["severity_as_expected"] == 8
    assert inc["ensemble"]["classified_correctly"] == inc["ensemble"]["classifiable"] == 8
    assert inc["supervised"]["status"].startswith("skipped")

    anom_eps = {e["attack"]: e["detected"] for e in inc["anomaly"]["per_episode"]}
    assert not anom_eps["DNS_TUNNELING"]  # each query is individually ordinary
    assert not anom_eps["SSH_BRUTE_FORCE"]  # each login session is individually ordinary
    assert inc["anomaly"]["classified_correctly"] == 0  # anomaly alone never names an attack


def test_without_a_profile_the_rules_miss_the_upload_and_the_anomaly_engine_does_not(lab, config):
    cfg = config()
    cfg.profile_path = None
    r = evaluate.evaluate(lab / "demo", None, cfg)
    rules_eps = {e["attack"]: e["detected"] for e in r["incident_level"]["rules"]["per_episode"]}
    anom_eps = {e["attack"]: e["detected"] for e in r["incident_level"]["anomaly"]["per_episode"]}
    assert not rules_eps["NOVEL_BULK_UPLOAD"] and anom_eps["NOVEL_BULK_UPLOAD"]
    assert "NEW_DESTINATION_BULK_UPLOAD" in r["inactive_rules"]


def test_latency_and_flow_metrics_are_sane(lab, config):
    r = _report(lab, config)
    eps = {e["attack"]: e for e in r["incident_level"]["ensemble"]["per_episode"]}
    assert 0 <= eps["SYN_FLOOD"]["latency_s"] <= 2  # fires as soon as the condition holds
    assert eps["BEACONING"]["latency_s"] > eps["SYN_FLOOD"]["latency_s"]
    fl = r["flow_level"]
    assert fl["attack_flows"] + fl["benign_flows"] == fl["flows"]
    assert fl["engines"]["ensemble"]["recall"] >= fl["engines"]["rules"]["recall"]
    assert 0 < fl["engines"]["anomaly"]["pr_auc"] <= 1
    assert r["supervised"]["status"] == "not evaluated"
    assert "| ensemble |" in evaluate.to_markdown(r)


def test_false_incident_is_counted(lab, config, tmp_path):
    truth = json.loads((lab / "demo" / "ground_truth.json").read_text())
    dropped = [g for g in truth if g["attack"] != "BEACONING"]
    path = tmp_path / "truth.jsonl"
    path.write_text("\n".join(json.dumps(g) for g in dropped))  # JSONL loads too
    r = evaluate.evaluate(lab / "demo", path, config())
    ens = r["incident_level"]["ensemble"]
    # beacon + self-signed TLS + unseen TLS client: three incidents with no episode now
    assert ens["false_incidents"] == 3 and {x["src"] for x in ens["false_incident_examples"]} == {"192.168.1.60"}


def _scan(t0: float) -> list[Flow]:
    return [Flow(ts=t0 + i * 0.5, uid=f"C{i}", src_ip="10.0.0.9", src_port=40000 + i, dst_ip="10.0.0.5",
                 dst_port=i + 1, proto="tcp", conn_state="REJ", history="Sr", orig_pkts=1, resp_pkts=1)
            for i in range(30)]


def test_scan_straddling_a_window_boundary_is_still_caught():
    """30 ports in 15 s, split 15/15 across a 60 s boundary: each tumbling half is below 20."""
    rule_set = [r for r in rules.load_rules(pipeline.ROOT / "config" / "rules.yaml")
                if r.id == "HORIZONTAL_PORT_SCAN"]
    alerts = rules.evaluate(rule_set, _scan(1_800_000_000 - 7.5))
    assert alerts, "hopping windows should cover the whole scan"
    uids = set().union(*(a.flow_uids for a in alerts))
    assert len(uids) == 30


def test_psi_flags_shift_not_noise():
    rng = np.random.default_rng(0)
    ref = rng.normal(size=4000)
    edges = _edges(ref)
    p = _proportions(ref, edges)

    def psi(x):
        q = _proportions(x, edges)
        return float(np.sum((q - p) * np.log(q / p)))

    assert psi(rng.normal(size=4000)) < 0.1
    assert psi(rng.normal(1.0, 1.0, size=4000)) > 0.25


def test_approvals_and_audit_trail(tmp_path):
    from nids.models import Incident
    from nids.storage import Store

    store = Store(tmp_path / "a.db")
    inc = Incident(incident_id="INC-x", ts_start=1.0, ts_end=2.0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
                   attack_type="t", attack_id=None, confidence=0.9, severity="high", flow_count=1, alert_count=1)
    store.save_incident(inc)
    store.save_command("INC-x", "block_source_ip", "cmd", "rollback", None, None)
    cmd = store.latest_command("INC-x")
    store.log_view("INC-x", "alice")
    store.record_decision("INC-x", cmd["id"], "approved", "alice", "CHG-1")
    store.record_decision("INC-x", cmd["id"], "rejected", "bob", "wrong host")
    assert [d["decision"] for d in store.decisions("INC-x")] == ["rejected", "approved"]
    assert [a["action"] for a in store.audit()] == ["rejected", "approved", "viewed command"]
    import pytest
    with pytest.raises(ValueError):
        store.record_decision("INC-x", cmd["id"], "executed", "mallory")


def test_background_psi_separates_attack_from_drift(lab, anomaly_model):
    from nids import anomaly
    from nids.sensing import zeek

    model = anomaly.AnomalyModel.load(anomaly_model)
    flows = zeek.read_conn(lab / "demo" / "conn.log")
    truth = evaluate.load_truth(lab / "demo" / "ground_truth.json")
    attack = {f.uid for f in flows if any(e.covers_flow(f) for e in truth)}
    psi = pipeline.psi_split(model, flows, {"INC-all-attacks": attack})
    assert max(psi["all"].values()) > 0.25  # the attacks alone shift the distribution
    assert max(psi["background"].values()) < 0.1  # the benign remainder has not drifted
    assert psi["background_flows"] == len(flows) - len(attack)
