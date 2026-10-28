"""End-to-end: synthetic demo capture -> incidents, checked against ground truth."""
import json

from nids import pipeline
from nids.storage import Store


def _run(lab, anomaly_model, tmp_path):
    cfg = pipeline.Config(db_path=tmp_path / "nids.db", model_path=anomaly_model)
    demo = lab / "demo"
    return pipeline.run(demo / "conn.log", demo / "dns.log", cfg), Store(cfg.db_path)


def test_one_incident_per_attack_episode(lab, anomaly_model, tmp_path):
    incidents, _ = _run(lab, anomaly_model, tmp_path)
    by_src = {i.src_ip: i for i in incidents}

    assert len(incidents) == 6, [(i.src_ip, i.attack_type) for i in incidents]
    flood = by_src["192.168.1.105"]
    assert flood.rule_ids == ["SYN_FLOOD"] and flood.attack_id == "T1498.001"
    # 24,900 SYN flows plus the attacker's poisoned-UA request 1.5 s earlier, which the
    # hopping window also covers. Overlapping windows must not double-count any of them.
    assert flood.flow_count == 24901 and flood.severity == "critical"
    assert 12000 <= flood.peak_pps <= 13000
    assert by_src["192.168.1.77"].attack_id == "T1046" and by_src["192.168.1.77"].severity == "critical"
    assert by_src["192.168.1.50"].rule_ids == ["DNS_TUNNELING"]
    assert by_src["192.168.1.60"].rule_ids == ["BEACONING"]
    assert by_src["192.168.1.250"].severity == "informational"
    assert by_src["192.168.1.30"].engines == ["anomaly"]  # novel behaviour, no rule


def test_negative_control_first_minute_is_quiet(lab, anomaly_model, tmp_path):
    incidents, _ = _run(lab, anomaly_model, tmp_path)
    truth = json.loads((lab / "demo" / "ground_truth.json").read_text())
    t0 = min(g["start"] for g in truth)
    attackers = {g["src"] for g in truth}
    assert all(i.src_ip in attackers for i in incidents), "benign host raised an incident"
    early = [i for i in incidents if i.ts_start < t0 + 60 and i.src_ip != "192.168.1.60"]
    assert early == []


def test_everything_persists_with_commands(lab, anomaly_model, tmp_path):
    incidents, store = _run(lab, anomaly_model, tmp_path)
    rows = store.incidents()
    assert len(rows) == len(incidents)
    for r in rows:
        assert r["narrative"]["technical_evidence"]
        cmd = store.latest_command(r["incident"]["incident_id"])
        assert cmd and (cmd["command"] or cmd["refused_reason"])
    allowlisted = next(r for r in rows if r["incident"]["src_ip"] == "192.168.1.250")
    assert store.latest_command(allowlisted["incident"]["incident_id"])["intent"] == "no_action"
