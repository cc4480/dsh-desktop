"""End-to-end: synthetic demo capture -> incidents, checked against ground truth."""
import json

from nids import pipeline
from nids.storage import Store


def _run(lab, config):
    cfg = config()
    return pipeline.run(lab / "demo", cfg), Store(cfg.db_path)


def test_one_incident_per_attack_technique(lab, config):
    incidents, _ = _run(lab, config)
    by = {(i.src_ip, i.attack_id): i for i in incidents}

    assert len(incidents) == 11, [(i.src_ip, i.attack_type) for i in incidents]
    flood = by[("192.168.1.105", "T1498.001")]
    # 24,900 SYN flows plus the attacker's poisoned-UA request 1.5 s earlier, which the
    # hopping window also covers. Overlapping windows must not double-count any of them.
    assert flood.flow_count == 24901 and flood.severity == "critical"
    assert 12000 <= flood.peak_pps <= 13000
    assert by[("192.168.1.77", "T1046")].severity == "critical"
    assert by[("192.168.1.50", "T1048")].rule_ids == ["DNS_TUNNELING"]
    assert by[("192.168.1.250", "T1046")].severity == "informational"
    upload = by[("192.168.1.30", "T1048")]
    assert upload.rule_ids == ["NEW_DESTINATION_BULK_UPLOAD"]  # behaviour, via the profile

    brute = by[("192.168.1.99", "T1110")]
    # Zeek's SSH::Password_Guessing notice merges into the conn-based incident, and is not
    # counted as a flow.
    assert brute.rule_ids == ["BRUTE_FORCE", "ZEEK_SSH_PASSWORD_GUESSING"] and brute.flow_count == 40
    assert brute.evidence["notice_count"] == 1


def test_multi_stage_activity_is_linked_into_campaigns(lab, config):
    incidents, _ = _run(lab, config)
    camp = {}
    for i in incidents:
        if i.campaign_id:
            camp.setdefault(i.campaign_id, set()).add((i.src_ip, i.attack_id))
    assert sorted(camp.values(), key=len) == [
        {("192.168.1.88", "T1595.002"), ("192.168.1.88", "T1595.003")},
        {("192.168.1.60", "T1071"), ("192.168.1.60", "T1071.001"), ("192.168.1.60", "T1573")},
    ]


def test_negative_controls_stay_quiet(lab, config):
    """No incident from benign hosts, the first minute, or the admin's legitimate SSH."""
    incidents, _ = _run(lab, config)
    truth = json.loads((lab / "demo" / "ground_truth.json").read_text())
    t0 = min(g["start"] for g in truth)
    attackers = {g["src"] for g in truth}
    assert all(i.src_ip in attackers for i in incidents), "benign host raised an incident"
    assert not any(i.src_ip == "192.168.1.5" for i in incidents)
    early = [i for i in incidents if i.ts_start < t0 + 60 and i.src_ip != "192.168.1.60"]
    assert early == []


def test_everything_persists_with_commands_and_forensics(lab, config):
    incidents, store = _run(lab, config)
    rows = store.incidents()
    assert len(rows) == len(incidents)
    for r in rows:
        assert r["narrative"]["technical_evidence"] and r["template"]
        cmd = store.latest_command(r["incident"]["incident_id"])
        assert cmd and (cmd["command"] or cmd["refused_reason"])
        f = r["incident"]["forensics"]
        assert f["bpf"].startswith("host ") and f["start"] < f["end"]
    allowlisted = next(r for r in rows if r["incident"]["src_ip"] == "192.168.1.250")
    assert store.latest_command(allowlisted["incident"]["incident_id"])["intent"] == "no_action"
    stats = store.last_run()["stats"]
    assert stats["engines"] == {"anomaly": "loaded", "supervised": "not trained", "profile": "loaded"}
    assert stats["inactive_rules"] == [] and stats["sensor"]["notices"] == 1


def test_profile_rules_are_reported_inactive_without_a_profile(lab, config):
    cfg = config()
    cfg.profile_path = None
    pipeline.run(lab / "demo", cfg)
    stats = Store(cfg.db_path).last_run()["stats"]
    assert set(stats["inactive_rules"]) == {"NEW_TLS_FINGERPRINT", "NEW_DESTINATION_BULK_UPLOAD"}
