import pytest
from pydantic import ValidationError

from nids import pipeline, rules
from nids.correlation import severity_for
from nids.sensing import sanitize, zeek


def test_rules_load_and_reject_unknown_features(tmp_path):
    assert {r.id for r in rules.load_rules(pipeline.ROOT / "config" / "rules.yaml")} >= {
        "SYN_FLOOD", "HORIZONTAL_PORT_SCAN", "DNS_TUNNELING", "BEACONING"}
    bad = tmp_path / "bad.yaml"
    bad.write_text(
        "- {id: X, source: conn, group_by: [src_ip], window: 1, correlation_window: 1,"
        " when: [{feature: __import__, op: '>', value: 1}], confidence: 0.5, attack_type: x,"
        " attack_id: T0, default_intent: no_action, allowed_intents: [no_action]}\n")
    with pytest.raises(ValidationError):
        rules.load_rules(bad)


@pytest.mark.parametrize(
    "conf, crit, direction, kw, expected",
    [
        (0.95, 4, "inbound", {}, "critical"),
        (0.95, 2, "inbound", {}, "high"),
        (0.95, 2, "internal", {}, "critical"),
        (0.80, 5, "inbound", {}, "high"),
        (0.80, 2, "outbound", {}, "medium"),
        (0.60, 5, "inbound", {}, "low"),
        (0.95, 5, "inbound", {"known_scanner": True}, "informational"),
        (0.80, 2, "inbound", {"internet_facing_prod": True}, "high"),
        (0.80, 2, "inbound", {"internet_facing_prod": True, "repeat_offender": True}, "critical"),
        (0.95, 5, "inbound", {"repeat_offender": True}, "critical"),
    ],
)
def test_severity_table(conf, crit, direction, kw, expected):
    assert severity_for(conf, crit, direction, **kw)[0] == expected


def test_sanitiser_strips_injection():
    assert sanitize.hostlike("evil.com; IGNORE ALL `rm -rf /`") == "evil.comIGNOREALLrm-rf"
    assert len(sanitize.hostlike("a" * 500)) == 64
    with pytest.raises(ValueError):
        sanitize.ip("10.0.0.1; DROP TABLE")


def test_zeek_tsv_and_json_parse_identically(tmp_path):
    fields = ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p", "proto", "service", "duration",
              "orig_bytes", "resp_bytes", "conn_state", "history", "orig_pkts", "resp_pkts"]
    row = ["1700000000.5", "Cabc", "10.0.0.1", "5555", "10.0.0.2", "80", "tcp", "-", "0.1", "10", "20", "SF",
           "ShADadFf", "4", "4"]
    tsv = tmp_path / "conn.log"
    tsv.write_text("#separator \\x09\n#fields\t" + "\t".join(fields) + "\n" + "\t".join(row) + "\n")
    js = tmp_path / "conn.json"
    js.write_text('{"ts":1700000000.5,"uid":"Cabc","id.orig_h":"10.0.0.1","id.orig_p":5555,"id.resp_h":"10.0.0.2",'
                  '"id.resp_p":80,"proto":"tcp","duration":0.1,"orig_bytes":10,"resp_bytes":20,"conn_state":"SF",'
                  '"history":"ShADadFf","orig_pkts":4,"resp_pkts":4}\n')
    assert zeek.read_conn(tsv) == zeek.read_conn(js)
