"""The live layer: replay feed, background jobs, generated docs, and the dashboard rendering."""
import json
import time

import pytest

from nids import docs, jobs, replay
from nids.rules import load_rules

DAY = 86_400.0


def _logdir(tmp_path, gap=1.0):
    d = tmp_path / "cap"
    d.mkdir()
    t0 = 1_793_178_000.0
    (d / "conn.log").write_text("\n".join(json.dumps({"ts": t0 + k * gap, "uid": f"C{k}"}) for k in range(3)) + "\n")
    (d / "dns.log").write_text(json.dumps({"ts": t0 + 0.5 * gap, "query": "example.org"}) + "\n")
    tsv = ["#separator \\x09", "#fields\tts\tpkts_proc", f"{t0 + 2 * gap}\t10"]
    (d / "stats.log").write_text("\n".join(tsv) + "\n")
    return d, t0


def test_replay_routes_each_log_and_shifts_whole_days(tmp_path):
    d, t0 = _logdir(tmp_path)
    now = [t0 + 3 * DAY + 5 * 3600]  # 3 days and 5 hours later
    clock = lambda: now[0]  # noqa: E731

    def sleep(s):
        now[0] += s

    n = replay.replay(d, tmp_path / "live", speed=1.0, clock=clock, sleep=sleep, log=lambda m: None)
    assert n == 5
    out = {p.stem: [json.loads(x) for x in p.read_text().splitlines()] for p in (tmp_path / "live").glob("*.log")}
    assert [r["uid"] for r in out["conn"]] == ["C0", "C1", "C2"]
    assert out["dns"][0]["query"] == "example.org"
    assert out["stats"][0]["pkts_proc"] == "10"  # TSV input becomes JSON lines
    assert out["conn"][0]["ts"] == t0 + 3 * DAY  # time of day kept, never shifted into the future


def test_replay_paces_by_speed(tmp_path):
    d, t0 = _logdir(tmp_path, gap=100.0)
    now = [t0]
    slept = []

    def sleep(s):
        slept.append(s)
        now[0] += s

    replay.replay(d, tmp_path / "live", speed=50.0, align="none", tick=0.5, clock=lambda: now[0], sleep=sleep,
                  log=lambda m: None)
    assert 3.5 <= sum(slept) <= 4.5  # 200 s of traffic at 50x


def test_jobs_start_status_output_stop(tmp_path):
    d, _ = _logdir(tmp_path, gap=3600.0)  # two hours of traffic at 1x: still running when stopped
    jd = tmp_path / "jobs"
    st = jobs.start("feed", ["replay", str(d), "--out", str(tmp_path / "live"), "--speed", "1", "--align", "none"], jd)
    assert st["running"] and st["pid"]
    again = jobs.start("feed", ["lab"], jd)  # refuses to start a second copy
    assert again["pid"] == st["pid"]
    deadline = time.time() + 20
    while "replaying" not in jobs.output("feed", jd) and time.time() < deadline:
        time.sleep(0.2)
    assert "replaying" in jobs.output("feed", jd)
    assert jobs.stop("feed", jd)
    assert not jobs.status("feed", jd)["running"]
    assert not jobs.stop("feed", jd)


def test_attack_table_covers_every_rule_with_a_known_technique():
    rows = docs.attack_table()
    rule_ids = {r.id for r in load_rules(docs.ROOT / "config" / "rules.yaml")}
    assert rule_ids <= {r["detector"] for r in rows}
    for r in rows:
        if r["engine"] == "rules":
            assert r["tactic"], f"{r['attack_id']} missing from attack.yaml"
        assert r["runbook"], f"no runbook for {r['detector']}"
    md = docs.attack_markdown(rows)
    assert md.count("\n| ") == len(rows) + 1


def test_docs_write(tmp_path):
    written = {p.name for p in docs.write(tmp_path)}
    assert {"architecture.dot", "trust_boundary.dot", "data_flow.dot", "attack_coverage.md"} <= written
    for name in docs.DIAGRAMS:
        dot = (tmp_path / f"{name}.dot").read_text()
        assert dot.count("{") == dot.count("}")


@pytest.mark.parametrize("role", ["approver", "analyst"])
def test_dashboard_renders_every_tab(tmp_path, monkeypatch, role):
    from streamlit.testing.v1 import AppTest

    monkeypatch.setenv("NIDS_DB", str(tmp_path / "ui.db"))
    monkeypatch.setenv("NIDS_DASHBOARD_PASSWORD", "test-password-1")
    at = AppTest.from_file(str(docs.ROOT / "dashboard" / "app.py"), default_timeout=60)
    at.session_state["authed"] = True
    at.session_state["viewer"] = "tester"
    at.session_state["role"] = role
    at.run()
    assert not at.exception, at.exception
    labels = [t.label for t in at.tabs]
    assert {"System", "Architecture"} <= set(labels)
    start = [b for b in at.button if "Start live demo" in b.label]
    assert start
    if role == "analyst":  # operating the system needs the approver role
        assert start[0].disabled
