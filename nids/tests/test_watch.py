"""Live mode: replaying a capture through `watch` must match the batch run, and the
incident lifecycle (new -> updated -> closed -> reopened) must follow log time."""
import json
from pathlib import Path

from nids import pipeline
from nids.storage import Store
from nids.watch import Watcher


def _logs(lab: Path) -> dict[str, list[dict]]:
    logs = {}
    for name in ("conn", "dns", "http", "ssl", "notice"):
        rows = [json.loads(line) for line in (lab / "demo" / f"{name}.log").read_text().splitlines()]
        for r in rows:  # Zeek writes a conn record when the connection ends
            r["_vis"] = r["ts"] + float(r.get("duration", 0) or 0)
        logs[name] = rows
    return logs


def _append(live: Path, logs: dict, lo: float, hi: float) -> None:
    for name, rows in logs.items():
        with (live / f"{name}.log").open("a") as fh:
            for r in rows:
                if lo <= r["_vis"] < hi:
                    fh.write(json.dumps({k: v for k, v in r.items() if k != "_vis"}) + "\n")


def test_watch_replay_matches_batch_and_closes_incidents(lab, config, tmp_path):
    batch = pipeline.run(lab / "demo", config())
    live = tmp_path / "live"
    live.mkdir()
    cfg = config()
    cfg.db_path = tmp_path / "live.db"
    logs = _logs(lab)
    t0 = min(r["ts"] for r in logs["conn"])
    w = Watcher(live, cfg, retention=3600, log=lambda m: None)
    store = Store(cfg.db_path)
    reopened = 0
    for cut in range(300, 2101, 300):
        _append(live, logs, t0 + cut - 300, t0 + cut)
        reopened += w.step()["reopened"]
        if cut == 600:
            # An analyst closes the beacon incident while the beacon is still running:
            # the next pass that sees new beacons must reopen it, not open a duplicate.
            beacon = next(r for r in store.incidents() if r["incident"]["rule_ids"] == ["BEACONING"])
            store.set_status(beacon["incident"]["incident_id"], "closed", "bob", "looked benign")
    assert reopened >= 1
    rows = store.incidents()
    key = lambda i: (i["src_ip"], i["dst_ip"], i["attack_type"], i["flow_count"])  # noqa: E731
    assert sorted(key(r["incident"]) for r in rows) == sorted(key(i.model_dump()) for i in batch)
    assert len(store.runs()) == 1  # one rolling live row, not one per pass

    w.now += 1800  # half an hour of silence: everything but the hour-long upload window closes
    w.step()
    statuses = {r["incident"]["attack_type"]: r["status"] for r in store.incidents()}
    assert statuses.pop("Exfiltration: Bulk Upload to New Destination") == "open"
    assert set(statuses.values()) == {"closed"}

    # The same host starts beaconing again long after: a new episode, so a new incident,
    # one tier more severe because the source already had a (closed) incident today.
    template = next(r for r in logs["conn"] if r["id.orig_h"] == "192.168.1.60")
    with (live / "conn.log").open("a") as fh:
        for k in range(10):
            r = {kk: v for kk, v in template.items() if kk != "_vis"}
            r.update(ts=w.now + 60 * k + (k % 2) * 0.4, uid=f"Cresume{k}")
            fh.write(json.dumps(r) + "\n")
    before = len(store.incidents())
    w.step()
    rows = store.incidents()
    assert len(rows) == before + 1
    fresh = max(rows, key=lambda r: r["incident"]["ts_start"])["incident"]
    assert fresh["rule_ids"] == ["BEACONING"]
    assert any("last 24h" in reason for reason in fresh["severity_reasons"])


def test_tail_survives_rotation_and_partial_lines(tmp_path):
    from nids.watch import Tail

    p = tmp_path / "conn.log"
    p.write_text('{"ts": 1, "uid": "A"}\n{"ts": 2, "ui')
    t = Tail(p)
    assert [r["uid"] for r in t.read()] == ["A"]
    with p.open("a") as fh:
        fh.write('d": "B"}\n')
    assert [r["uid"] for r in t.read()] == ["B"]
    p.rename(tmp_path / "conn.old.log")
    p.write_text('{"ts": 3, "uid": "C"}\n')
    assert [r["uid"] for r in t.read()] == ["C"]
