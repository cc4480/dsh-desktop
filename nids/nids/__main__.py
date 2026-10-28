"""CLI.

  python -m nids lab                         generate synthetic baseline + demo Zeek logs
  python -m nids train LOGDIR                anomaly model (IF + autoencoder) + behavioural profile
  python -m nids run LOGDIR [--backend ...]  detect, correlate, explain, render, store (batch)
  python -m nids llm-check                   list DeepSeek models and test one grounded narrative
  python -m nids watch LOGDIR                the same, live, following Zeek's current logs
  python -m nids evaluate LOGDIR             score each engine and the ensemble against ground truth
  python -m nids pcap INCIDENT --pcap FILE   cut an incident's packets out of a capture
  python -m nids add-user NAME --role ROLE   dashboard login (analyst | approver)
  python -m nids study-report                results of the blinded raw / template / LLM study
  python -m nids replay LOGDIR --out LIVEDIR stream a capture into LIVEDIR in real time (live demo feed)
  python -m nids docs                        regenerate diagrams + ATT&CK coverage table in docs/
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from nids import anomaly, auth, docs, evaluate, forensics, pipeline, rules, study
from nids.assets import AssetRegistry
from nids.explain import llm
from nids.lab import generate
from nids.models import Incident
from nids.profile import build as build_profile
from nids.sensing import zeek
from nids.storage import Store

SEV_COLOUR = {"critical": "\033[41;97m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m",
              "informational": "\033[37m"}


def _config(a: argparse.Namespace, **extra) -> pipeline.Config:
    return pipeline.Config(rules_path=a.rules, assets_path=a.assets, policy_path=a.policy,
                           model_path=None if getattr(a, "no_anomaly", False) else a.anomaly_model,
                           profile_path=a.profile, supervised_path=a.supervised, **extra)


def _print_incidents(incidents: list[Incident]) -> None:
    for i in incidents:
        c = SEV_COLOUR.get(i.severity, "") if sys.stdout.isatty() else ""
        r = "\033[0m" if c else ""
        camp = f"  [{i.campaign_id}]" if i.campaign_id else ""
        print(f"{c}{i.severity.upper():<13}{r} {i.incident_id}  {i.attack_type:<48} "
              f"{i.src_ip} -> {i.dst_ip or '*'}  flows={i.flow_count} conf={i.confidence}{camp}")


def llm_check(a: argparse.Namespace) -> int:
    """Prove the DeepSeek setup end to end before trusting it with incidents."""
    import os

    if not os.environ.get("DEEPSEEK_API_KEY"):
        print("DEEPSEEK_API_KEY is not set", file=sys.stderr)
        return 1
    try:
        models = llm.list_models(os.environ.get("DEEPSEEK_BASE_URL", llm.DEEPSEEK_URL))
        print("models available to this key:", ", ".join(models) or "(none listed)")
    except Exception as e:  # listing is informative only; the test call below decides
        print(f"could not list models: {type(e).__name__}: {e}")
    model = a.model or os.environ.get("DEEPSEEK_MODEL", "")
    if not model:
        print("pick one and pass --model (or set DEEPSEEK_MODEL)", file=sys.stderr)
        return 1
    sent: list[str] = []
    ex = llm.Explainer(AssetRegistry.load(a.assets), "deepseek", model,
                       egress_log=lambda iid, backend, payload: sent.append(payload))
    probe = Incident(
        incident_id="INC-llm-check", ts_start=1_800_000_000.0, ts_end=1_800_000_060.0, src_ip="203.0.113.9",
        dst_ip="192.168.1.20", attack_type="Brute Force", attack_id="T1110", rule_ids=["BRUTE_FORCE"],
        confidence=0.85, severity="critical", flow_count=40, alert_count=1, asset_name="db-prod-01",
        asset_criticality=5, direction="inbound",
        evidence={"src_ip": "203.0.113.9", "dst_ip": "192.168.1.20", "dst_port": 22, "flow_count": 40,
                  "rule_match": "BRUTE_FORCE", "handshake_ratio": 1.0, "mean_duration": 2.4,
                  "asset_name": "db-prod-01", "asset_criticality": 5})
    res = ex.explain(probe, ["block_source_ip", "review_account_activity", "no_action"], "block_source_ip")
    print(f"\nmodel {model}: {'PASS' if res.validation_passed else 'FAIL'}"
          f"  ({res.latency_ms} ms)  {'; '.join(res.reasons)}")
    print("summary:", res.narrative.summary)
    print("evidence:", res.narrative.technical_evidence, " intent:", res.narrative.remediation_intent)
    leaked = [s for s in ("192.168.1.20", "db-prod-01") if any(s in p for p in sent)]
    print("redaction:", "OK, internal address and asset name never left the host" if not leaked
          else f"LEAKED {leaked}")
    return 0 if res.validation_passed and not leaked else 1


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nids")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = pipeline.Config

    lab = sub.add_parser("lab", help="generate synthetic Zeek logs")
    lab.add_argument("--out", type=Path, default=pipeline.ROOT / "data" / "lab")

    tr = sub.add_parser("train", help="fit the anomaly model and build the profile from benign logs")
    tr.add_argument("logdir", type=Path)
    tr.add_argument("--no-clean", action="store_true", help="skip majority-vote baseline cleaning")
    tra = sub.add_parser("train-anomaly", help="alias of train")
    tra.add_argument("logdir", type=Path)
    tra.add_argument("--no-clean", action="store_true")
    for p in (tr, tra):
        p.add_argument("--out", type=Path, default=d.model_path)
        p.add_argument("--profile-out", type=Path, default=d.profile_path)
        p.add_argument("--rules", type=Path, default=d.rules_path)

    run = sub.add_parser("run", help="run the pipeline over a Zeek log dir")
    watch = sub.add_parser("watch", help="follow a live Zeek log dir")
    ev = sub.add_parser("evaluate", help="score a capture against its ground truth")
    for p in (run, watch):
        p.add_argument("logdir", type=Path)
        p.add_argument("--db", type=Path, default=d.db_path)
        p.add_argument("--backend", choices=list(llm.BACKENDS), default=llm.default_backend(),
                       help="default: deepseek if DEEPSEEK_API_KEY is set, else none (template only)")
        p.add_argument("--model", default="", help="LLM model id (DeepSeek: or set DEEPSEEK_MODEL)")
        p.add_argument("--no-anomaly", action="store_true")
    run.add_argument("--fresh", action="store_true", help="delete the database first")
    watch.add_argument("--interval", type=float, default=10.0, help="seconds between detection passes")
    watch.add_argument("--retention", type=float, default=3600.0, help="seconds of history kept in memory")
    watch.add_argument("--once", action="store_true", help="one pass, then exit (for testing)")
    ev.add_argument("logdir", type=Path)
    ev.add_argument("--truth", type=Path, help="default: LOGDIR/ground_truth.json(l)")
    ev.add_argument("--out", type=Path, default=pipeline.ROOT / "data" / "eval")
    for p in (run, watch, ev):
        p.add_argument("--rules", type=Path, default=d.rules_path)
        p.add_argument("--assets", type=Path, default=d.assets_path)
        p.add_argument("--policy", type=Path, default=d.policy_path)
        p.add_argument("--anomaly-model", type=Path, default=d.model_path)
        p.add_argument("--profile", type=Path, default=d.profile_path)
        p.add_argument("--supervised", type=Path, default=d.supervised_path)

    pc = sub.add_parser("pcap", help="extract an incident's packets from a capture")
    pc.add_argument("incident_id")
    pc.add_argument("--pcap", type=Path, required=True)
    pc.add_argument("--out", type=Path)
    pc.add_argument("--db", type=Path, default=d.db_path)

    au = sub.add_parser("add-user", help="create or update a dashboard login")
    au.add_argument("name")
    au.add_argument("--role", choices=list(auth.ROLES), required=True)
    au.add_argument("--users", type=Path, default=auth.USERS_PATH)

    lc = sub.add_parser("llm-check", help="list DeepSeek models and run one validated test narrative")
    lc.add_argument("--model", default="", help="model to test (default: DEEPSEEK_MODEL)")
    lc.add_argument("--assets", type=Path, default=d.assets_path)

    sr = sub.add_parser("study-report", help="summarise the blinded analyst study")
    sr.add_argument("--db", type=Path, default=d.db_path)

    rp = sub.add_parser("replay", help="stream a recorded Zeek log dir into LIVEDIR in real time")
    rp.add_argument("logdir", type=Path)
    rp.add_argument("--out", type=Path, default=pipeline.ROOT / "data" / "live")
    rp.add_argument("--speed", type=float, default=10.0, help="times real time (default 10)")
    rp.add_argument("--align", choices=["day", "now", "none"], default="day",
                    help="day: shift to today keeping the time of day (default); now: to the wall clock")

    dc = sub.add_parser("docs", help="write architecture diagrams and the ATT&CK coverage table")
    dc.add_argument("--out", type=Path, default=pipeline.ROOT / "docs")

    a = ap.parse_args(argv)
    if a.cmd == "lab":
        generate.main(["--out", str(a.out)])
    elif a.cmd in ("train", "train-anomaly"):
        bundle = zeek.read_dir(a.logdir)
        # Majority vote, part 1: anything a rule fires on is not baseline.
        flagged = {u for al in rules.evaluate(rules.load_rules(a.rules), bundle) for u in al.flow_uids}
        model = anomaly.train(bundle.flows, exclude_uids=flagged, clean=not a.no_clean)
        model.save(a.out)
        prof = build_profile(bundle)
        prof.save(a.profile_out)
        print(f"anomaly model: {model.n_train} flows after removing {model.n_cleaned} "
              f"(rule hits + top-1% votes), hours calibrated {sorted(model.by_hour)} -> {a.out}")
        print(f"profile: {prof.summary()} -> {a.profile_out}")
    elif a.cmd == "run":
        if a.fresh and a.db.exists():
            a.db.unlink()
        incidents = pipeline.run(a.logdir, _config(a, db_path=a.db, backend=a.backend, llm_model=a.model))
        _print_incidents(incidents)
        stats = Store(a.db).last_run()["stats"]  # type: ignore[index]
        if stats["inactive_rules"]:
            print(f"\nrules that could not fire (no profile): {', '.join(stats['inactive_rules'])}")
        print(f"\n{len(incidents)} incidents -> {a.db}   engines: {stats['engines']}")
    elif a.cmd == "watch":
        from nids import watch as watch_mod

        watch_mod.watch(a.logdir, _config(a, db_path=a.db, backend=a.backend, llm_model=a.model),
                        interval=a.interval, retention=a.retention, once=a.once)
    elif a.cmd == "evaluate":
        report = evaluate.evaluate(a.logdir, a.truth, _config(a))
        a.out.mkdir(parents=True, exist_ok=True)
        stem = a.logdir.resolve().name
        (a.out / f"{stem}.json").write_text(json.dumps(report, indent=2))
        md = evaluate.to_markdown(report)
        (a.out / f"{stem}.md").write_text(md)
        print(md)
        print(f"-> {a.out / stem}.json / .md")
    elif a.cmd == "pcap":
        body = Store(a.db).get_incident(a.incident_id)
        if not body:
            print(f"no incident {a.incident_id} in {a.db}", file=sys.stderr)
            return 1
        inc = Incident.model_validate(body)
        out = a.out or Path(f"{inc.incident_id}.pcap")
        ok, msg = forensics.extract(inc.forensics, a.pcap, out)
        print(msg)
        return 0 if ok else 1
    elif a.cmd == "add-user":
        pw = getpass.getpass(f"password for {a.name}: ")
        if pw != getpass.getpass("repeat: "):
            print("passwords differ", file=sys.stderr)
            return 1
        auth.add_user(a.users, a.name, pw, a.role)
        print(f"{a.name} ({a.role}) -> {a.users}")
    elif a.cmd == "llm-check":
        return llm_check(a)
    elif a.cmd == "replay":
        from nids import replay

        replay.replay(a.logdir, a.out, speed=a.speed, align=a.align)
    elif a.cmd == "docs":
        for p in docs.write(a.out):
            print(p)
    elif a.cmd == "study-report":
        print(study.to_markdown(study.report(Store(a.db).study_responses())))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except ValueError as e:  # configuration problems (e.g. DeepSeek key or model missing)
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
