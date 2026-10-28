"""CLI.

  python -m nids lab                         generate synthetic baseline + demo Zeek logs
  python -m nids train LOGDIR                anomaly model (IF + autoencoder) + behavioural profile
  python -m nids run LOGDIR [--backend ...]  detect, correlate, explain, render, store (batch)
  python -m nids watch LOGDIR                the same, live, following Zeek's current logs
  python -m nids evaluate LOGDIR             score each engine and the ensemble against ground truth
  python -m nids pcap INCIDENT --pcap FILE   cut an incident's packets out of a capture
  python -m nids add-user NAME --role ROLE   dashboard login (analyst | approver)
  python -m nids study-report                results of the blinded raw / template / LLM study
"""
from __future__ import annotations

import argparse
import getpass
import json
import sys
from pathlib import Path

from nids import anomaly, auth, evaluate, forensics, pipeline, rules, study
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
        p.add_argument("--backend", choices=["none", "ollama", "openai"], default="none")
        p.add_argument("--model", default="llama3.1:8b")
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

    sr = sub.add_parser("study-report", help="summarise the blinded analyst study")
    sr.add_argument("--db", type=Path, default=d.db_path)

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
    elif a.cmd == "study-report":
        print(study.to_markdown(study.report(Store(a.db).study_responses())))
    return 0


if __name__ == "__main__":
    sys.exit(main())
