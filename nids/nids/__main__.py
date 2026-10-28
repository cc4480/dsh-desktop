"""CLI.

  python -m nids lab                        generate synthetic baseline + demo Zeek logs
  python -m nids train-anomaly LOGDIR       fit IsolationForest + frozen ECDF on benign logs
  python -m nids run LOGDIR [--backend ...] detect, correlate, explain, render, store
  python -m nids evaluate LOGDIR            score rules / anomaly / ensemble against ground truth
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from nids import anomaly, evaluate, pipeline
from nids.lab import generate
from nids.sensing import zeek

SEV_COLOUR = {"critical": "\033[41;97m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m",
              "informational": "\033[37m"}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="nids")
    sub = ap.add_subparsers(dest="cmd", required=True)

    lab = sub.add_parser("lab", help="generate synthetic Zeek logs")
    lab.add_argument("--out", type=Path, default=pipeline.ROOT / "data" / "lab")

    tr = sub.add_parser("train-anomaly", help="fit the anomaly model on a benign Zeek log dir")
    tr.add_argument("logdir", type=Path)
    tr.add_argument("--out", type=Path, default=pipeline.ROOT / "models" / "anomaly.joblib")

    run = sub.add_parser("run", help="run the pipeline over a Zeek log dir")
    run.add_argument("logdir", type=Path)
    run.add_argument("--db", type=Path, default=pipeline.Config.db_path)
    run.add_argument("--backend", choices=["none", "ollama", "openai"], default="none")
    run.add_argument("--model", default="llama3.1:8b")
    run.add_argument("--no-anomaly", action="store_true")
    run.add_argument("--fresh", action="store_true", help="delete the database first")

    ev = sub.add_parser("evaluate", help="score a capture against its ground truth")
    ev.add_argument("logdir", type=Path)
    ev.add_argument("--truth", type=Path, help="default: LOGDIR/ground_truth.json(l)")
    ev.add_argument("--out", type=Path, default=pipeline.ROOT / "data" / "eval")

    for p in (run, ev):
        p.add_argument("--rules", type=Path, default=pipeline.Config.rules_path)
        p.add_argument("--assets", type=Path, default=pipeline.Config.assets_path)
        p.add_argument("--anomaly-model", type=Path, default=pipeline.Config.model_path)

    a = ap.parse_args(argv)
    if a.cmd == "lab":
        generate.main(["--out", str(a.out)])
    elif a.cmd == "train-anomaly":
        flows = zeek.read_conn(a.logdir / "conn.log")
        model = anomaly.train(flows)
        model.save(a.out)
        print(f"trained on {len(flows)} benign flows -> {a.out}")
    elif a.cmd == "run":
        if a.fresh and a.db.exists():
            a.db.unlink()
        cfg = pipeline.Config(db_path=a.db, backend=a.backend, llm_model=a.model, rules_path=a.rules,
                              assets_path=a.assets, model_path=None if a.no_anomaly else a.anomaly_model)
        dns = a.logdir / "dns.log"
        incidents = pipeline.run(a.logdir / "conn.log", dns if dns.exists() else None, cfg)
        for i in incidents:
            c = SEV_COLOUR.get(i.severity, "") if sys.stdout.isatty() else ""
            r = "\033[0m" if c else ""
            print(f"{c}{i.severity.upper():<13}{r} {i.incident_id}  {i.attack_type:<48} "
                  f"{i.src_ip} -> {i.dst_ip or '*'}  flows={i.flow_count} conf={i.confidence}")
        print(f"\n{len(incidents)} incidents -> {a.db}")
    elif a.cmd == "evaluate":
        cfg = pipeline.Config(rules_path=a.rules, assets_path=a.assets, model_path=a.anomaly_model)
        report = evaluate.evaluate(a.logdir, a.truth, cfg)
        a.out.mkdir(parents=True, exist_ok=True)
        stem = a.logdir.resolve().name
        (a.out / f"{stem}.json").write_text(json.dumps(report, indent=2))
        md = evaluate.to_markdown(report)
        (a.out / f"{stem}.md").write_text(md)
        print(md)
        print(f"-> {a.out / stem}.json / .md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
