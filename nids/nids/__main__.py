"""CLI.

  python -m nids lab                        generate synthetic baseline + demo Zeek logs
  python -m nids train-anomaly LOGDIR       fit IsolationForest + frozen ECDF on benign logs
  python -m nids run LOGDIR [--backend ...] detect, correlate, explain, render, store
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from nids import anomaly, pipeline
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
        cfg = pipeline.Config(db_path=a.db, backend=a.backend, llm_model=a.model)
        if a.no_anomaly:
            cfg.model_path = None
        dns = a.logdir / "dns.log"
        incidents = pipeline.run(a.logdir / "conn.log", dns if dns.exists() else None, cfg)
        for i in incidents:
            c = SEV_COLOUR.get(i.severity, "") if sys.stdout.isatty() else ""
            r = "\033[0m" if c else ""
            print(f"{c}{i.severity.upper():<13}{r} {i.incident_id}  {i.attack_type:<48} "
                  f"{i.src_ip} -> {i.dst_ip or '*'}  flows={i.flow_count} conf={i.confidence}")
        print(f"\n{len(incidents)} incidents -> {a.db}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
