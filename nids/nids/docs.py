"""Generated documentation: architecture diagrams and the ATT&CK coverage table.

Both are built from the code and config the system actually runs, so they cannot drift:
the table reads config/rules.yaml and config/attack.yaml, the diagrams name the real
modules. Diagrams are Graphviz DOT (the dashboard renders them in the browser, no
system Graphviz needed); `nids docs` also writes SVG when the `dot` binary exists.
"""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import yaml

from nids import rules as rules_mod
from nids.correlation import POINT_ENGINES

ROOT = Path(__file__).resolve().parents[1]

_STYLE = """
  graph [rankdir=LR, fontname="Helvetica", fontsize=11, nodesep=0.35, ranksep=0.5, bgcolor="transparent"];
  node  [shape=box, style="rounded,filled", fillcolor="#f4f6f8", color="#8a94a0", fontname="Helvetica", fontsize=10];
  edge  [color="#5b6570", fontname="Helvetica", fontsize=9];
"""

ARCHITECTURE = """digraph architecture {""" + _STYLE + """
  subgraph cluster_sensor {
    label="Plane 1  Sensing (edge)"; style="rounded"; color="#8a94a0";
    zeek  [label="Zeek 9 + JA4\\nconn dns http ssl notice weird"];
    sanit [label="Edge sanitisation\\nUA -> enum, URI -> len + hash\\nCommunity ID v1"];
    zeek -> sanit;
  }
  subgraph cluster_detect {
    label="Planes 2-3  Features and detection (deterministic)"; style="rounded"; color="#8a94a0";
    feat  [label="Feature registry v2\\nhopping windows"];
    prof  [label="Behavioural profile\\nknown dsts, hourly bytes, JA4 set"];
    rules [label="Rule engine\\nYAML (feature, op, value), no eval"];
    anom  [label="Anomaly engine\\nIsolation Forest + autoencoder\\nper-hour ECDF calibration"];
    sup   [label="Supervised model\\nCIC-IDS2017, Zeek adapter\\nisotonic calibration"];
    feat -> rules; prof -> rules; feat -> anom; feat -> sup;
  }
  subgraph cluster_correlate {
    label="Plane 4  Correlation and policy (deterministic)"; style="rounded"; color="#8a94a0";
    corr  [label="Correlator\\nincidents by (src, dst, attack)\\ncampaigns, severity table"];
    pol   [label="Policy engine\\niptables / nftables + rollback\\nguards, never executes"];
    corr -> pol;
  }
  subgraph cluster_explain {
    label="Plane 5  Explanation (untrusted output)"; style="rounded,dashed"; color="#c0392b"; fontcolor="#c0392b";
    prompt [label="Prompt builder\\nCONTEXT / CLASSIFICATION / EVIDENCE"];
    redact [label="Redactor\\ninternal IPs + asset names aliased"];
    llm    [label="DeepSeek API\\n(cloud, json_object)", fillcolor="#fdecea", color="#c0392b"];
    valid  [label="Validator\\ncitations, CVEs, commands\\noverrides owned fields"];
    tmpl   [label="Template fallback"];
    prompt -> redact -> llm -> valid;
    valid -> tmpl [label="reject", style=dashed];
  }
  store [label="SQLite store\\nincidents, approvals, egress_log, cache", shape=cylinder];
  ui    [label="Dashboard\\nanalyst / approver"];
  sanit -> feat; sanit -> prof;
  rules -> corr; anom -> corr; sup -> corr;
  corr -> prompt;
  valid -> store; tmpl -> store; pol -> store;
  store -> ui;
  ui -> pol [label="approve (human)", style=dashed];
}
"""

TRUST_BOUNDARY = """digraph trust {""" + _STYLE + """
  subgraph cluster_trusted {
    label="Trusted: decided by code and config"; style="rounded"; color="#2e7d32"; fontcolor="#2e7d32";
    cls   [label="Classification\\nattack type, ATT&CK id, severity,\\nconfidence, allowed intents"];
    ctx   [label="CONTEXT\\nlocal ATT&CK summary + runbook"];
    owned [label="Owned fields in the final narrative\\nattack id, severity, intent, command"];
  }
  subgraph cluster_untrusted {
    label="Untrusted: attacker-influenced or model-generated"; style="rounded,dashed"; color="#c0392b"; fontcolor="#c0392b";
    ev    [label="EVIDENCE\\nfeature values, hostnames, DNS names\\n(may carry injected text)"];
    out   [label="LLM output\\nsummary, technical_evidence"];
  }
  check [label="Validator\\ncited field must exist AND match value\\nno new CVEs, no commands\\nintent must be in allowed list", fillcolor="#fff8e1"];
  cls -> check; ctx -> out [label="prompt"]; ev -> out [label="prompt (data only)"];
  out -> check;
  check -> owned [label="overwrite"];
}
"""

DATA_FLOW = """digraph dataflow {""" + _STYLE + """
  pcap  [label="Network traffic\\n(mirror / TAP)", shape=ellipse];
  logs  [label="Zeek logs\\n(rotating)"];
  watch [label="nids watch\\nrotation-safe tail, 10 s passes"];
  inc   [label="Incident\\n(local, full evidence)"];
  red   [label="Redacted prompt\\n10.x -> HOST_1, db-prod-01 -> ASSET_1"];
  ds    [label="api.deepseek.com", shape=ellipse, fillcolor="#fdecea", color="#c0392b"];
  egr   [label="egress_log\\nexact payload sent", shape=cylinder];
  nar   [label="Validated narrative\\naliases restored locally"];
  db    [label="SQLite", shape=cylinder];
  ui    [label="Dashboard"];
  fw    [label="Firewall command\\n(printed for a human)", shape=note];
  pcap -> logs -> watch -> inc -> red;
  red -> ds [label="HTTPS, only when backend=deepseek", color="#c0392b", fontcolor="#c0392b"];
  red -> egr [label="recorded first"];
  ds -> nar -> db -> ui -> fw [label="approver"];
  inc -> db [label="always (template if no LLM)"];
}
"""

DIAGRAMS = {"architecture": ARCHITECTURE, "trust_boundary": TRUST_BOUNDARY, "data_flow": DATA_FLOW}


def _condition(c) -> str:
    v = f"{c.value:g}" if isinstance(c.value, float) else c.value
    return f"{c.feature} {c.op} {v}"


def attack_table(rules_path: Path | None = None, attack_path: Path | None = None) -> list[dict]:
    rules = rules_mod.load_rules(rules_path or ROOT / "config" / "rules.yaml")
    with (attack_path or ROOT / "config" / "attack.yaml").open(encoding="utf-8") as fh:
        attack = yaml.safe_load(fh) or {}
    rows = []
    for r in rules:
        ref = attack.get(r.attack_id, {})
        rows.append({
            "detector": r.id, "engine": "rules", "attack_id": r.attack_id,
            "technique": ref.get("name", "(missing from attack.yaml)"), "tactic": ref.get("tactic", ""),
            "signal": "; ".join(_condition(c) for c in r.when), "window_s": r.window,
            "confidence": r.confidence, "default_intent": r.default_intent,
            "runbook": (ROOT / "runbooks" / f"{r.id}.md").exists(),
        })
    for engine in POINT_ENGINES:  # no technique by design: an analyst classifies these
        rows.append({
            "detector": engine.upper(), "engine": engine, "attack_id": "", "technique": "(unclassified)",
            "tactic": "", "signal": "per-flow score above calibrated threshold, >= 3 flows per pair",
            "window_s": None, "confidence": None, "default_intent": "enable_verbose_logging",
            "runbook": (ROOT / "runbooks" / "ANOMALY.md").exists(),
        })
    return rows


def attack_markdown(rows: list[dict]) -> str:
    lines = ["# ATT&CK coverage", "",
             "Generated by `python -m nids docs` from config/rules.yaml and config/attack.yaml.",
             "ATT&CK ids are assigned by these rules, never by the LLM.", "",
             "| Detector | ATT&CK | Technique | Tactic | Signal | Window | Conf. | Default intent | Runbook |",
             "|---|---|---|---|---|---|---|---|---|"]
    for r in rows:
        window = "-" if r["window_s"] is None else f"{r['window_s']:g} s"
        lines.append(f"| {r['detector']} | {r['attack_id'] or '-'} | {r['technique']} | {r['tactic'] or '-'} | "
                     f"`{r['signal']}` | {window} | "
                     f"{'-' if r['confidence'] is None else r['confidence']} | {r['default_intent']} | "
                     f"{'yes' if r['runbook'] else 'MISSING'} |")
    tactics = sorted({r["tactic"] for r in rows if r["tactic"]})
    lines += ["", f"{len({r['attack_id'] for r in rows if r['attack_id']})} techniques across "
              f"{len(tactics)} tactics: {', '.join(tactics)}."]
    return "\n".join(lines) + "\n"


def write(out: Path) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written = []
    for name, dot in DIAGRAMS.items():
        p = out / f"{name}.dot"
        p.write_text(dot)
        written.append(p)
        if shutil.which("dot"):
            svg = out / f"{name}.svg"
            subprocess.run(["dot", "-Tsvg", str(p), "-o", str(svg)], check=True)
            written.append(svg)
    p = out / "attack_coverage.md"
    p.write_text(attack_markdown(attack_table()))
    written.append(p)
    return written
