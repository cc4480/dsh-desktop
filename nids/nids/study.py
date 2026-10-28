"""§6.4 ablation: does the LLM narrative actually help an analyst?

Three versions of each incident, shown blind:
  A  raw alert      what an IDS console shows: the signature that fired plus flow
                    statistics, no prose (the "cryptic telemetry" baseline). It keeps the
                    signature name because every real alert has one; hiding it would
                    measure "label vs no label", not "narrative vs raw alert"
  B  template       the deterministic summary (nids/explain/template.py)
  C  LLM narrative  the validated, grounded narrative (only where one exists)

Each analyst sees each incident once, in one version, assigned by a stable hash of
(analyst, incident) so versions are balanced across analysts and nobody sees the same
incident twice. Order is shuffled per analyst. For each item the dashboard times two
multiple-choice questions (what happened? what should be done?) and collects
actionability and confidence ratings (1-5). This module builds the items, grades the
answers and summarises the deltas.

Because every version names the detection in some form, "what happened" accuracy is
expected near the ceiling everywhere; the discriminating measures are time to answer
and whether the analyst picks an appropriate first action.
"""
from __future__ import annotations

import hashlib
import random
import statistics
from dataclasses import dataclass

NO_ATTACK = "Benign / no attack"
INTENT_LABELS = {
    "block_source_ip": "Block the source address",
    "rate_limit_destination_port": "Rate-limit the targeted port",
    "isolate_host": "Isolate the affected host",
    "enable_verbose_logging": "Capture traffic and investigate",
    "review_account_activity": "Review account activity",
    "no_action": "No action needed",
}
RAW_FIELD_ORDER = ["rule_match", "src_ip", "dst_ip", "dst_port", "direction", "flow_count", "duration_s"]


@dataclass
class Item:
    incident_id: str
    version: str  # A | B | C
    body: dict  # what the analyst sees
    correct_what: str
    acceptable_actions: list[str]


def versions_for(row: dict) -> dict[str, dict]:
    inc = row["incident"]
    ev = inc["evidence"]
    fields = {k: ev[k] for k in RAW_FIELD_ORDER if k in ev}
    fields.update({k: v for k, v in ev.items() if k not in fields})
    fields.setdefault("rule_match", "ANOMALY_SCORE")
    out = {"A": {"kind": "raw", "fields": fields | {"first_seen": inc["ts_start"], "last_seen": inc["ts_end"]}}}
    if row.get("template"):
        t = row["template"]
        out["B"] = {"kind": "narrative", "summary": t["summary"], "evidence": t["technical_evidence"]}
    n = row.get("narrative")
    if n and row.get("validation_passed") and row.get("narrative_source") in ("llm", "cache"):
        out["C"] = {"kind": "narrative", "summary": n["summary"], "evidence": n["technical_evidence"],
                    "note": n.get("confidence_note", "")}
    return out


def acceptable_actions(row: dict, allowed: list[str] | None) -> list[str]:
    inc = row["incident"]
    if inc["severity"] == "informational":
        return ["no_action"]
    return [a for a in (allowed or list(INTENT_LABELS)) if a != "no_action"]


def what_options(rows: list[dict]) -> list[str]:
    return sorted({r["incident"]["attack_type"] for r in rows} | {NO_ATTACK})


def assign(analyst: str, rows: list[dict], allowed_by_type: dict[str, list[str]]) -> list[Item]:
    items = []
    for row in rows:
        vs = versions_for(row)
        keys = sorted(vs)
        h = int(hashlib.sha256(f"{analyst}|{row['incident']['incident_id']}".encode()).hexdigest(), 16)
        v = keys[h % len(keys)]
        inc = row["incident"]
        items.append(Item(inc["incident_id"], v, vs[v], inc["attack_type"],
                          acceptable_actions(row, allowed_by_type.get(inc["attack_type"]))))
    random.Random(analyst).shuffle(items)
    return items


def report(responses: list[dict]) -> dict:
    by_v: dict[str, list[dict]] = {}
    for r in responses:
        by_v.setdefault(r["version"], []).append(r)

    def summary(rs: list[dict]) -> dict:
        return {
            "n": len(rs),
            "analysts": len({r["analyst"] for r in rs}),
            "accuracy_what": round(statistics.fmean(r["correct_what"] for r in rs), 3),
            "accuracy_action": round(statistics.fmean(r["correct_action"] for r in rs), 3),
            "median_seconds_what": round(statistics.median(r["seconds_what"] for r in rs), 1),
            "median_seconds_action": round(statistics.median(r["seconds_action"] for r in rs), 1),
            "mean_actionability": round(statistics.fmean(r["actionability"] for r in rs), 2),
            "mean_confidence": round(statistics.fmean(r["confidence"] for r in rs), 2),
        }

    out: dict = {"versions": {v: summary(rs) for v, rs in sorted(by_v.items())}}
    deltas = {}
    for a, b in (("A", "B"), ("B", "C"), ("A", "C")):
        if a in out["versions"] and b in out["versions"]:
            va, vb = out["versions"][a], out["versions"][b]
            deltas[f"{b}-{a}"] = {k: round(vb[k] - va[k], 3) for k in va if k not in ("n", "analysts")}
    out["deltas"] = deltas
    out["warning"] = ("fewer than 8 analysts: treat as indicative" if
                      len({r["analyst"] for r in responses}) < 8 else "")
    return out


def to_markdown(r: dict) -> str:
    if not r["versions"]:
        return "No study responses yet."
    names = {"A": "raw alert", "B": "template", "C": "LLM narrative"}
    lines = ["| Version | n | Analysts | What: accuracy / median s | Action: accuracy / median s "
             "| Actionability | Confidence |", "|---|---|---|---|---|---|---|"]
    for v, m in r["versions"].items():
        lines.append(f"| {v} {names[v]} | {m['n']} | {m['analysts']} | {m['accuracy_what']:.0%} / "
                     f"{m['median_seconds_what']} | {m['accuracy_action']:.0%} / {m['median_seconds_action']} "
                     f"| {m['mean_actionability']} | {m['mean_confidence']} |")
    for k, d in r["deltas"].items():
        lines.append(f"\n**{k}:** what-accuracy {d['accuracy_what']:+.0%}, what-time {d['median_seconds_what']:+} s, "
                     f"action-accuracy {d['accuracy_action']:+.0%}, action-time {d['median_seconds_action']:+} s, "
                     f"actionability {d['mean_actionability']:+}")
    if r["warning"]:
        lines.append(f"\n_{r['warning']}_")
    return "\n".join(lines)
