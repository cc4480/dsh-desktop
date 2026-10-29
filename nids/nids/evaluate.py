"""Evaluation harness (blueprint §6.1, §6.3, §6.5).

Scores a capture against its ground truth with three engine configurations, so the
"does the ML earn its complexity?" question is answered with a table:

    rules       rule signatures only (with the behavioural profile, if one is trained)
    anomaly     Isolation Forest + autoencoder only (frozen-ECDF thresholds)
    supervised  the CIC-IDS2017 classifier through the Zeek adapter only
    ensemble    everything available, correlated (what the pipeline ships)

Two levels:
  incident level  episodes detected, false incidents, false incidents per hour,
                  ATT&CK classification, severity expectation, detection latency
  flow level      precision / recall / F1 per engine (PR-AUC for the scored engine),
                  and per-episode flow recall

Detection latency is measured from the episode's first packet to the first moment the
detection logic could fire (rule window close, or the k-th anomalous flow's end). It
excludes Zeek's own delay before it logs a connection (connection end or inactivity
timeout); measure that separately on a live sensor.
"""
from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import numpy as np
from sklearn.metrics import average_precision_score

from nids import anomaly, pipeline, rules, supervised
from nids.assets import AssetRegistry
from nids.features import flow_matrix
from nids.models import Flow, Incident
from nids.sensing import zeek

CONFIGS = {"rules": ("rule",), "anomaly": ("anomaly",), "supervised": ("supervised",),
           "ensemble": ("rule", "anomaly", "supervised")}
INCIDENT_SLACK = 60.0  # seconds either side of an episode an incident may start/end in
FLOW_SLACK = 2.0


@dataclass
class Episode:
    attack: str
    src: str
    dst: str | None
    start: float
    end: float
    expect: str = "detect"  # detect | informational | ignore
    attack_id: str | None = None

    def covers_flow(self, f: Flow, slack: float = FLOW_SLACK) -> bool:
        return (f.src_ip == self.src and (self.dst is None or f.dst_ip == self.dst)
                and self.start - slack <= f.ts <= self.end + slack)

    def matches(self, i: Incident, slack: float = INCIDENT_SLACK) -> bool:
        return (i.src_ip == self.src and (self.dst is None or i.dst_ip in (None, self.dst))
                and i.ts_start <= self.end + slack and i.ts_end >= self.start - slack)


def load_truth(path: str | Path) -> list[Episode]:
    """JSON array, or JSON lines (what the Docker lab's attack scripts append)."""
    text = Path(path).read_text(encoding="utf-8").strip()
    rows = json.loads(text) if text.startswith("[") else [json.loads(line) for line in text.splitlines() if line.strip()]
    return [Episode(**{k: r.get(k) for k in Episode.__dataclass_fields__ if k in r}) for r in rows]


def _prf(y: np.ndarray, pred: np.ndarray) -> dict:
    tp = int((y & pred).sum())
    fp = int((~y & pred).sum())
    fn = int((y & ~pred).sum())
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    return {"precision": round(p, 4), "recall": round(r, 4),
            "f1": round(2 * p * r / (p + r), 4) if p + r else 0.0, "tp": tp, "fp": fp, "fn": fn}


def _percentile(xs: list[float], q: float) -> float | None:
    return round(float(np.percentile(xs, q)), 1) if xs else None


def incident_level(incidents: Sequence[Incident], truth: Sequence[Episode], hours: float) -> dict:
    scored = [e for e in truth if e.expect != "ignore"]
    episodes, latencies, matched_ids = [], [], set()
    for e in scored:
        hits = [i for i in incidents if e.matches(i)]
        matched_ids.update(i.incident_id for i in hits)
        latency = round(min(i.detected_at for i in hits) - e.start, 1) if hits else None
        if latency is not None:
            latencies.append(latency)
        sev_ok = (all(i.severity == "informational" for i in hits) if e.expect == "informational"
                  else all(i.severity != "informational" for i in hits))
        episodes.append({
            "attack": e.attack,
            "src": e.src,
            "dst": e.dst,
            "expect": e.expect,
            "detected": bool(hits),
            "incidents": len(hits),
            "severity": sorted({i.severity for i in hits}),
            "severity_as_expected": bool(hits) and sev_ok,
            "attack_id_expected": e.attack_id,
            "attack_ids": sorted({i.attack_id for i in hits if i.attack_id}),
            "classified_correctly": (e.attack_id in {i.attack_id for i in hits}) if e.attack_id and hits else None,
            "latency_s": latency,
        })
    ignored = {i.incident_id for e in truth if e.expect == "ignore" for i in incidents if e.matches(i)}
    false_incidents = [i for i in incidents if i.incident_id not in matched_ids | ignored]
    detected = sum(ep["detected"] for ep in episodes)
    true_incidents = len(incidents) - len(false_incidents)
    return {
        "incidents": len(incidents),
        "episodes": len(episodes),
        "episodes_detected": detected,
        "episode_recall": round(detected / len(episodes), 4) if episodes else None,
        "incident_precision": round(true_incidents / len(incidents), 4) if incidents else None,
        "false_incidents": len(false_incidents),
        "false_incidents_per_hour": round(len(false_incidents) / hours, 2) if hours else None,
        "false_incident_examples": [
            {"src": i.src_ip, "dst": i.dst_ip, "attack_type": i.attack_type, "severity": i.severity}
            for i in false_incidents[:10]
        ],
        "fragmented_episodes": sum(ep["incidents"] > 1 for ep in episodes),
        "classified_correctly": sum(bool(ep["classified_correctly"]) for ep in episodes),
        "classifiable": sum(ep["classified_correctly"] is not None for ep in episodes),
        "severity_as_expected": sum(ep["severity_as_expected"] for ep in episodes),
        "latency_s": {"p50": _percentile(latencies, 50), "p95": _percentile(latencies, 95),
                      "p99": _percentile(latencies, 99), "max": max(latencies) if latencies else None,
                      "n": len(latencies)},
        "per_episode": episodes,
    }


def flow_level(flows: Sequence[Flow], truth: Sequence[Episode], flagged: dict[str, set[str]],
               scores: dict[str, np.ndarray]) -> dict:
    ignore = np.array([any(e.covers_flow(f) for e in truth if e.expect == "ignore") for f in flows])
    label = np.array([any(e.covers_flow(f) for e in truth if e.expect != "ignore") for f in flows])
    keep = ~ignore | label
    y = label[keep]
    uids = [f.uid for f, k in zip(flows, keep) if k]
    out: dict = {"flows": int(keep.sum()), "attack_flows": int(y.sum()), "benign_flows": int((~y).sum())}

    engines: dict[str, dict] = {}
    for name, flagged_uids in flagged.items():
        pred = np.array([u in flagged_uids for u in uids])
        engines[name] = _prf(y, pred)
        per_ep = {}
        for e in truth:
            if e.expect == "ignore":
                continue
            m = np.array([e.covers_flow(f) for f, k in zip(flows, keep) if k])
            per_ep[e.attack] = round(float(pred[m].mean()), 4) if m.any() else None
        engines[name]["per_episode_recall"] = per_ep
    thresholds = {"anomaly": anomaly.ALERT_THRESHOLD, "supervised": supervised.ALERT_PROBABILITY}
    for name, sc in scores.items():
        if name not in engines:
            continue
        s = sc[keep]
        engines[name]["pr_auc"] = round(float(average_precision_score(y, s)), 4) if y.any() else None
        engines[name]["benign_flows_over_threshold"] = int(((s > thresholds[name]) & ~y).sum())
    out["engines"] = engines
    return out


def evaluate(logdir: Path, truth_path: Path | None = None, cfg: pipeline.Config | None = None) -> dict:
    cfg = cfg or pipeline.Config()
    truth = load_truth(truth_path or _find_truth(logdir))
    bundle = zeek.read_dir(logdir)
    flows = bundle.flows
    rule_set = rules.load_rules(cfg.rules_path)
    assets = AssetRegistry.load(cfg.assets_path)
    models = pipeline.Models.load(cfg)
    hours = max((flows[-1].ts - flows[0].ts) / 3600, 1 / 3600) if flows else 0.0

    report: dict = {
        "capture": {"logdir": str(logdir), "flows": len(flows), "dns_queries": len(bundle.dns),
                    "http_requests": len(bundle.http), "tls_sessions": len(bundle.tls),
                    "hours": round(hours, 3), "episodes": len(truth)},
        "engines": models.status(),
        "inactive_rules": rules.inactive(rule_set, models.profile),
        "anomaly_model": pipeline.model_meta(cfg.model_path) if models.anomaly else None,
        "incident_level": {},
        "flow_level": None,
        "supervised": models.supervised.report if models.supervised else
        {"status": "not evaluated", "reason": "no supervised model (python ml/train_supervised.py --data <CIC dir>)"},
    }
    available = {"anomaly": models.anomaly is not None, "supervised": models.supervised is not None}
    flagged: dict[str, set[str]] = {}
    for name, engines in CONFIGS.items():
        if name != "ensemble" and any(e in available and not available[e] for e in engines):
            report["incident_level"][name] = {"status": f"skipped: no {engines[0]} model"}
            continue
        det = pipeline.detect(bundle, rule_set, assets, models, engines=engines)
        report["incident_level"][name] = incident_level(det.incidents, truth, hours)
        if name == "ensemble":
            flagged["ensemble"] = set().union(*det.incident_uids.values()) if det.incident_uids else set()
        elif name == "rules":
            flagged["rules"] = {u for a in det.alerts if a.engine == "rule" for u in a.flow_uids}

    scores: dict[str, np.ndarray] = {}
    if models.anomaly is not None:
        scores["anomaly"] = models.anomaly.score(flow_matrix(flows), anomaly.hours_of(flows))
        flagged["anomaly"] = {f.uid for f, s in zip(flows, scores["anomaly"]) if s > anomaly.ALERT_THRESHOLD}
    if models.supervised is not None:
        scores["supervised"] = models.supervised.predict(flows)
        flagged["supervised"] = {f.uid for f, p in zip(flows, scores["supervised"])
                                 if p >= supervised.ALERT_PROBABILITY}
    report["flow_level"] = flow_level(flows, truth, flagged, scores)
    return report


def _find_truth(logdir: Path) -> Path:
    for name in ("ground_truth.json", "ground_truth.jsonl"):
        if (logdir / name).exists():
            return logdir / name
    raise FileNotFoundError(f"no ground_truth.json(l) in {logdir}; pass --truth")


def _fmt(v) -> str:
    if v is None:
        return "—"
    if isinstance(v, float):
        return f"{v:.3f}".rstrip("0").rstrip(".") if v != int(v) else str(int(v))
    return str(v)


def to_markdown(r: dict) -> str:
    c = r["capture"]
    lines = [
        f"# Evaluation — `{Path(c['logdir']).name}`",
        "",
        f"{c['flows']:,} flows over {c['hours'] * 60:.1f} min, {c['episodes']} ground-truth episodes.",
        "",
        "## Incident level",
        "",
        "| Config | Incidents | Episodes detected | Incident precision | False incidents | FP / hour "
        "| ATT&CK correct | Latency p50 / p95 / max (s) |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for name, m in r["incident_level"].items():
        if "status" in m:
            lines.append(f"| {name} | {m['status']} | | | | | | |")
            continue
        lat = m["latency_s"]
        lines.append(
            f"| {name} | {m['incidents']} | {m['episodes_detected']}/{m['episodes']} | {_fmt(m['incident_precision'])} "
            f"| {m['false_incidents']} | {_fmt(m['false_incidents_per_hour'])} "
            f"| {m['classified_correctly']}/{m['classifiable']} "
            f"| {_fmt(lat['p50'])} / {_fmt(lat['p95'])} / {_fmt(lat['max'])} |")
    if "status" in r["supervised"]:
        lines.append(f"| supervised model | {r['supervised']['status']}: {r['supervised']['reason']} | | | | | | |")
    if r.get("inactive_rules"):
        lines += ["", f"Rules that could not fire (no profile): {', '.join(r['inactive_rules'])}."]

    ens = r["incident_level"].get("ensemble", {})
    if "per_episode" in ens:
        lines += ["", "### Ensemble, per episode", "",
                  "| Episode | Expect | Detected | Incidents | Severity | ATT&CK | Latency (s) |",
                  "|---|---|---|---|---|---|---|"]
        for ep in ens["per_episode"]:
            lines.append(
                f"| {ep['attack']} | {ep['expect']} | {'yes' if ep['detected'] else '**no**'} | {ep['incidents']} "
                f"| {', '.join(ep['severity']) or '—'}{'' if ep['severity_as_expected'] or not ep['detected'] else ' ⚠'} "
                f"| {', '.join(ep['attack_ids']) or '—'} | {_fmt(ep['latency_s'])} |")

    fl = r["flow_level"]
    if fl:
        lines += ["", "## Flow level", "",
                  f"{fl['attack_flows']:,} attack flows, {fl['benign_flows']:,} benign flows "
                  "(flood flows dominate the attack count, so read the per-episode columns).", "",
                  "| Engine | Precision | Recall | F1 | PR-AUC | " +
                  " | ".join(next(iter(fl["engines"].values()))["per_episode_recall"]) + " |",
                  "|---|---|---|---|---|" + "---|" * len(next(iter(fl["engines"].values()))["per_episode_recall"])]
        for name, m in fl["engines"].items():
            lines.append(f"| {name} | {_fmt(m['precision'])} | {_fmt(m['recall'])} | {_fmt(m['f1'])} "
                         f"| {_fmt(m.get('pr_auc'))} | " +
                         " | ".join(_fmt(v) for v in m["per_episode_recall"].values()) + " |")
    lines += ["", "Latency = first packet of the episode to the first moment the detection logic could fire. "
                  "It excludes Zeek's own connection-logging delay."]
    return "\n".join(lines) + "\n"
