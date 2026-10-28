"""End-to-end batch pipeline: Zeek logs -> rules + anomaly -> incidents -> narrative ->
policy render -> store. The dashboard only ever reads the store."""
from __future__ import annotations

import json
import math
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from nids import anomaly, rules
from nids.assets import AssetRegistry
from nids.correlation import Correlator
from nids.explain.llm import Explainer
from nids.features import flow_matrix
from nids.models import Alert, DnsQuery, Flow, Incident
from nids.response.policy import PolicyEngine
from nids.sensing import zeek
from nids.storage import Store

ROOT = Path(__file__).resolve().parents[1]
ANOMALY_DEFAULT_INTENT = "enable_verbose_logging"
ANOMALY_ALLOWED = ["enable_verbose_logging", "review_account_activity", "isolate_host", "no_action"]
ENGINES = ("rule", "anomaly")
TIMELINE_POINTS = 120
SERIES_POINTS = 300


@dataclass
class Config:
    rules_path: Path = ROOT / "config" / "rules.yaml"
    assets_path: Path = ROOT / "config" / "assets.yaml"
    model_path: Path | None = ROOT / "models" / "anomaly.joblib"
    db_path: Path = ROOT / "data" / "nids.db"
    backend: str = "none"
    llm_model: str = "llama3.1:8b"
    iface: str = "eth0"


@dataclass
class Detection:
    alerts: list[Alert]
    incidents: list[Incident]
    watchlist: int
    rule_alerts: int
    model: anomaly.AnomalyModel | None = None
    timing_ms: dict[str, float] = field(default_factory=dict)
    incident_uids: dict[str, set[str]] = field(default_factory=dict)


def detect(
    flows: Sequence[Flow],
    dns: Sequence[DnsQuery],
    rule_set: Sequence[rules.Rule],
    assets: AssetRegistry,
    model: anomaly.AnomalyModel | None,
    engines: Sequence[str] = ENGINES,
    recent_sources: Callable[[str, float], bool] | None = None,
) -> Detection:
    """Planes 3 and 4 only: no narrative, no storage. Shared by `run` and the evaluator."""
    t0 = time.perf_counter()
    alerts = rules.evaluate(rule_set, flows, dns) if "rule" in engines else []
    n_rule = len(alerts)
    if model is not None and "anomaly" in engines:
        alerts += anomaly.detect(model, flows)
    t1 = time.perf_counter()
    correlator = Correlator(rule_set, assets, recent_sources)
    incidents = correlator.correlate(alerts)
    t2 = time.perf_counter()
    return Detection(alerts, incidents, correlator.watchlist, n_rule, model,
                     {"detect": round((t1 - t0) * 1000, 1), "correlate": round((t2 - t1) * 1000, 1)},
                     correlator.incident_uids)


def attach_timelines(incidents: Sequence[Incident], flows: Sequence[Flow], pad: float = 30.0) -> None:
    """Packets/s of the incident's own traffic, padded either side, for the dashboard chart."""
    by_src: dict[str, list[Flow]] = defaultdict(list)
    for f in flows:
        by_src[f.src_ip].append(f)
    for inc in incidents:
        lo, hi = inc.ts_start - pad, inc.ts_end + pad
        width = max(1.0, math.ceil((hi - lo) / TIMELINE_POINTS))
        bins = np.zeros(int((hi - lo) // width) + 1)
        for f in by_src.get(inc.src_ip, []):
            if lo <= f.ts <= hi and (inc.dst_ip is None or f.dst_ip == inc.dst_ip):
                bins[int((f.ts - lo) // width)] += f.orig_pkts + f.resp_pkts
        inc.timeline = [[round(lo + i * width, 3), round(float(v) / width, 1)] for i, v in enumerate(bins)]


def run_series(flows: Sequence[Flow], alerts: Sequence[Alert]) -> dict[str, list[float]]:
    """Whole-capture packets/s and anomaly-alert counts, downsampled for the banner chart."""
    if not flows:
        return {"t": [], "pps": [], "anomalies": []}
    lo, hi = flows[0].ts, flows[-1].ts
    width = max(1.0, math.ceil((hi - lo + 1) / SERIES_POINTS))
    n = int((hi - lo) // width) + 1
    pps, anom = np.zeros(n), np.zeros(n)
    for f in flows:
        pps[int((f.ts - lo) // width)] += f.orig_pkts + f.resp_pkts
    for a in alerts:
        if a.engine == "anomaly" and lo <= a.ts_start <= hi:
            anom[int((a.ts_start - lo) // width)] += 1
    return {"t": [round(lo + i * width, 3) for i in range(n)],
            "pps": [round(float(v) / width, 1) for v in pps], "anomalies": [int(v) for v in anom]}


def psi_split(model: anomaly.AnomalyModel, flows: Sequence[Flow], incident_uids: dict[str, set[str]]) -> dict:
    """PSI on background traffic (flows in no incident) and on everything.

    An attack shifts the all-traffic distribution by itself (a flood is mostly half-open
    flows), which would hide genuine drift. Background PSI is the drift signal.
    """
    in_incident = set().union(*incident_uids.values()) if incident_uids else set()
    background = [f for f in flows if f.uid not in in_incident]
    return {"background": model.psi(flow_matrix(background)), "all": model.psi(flow_matrix(flows)),
            "background_flows": len(background)}


def model_meta(model_path: Path | None) -> dict:
    if not model_path:
        return {}
    meta = Path(model_path).with_suffix(".json")
    return json.loads(meta.read_text()) if meta.exists() else {}


def run(conn_log: Path, dns_log: Path | None, cfg: Config, explainer: Explainer | None = None) -> list[Incident]:
    t0 = time.perf_counter()
    rule_set = rules.load_rules(cfg.rules_path)
    by_attack = {r.attack_type: r for r in rule_set}
    assets = AssetRegistry.load(cfg.assets_path)
    store = Store(cfg.db_path)

    flows = zeek.read_conn(conn_log)
    dns = zeek.read_dns(dns_log) if dns_log else []
    t_parse = time.perf_counter()

    model = None
    if cfg.model_path and Path(cfg.model_path).exists():
        model = anomaly.AnomalyModel.load(cfg.model_path)
    det = detect(flows, dns, rule_set, assets, model, recent_sources=store.recent_source)
    incidents = det.incidents
    attach_timelines(incidents, flows)
    t_corr = time.perf_counter()

    explainer = explainer or Explainer(
        assets, cfg.backend, cfg.llm_model,
        cache_get=store.cache_get, cache_put=store.cache_put, egress_log=store.log_egress,
    )
    policy = PolicyEngine(assets, iface=cfg.iface)
    passed = 0
    for inc in incidents:
        rule = by_attack.get(inc.attack_type)
        allowed = rule.allowed_intents if rule else ANOMALY_ALLOWED
        default = rule.default_intent if rule else ANOMALY_DEFAULT_INTENT
        if inc.severity == "informational":  # allowlisted source: recommend nothing
            allowed, default = ["no_action"], "no_action"
        store.save_incident(inc)
        res = explainer.explain(inc, allowed, default)
        passed += res.validation_passed
        store.save_narrative(inc.incident_id, res.narrative.model_dump(), res.validation_passed, res.source, res.reasons)
        rendered = policy.render(res.narrative.remediation_intent, inc)
        store.save_command(inc.incident_id, rendered.intent, rendered.command, rendered.rollback,
                           rendered.dry_run, rendered.refused_reason)
    t_end = time.perf_counter()

    span = (flows[-1].ts - flows[0].ts) if len(flows) > 1 else 0.0
    store.save_run(
        str(conn_log), len(flows), len(det.alerts), len(incidents),
        {
            "rule_alerts": det.rule_alerts,
            "anomaly_alerts": len(det.alerts) - det.rule_alerts,
            "anomaly_watchlist": det.watchlist,
            "capture_seconds": round(span, 1),
            "mean_pps": round(sum(f.orig_pkts + f.resp_pkts for f in flows) / max(span, 1.0), 1),
            "narrative_validation_pass": passed,
            "backend": cfg.backend,
            "model": model_meta(cfg.model_path) if model else {},
            "psi": psi_split(model, flows, det.incident_uids) if model else {},
            "series": run_series(flows, det.alerts),
            "timing_ms": {
                "parse": round((t_parse - t0) * 1000, 1),
                **det.timing_ms,
                "explain_and_render": round((t_end - t_corr) * 1000, 1),
            },
        },
    )
    return incidents
