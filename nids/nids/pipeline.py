"""End-to-end pipeline: Zeek logs -> rules + anomaly + supervised -> incidents ->
narrative -> policy render -> store. The dashboard only ever reads the store.

`run` processes a log directory once (batch); nids/watch.py calls the same `detect` and
`respond` on a sliding buffer for live operation.
"""
from __future__ import annotations

import json
import math
import time
from collections import defaultdict
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

import numpy as np

from nids import anomaly, forensics, rules, supervised
from nids.assets import AssetRegistry
from nids.correlation import Correlator
from nids.explain.llm import Explainer
from nids.features import flow_matrix
from nids.models import Alert, Flow, Incident
from nids.profile import Profile
from nids.response.policy import PolicyEngine
from nids.sensing import zeek
from nids.sensing.zeek import LogBundle
from nids.storage import Store

ROOT = Path(__file__).resolve().parents[1]
ANOMALY_DEFAULT_INTENT = "enable_verbose_logging"
ANOMALY_ALLOWED = ["enable_verbose_logging", "review_account_activity", "isolate_host", "no_action"]
ENGINES = ("rule", "anomaly", "supervised")
TIMELINE_POINTS = 120
SERIES_POINTS = 300


@dataclass
class Config:
    rules_path: Path = ROOT / "config" / "rules.yaml"
    assets_path: Path = ROOT / "config" / "assets.yaml"
    policy_path: Path = ROOT / "config" / "policy.yaml"
    model_path: Path | None = ROOT / "models" / "anomaly.joblib"
    profile_path: Path | None = ROOT / "models" / "profile.json"
    supervised_path: Path | None = ROOT / "models" / "supervised.joblib"
    db_path: Path = ROOT / "data" / "nids.db"
    backend: str = "none"
    llm_model: str = ""  # DeepSeek: --model or DEEPSEEK_MODEL


@dataclass
class Models:
    anomaly: anomaly.AnomalyModel | None = None
    supervised: supervised.SupervisedModel | None = None
    profile: Profile | None = None
    errors: dict[str, str] = field(default_factory=dict)

    @staticmethod
    def load(cfg: Config) -> "Models":
        m = Models()
        for name, path, loader in (("anomaly", cfg.model_path, anomaly.AnomalyModel.load),
                                   ("supervised", cfg.supervised_path, supervised.SupervisedModel.load),
                                   ("profile", cfg.profile_path, Profile.load)):
            if path and Path(path).exists():
                try:
                    setattr(m, name, loader(path))
                except (ValueError, KeyError, OSError) as e:  # stale or incompatible artefact
                    m.errors[name] = str(e)[:200]
        return m

    def status(self) -> dict[str, str]:
        out = {}
        for name in ("anomaly", "supervised", "profile"):
            out[name] = "loaded" if getattr(self, name) is not None else self.errors.get(name, "not trained")
        return out


@dataclass
class Detection:
    alerts: list[Alert]
    incidents: list[Incident]
    watchlist: int
    rule_alerts: int
    timing_ms: dict[str, float] = field(default_factory=dict)
    incident_uids: dict[str, set[str]] = field(default_factory=dict)
    inactive_rules: list[str] = field(default_factory=list)

    def count(self, engine: str) -> int:
        return sum(a.engine == engine for a in self.alerts)


def detect(
    bundle: LogBundle,
    rule_set: Sequence[rules.Rule],
    assets: AssetRegistry,
    models: Models,
    engines: Sequence[str] = ENGINES,
    recent_sources: Callable[[str, float], bool] | None = None,
    point_alerts: Sequence[Alert] | None = None,
) -> Detection:
    """Planes 3 and 4 only: no narrative, no storage. Shared by run, watch and evaluate.

    point_alerts: anomaly/supervised alerts already computed per flow (watch mode scores
    each flow once as it arrives instead of rescoring the whole buffer every pass).
    """
    t0 = time.perf_counter()
    alerts = rules.evaluate(rule_set, bundle, profile=models.profile) if "rule" in engines else []
    n_rule = len(alerts)
    if point_alerts is not None:
        alerts += [a for a in point_alerts if a.engine in engines]
    else:
        if models.anomaly is not None and "anomaly" in engines:
            alerts += anomaly.detect(models.anomaly, bundle.flows)
        if models.supervised is not None and "supervised" in engines:
            alerts += supervised.detect(models.supervised, bundle.flows)
    t1 = time.perf_counter()
    known = (lambda src, dst: not models.profile.is_new_dst(src, dst)) if models.profile else None
    correlator = Correlator(rule_set, assets, recent_sources, known_pair=known)
    incidents = correlator.correlate(alerts)
    t2 = time.perf_counter()
    return Detection(alerts, incidents, correlator.watchlist, n_rule,
                     {"detect": round((t1 - t0) * 1000, 1), "correlate": round((t2 - t1) * 1000, 1)},
                     correlator.incident_uids,
                     rules.inactive(rule_set, models.profile) if "rule" in engines else [])


def attach_context(det: Detection, flows: Sequence[Flow], pad: float = 30.0) -> None:
    """Per-incident packets/s timeline (dashboard chart) and forensic pivot data."""
    by_src: dict[str, list[Flow]] = defaultdict(list)
    for f in flows:
        by_src[f.src_ip].append(f)
    for inc in det.incidents:
        lo, hi = inc.ts_start - pad, inc.ts_end + pad
        width = max(1.0, math.ceil((hi - lo) / TIMELINE_POINTS))
        bins = np.zeros(int((hi - lo) // width) + 1)
        mine = [f for f in by_src.get(inc.src_ip, []) if lo <= f.ts <= hi
                and (inc.dst_ip is None or f.dst_ip == inc.dst_ip)]
        for f in mine:
            bins[int((f.ts - lo) // width)] += f.orig_pkts + f.resp_pkts
        inc.timeline = [[round(lo + i * width, 3), round(float(v) / width, 1)] for i, v in enumerate(bins)]
        inc.forensics = forensics.build(inc, mine, det.incident_uids.get(inc.incident_id, set()))


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


class Responder:
    """Plane 5 + 6 + storage for a batch of incidents. Reused by watch mode."""

    def __init__(self, cfg: Config, store: Store, assets: AssetRegistry, rule_set: Sequence[rules.Rule],
                 explainer: Explainer | None = None):
        self.store = store
        self.by_attack = {r.attack_type: r for r in rule_set}
        self.explainer = explainer or Explainer(
            assets, cfg.backend, cfg.llm_model,
            cache_get=store.cache_get, cache_put=store.cache_put, egress_log=store.log_egress,
        )
        self.policy = PolicyEngine.from_config(cfg.policy_path, assets)
        self.latencies: list[float] = []
        self.passed = 0

    def intents(self, inc: Incident) -> tuple[list[str], str]:
        rule = self.by_attack.get(inc.attack_type)
        allowed = rule.allowed_intents if rule else ANOMALY_ALLOWED
        default = rule.default_intent if rule else ANOMALY_DEFAULT_INTENT
        if inc.severity == "informational":  # allowlisted source: recommend nothing
            return ["no_action"], "no_action"
        return allowed, default

    def respond(self, inc: Incident, explain: bool = True) -> None:
        self.store.save_incident(inc)
        if not explain:
            return
        allowed, default = self.intents(inc)
        res = self.explainer.explain(inc, allowed, default)
        self.passed += res.validation_passed
        if res.latency_ms is not None:
            self.latencies.append(res.latency_ms)
        self.store.save_narrative(inc.incident_id, res.narrative.model_dump(), res.validation_passed, res.source,
                                  res.reasons, template=res.template.model_dump(), latency_ms=res.latency_ms)
        rendered = self.policy.render(res.narrative.remediation_intent, inc)
        self.store.save_command(inc.incident_id, rendered.intent, rendered.command, rendered.rollback,
                                rendered.dry_run, rendered.refused_reason)

    def latency_stats(self) -> dict:
        if not self.latencies:
            return {}
        return {"n": len(self.latencies), "p50": round(float(np.percentile(self.latencies, 50)), 1),
                "p99": round(float(np.percentile(self.latencies, 99)), 1)}


def run_stats(bundle: LogBundle, det: Detection, models: Models, cfg: Config, responder: Responder,
              timing: dict) -> dict:
    flows = bundle.flows
    span = (flows[-1].ts - flows[0].ts) if len(flows) > 1 else 0.0
    return {
        "rule_alerts": det.rule_alerts,
        "anomaly_alerts": det.count("anomaly"),
        "supervised_alerts": det.count("supervised"),
        "anomaly_watchlist": det.watchlist,
        "inactive_rules": det.inactive_rules,
        "engines": models.status(),
        "capture_seconds": round(span, 1),
        "mean_pps": round(sum(f.orig_pkts + f.resp_pkts for f in flows) / max(span, 1.0), 1),
        "records": {"conn": len(flows), "dns": len(bundle.dns), "http": len(bundle.http), "tls": len(bundle.tls),
                    "notice": len(bundle.notices)},
        "sensor": bundle.health.model_dump(),
        "narrative_validation_pass": responder.passed,
        "narrative_latency_ms": responder.latency_stats(),
        "backend": cfg.backend,
        "llm_model": responder.explainer.model if cfg.backend != "none" else "",
        "model": model_meta(cfg.model_path) if models.anomaly else {},
        "profile": models.profile.summary() if models.profile else {},
        "supervised": (models.supervised.report.get("zeek_temporal", {}).get("test", {})
                       if models.supervised else {}),
        "psi": psi_split(models.anomaly, flows, det.incident_uids) if models.anomaly else {},
        "series": run_series(flows, det.alerts),
        "timing_ms": timing,
    }


def run(logdir: Path, cfg: Config, explainer: Explainer | None = None) -> list[Incident]:
    t0 = time.perf_counter()
    rule_set = rules.load_rules(cfg.rules_path)
    assets = AssetRegistry.load(cfg.assets_path)
    store = Store(cfg.db_path)
    models = Models.load(cfg)

    bundle = zeek.read_dir(logdir)
    t_parse = time.perf_counter()
    det = detect(bundle, rule_set, assets, models, recent_sources=store.recent_source)
    attach_context(det, bundle.flows)
    t_corr = time.perf_counter()

    responder = Responder(cfg, store, assets, rule_set, explainer)
    for inc in det.incidents:
        responder.respond(inc)
    t_end = time.perf_counter()

    timing = {"parse": round((t_parse - t0) * 1000, 1), **det.timing_ms,
              "explain_and_render": round((t_end - t_corr) * 1000, 1)}
    store.save_run(str(Path(logdir) / "conn.log"), len(bundle.flows), len(det.alerts), len(det.incidents),
                   run_stats(bundle, det, models, cfg, responder, timing))
    return det.incidents
