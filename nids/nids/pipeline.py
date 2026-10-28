"""End-to-end batch pipeline: Zeek logs -> rules + anomaly -> incidents -> narrative ->
policy render -> store. The dashboard only ever reads the store."""
from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from nids import anomaly, rules
from nids.assets import AssetRegistry
from nids.correlation import Correlator
from nids.explain.llm import Explainer
from nids.models import Incident
from nids.response.policy import PolicyEngine
from nids.sensing import zeek
from nids.storage import Store

ROOT = Path(__file__).resolve().parents[1]
ANOMALY_DEFAULT_INTENT = "enable_verbose_logging"
ANOMALY_ALLOWED = ["enable_verbose_logging", "review_account_activity", "isolate_host", "no_action"]


@dataclass
class Config:
    rules_path: Path = ROOT / "config" / "rules.yaml"
    assets_path: Path = ROOT / "config" / "assets.yaml"
    model_path: Path | None = ROOT / "models" / "anomaly.joblib"
    db_path: Path = ROOT / "data" / "nids.db"
    backend: str = "none"
    llm_model: str = "llama3.1:8b"
    iface: str = "eth0"


def run(conn_log: Path, dns_log: Path | None, cfg: Config, explainer: Explainer | None = None) -> list[Incident]:
    t0 = time.perf_counter()
    rule_set = rules.load_rules(cfg.rules_path)
    by_attack = {r.attack_type: r for r in rule_set}
    assets = AssetRegistry.load(cfg.assets_path)
    store = Store(cfg.db_path)

    flows = zeek.read_conn(conn_log)
    dns = zeek.read_dns(dns_log) if dns_log else []
    t_parse = time.perf_counter()

    alerts = rules.evaluate(rule_set, flows, dns)
    n_rule = len(alerts)
    if cfg.model_path and Path(cfg.model_path).exists():
        alerts += anomaly.detect(anomaly.AnomalyModel.load(cfg.model_path), flows)
    t_detect = time.perf_counter()

    correlator = Correlator(rule_set, assets, store.recent_source)
    incidents = correlator.correlate(alerts)
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
        str(conn_log), len(flows), len(alerts), len(incidents),
        {
            "rule_alerts": n_rule,
            "anomaly_alerts": len(alerts) - n_rule,
            "anomaly_watchlist": correlator.watchlist,
            "capture_seconds": round(span, 1),
            "mean_pps": round(sum(f.orig_pkts + f.resp_pkts for f in flows) / max(span, 1.0), 1),
            "narrative_validation_pass": passed,
            "backend": cfg.backend,
            "timing_ms": {
                "parse": round((t_parse - t0) * 1000, 1),
                "detect": round((t_detect - t_parse) * 1000, 1),
                "correlate": round((t_corr - t_detect) * 1000, 1),
                "explain_and_render": round((t_end - t_corr) * 1000, 1),
            },
        },
    )
    return incidents
