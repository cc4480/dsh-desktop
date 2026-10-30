"""Plane 4: correlation, incident formation and deterministic severity.

Thousands of per-window or per-flow alerts collapse into one incident per attack episode,
keyed by (src_ip, dst_ip, attack_type). Anomaly-engine alerts that overlap an open rule
incident for the same source enrich it instead of opening a second incident.
"""
from __future__ import annotations

import hashlib
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from nids.assets import AssetRegistry
from nids.models import SEVERITY_ORDER, Alert, Incident
from nids.rules import Rule

ANOMALY_WINDOW = 120.0
# Engines that score single flows. Their alerts enrich a rule incident they overlap, or
# group into their own incident once enough of them agree on one pair.
POINT_ENGINES = ("anomaly", "supervised")
DEFAULT_WINDOW = 300.0
# A single flow above the 0.99 percentile is, by construction, a 1-in-100 benign event.
# Standalone anomaly incidents therefore need several anomalous flows on the same pair;
# lone ones are counted as watchlist only.
ANOMALY_MIN_FLOWS = 3
# ...but when the baseline profile already knows the (src, dst) relationship, rare-but-
# legitimate traffic (an admin's long SSH session) must recur much more before it becomes
# an incident on statistics alone. A new relationship needs only ANOMALY_MIN_FLOWS.
ANOMALY_MIN_FLOWS_KNOWN_PAIR = 10
CAMPAIGN_GAP = 3600.0
INT_FEATURES = {"packets_per_second", "bytes_out", "bytes_in", "query_count", "distinct_dst_ips",
                "distinct_dst_ports", "flow_count", "request_count", "distinct_uri_count", "session_count",
                "notice_count", "mean_bytes_out"}


def severity_for(
    confidence: float,
    criticality: int,
    direction: str,
    *,
    known_scanner: bool = False,
    internet_facing_prod: bool = False,
    repeat_offender: bool = False,
) -> tuple[str, list[str]]:
    """The blueprint §3.5 table, plus its modifiers. Returns (severity, reasons)."""
    reasons: list[str] = []
    if known_scanner:
        return "informational", ["source is in the known-scanner allowlist"]

    if confidence >= 0.90:
        if criticality >= 4:
            sev, why = "critical", f"confidence {confidence:.2f} >= 0.90 and asset criticality {criticality} >= 4"
        elif direction == "internal":
            sev, why = "critical", f"confidence {confidence:.2f} >= 0.90 and internal-to-internal (lateral movement)"
        else:
            sev, why = "high", f"confidence {confidence:.2f} >= 0.90 and asset criticality {criticality}"
    elif confidence >= 0.70:
        sev = "high" if criticality >= 4 else "medium"
        why = f"confidence {confidence:.2f} in [0.70, 0.90) and asset criticality {criticality}"
    else:
        sev, why = "low", f"confidence {confidence:.2f} < 0.70 (watchlist)"
    reasons.append(why)

    bumps = []
    if internet_facing_prod:
        bumps.append("target is internet-facing production")
    if repeat_offender:
        bumps.append("same source produced an incident in the last 24h")
    for b in bumps:
        nxt = min(SEVERITY_ORDER.index(sev) + 1, len(SEVERITY_ORDER) - 1)
        if SEVERITY_ORDER[nxt] != sev:
            reasons.append(f"+1 tier: {b}")
        sev = SEVERITY_ORDER[nxt]
    return sev, reasons


def link_campaigns(incidents: Sequence[Incident], gap: float = CAMPAIGN_GAP) -> None:
    """Chain incidents from the same source that follow each other within `gap` seconds.

    A chain spanning at least two attack types (scan -> brute force, beacon -> exfil) is a
    multi-stage campaign and gets one campaign_id. Severity is not changed here: the
    repeat-offender modifier in severity_for already covers recurrence.
    """
    by_src: dict[str, list[Incident]] = {}
    for inc in sorted(incidents, key=lambda i: i.ts_start):
        by_src.setdefault(inc.src_ip, []).append(inc)
    for src, items in by_src.items():
        chain: list[Incident] = []
        nxt: Incident | None
        for nxt in [*items, None]:
            if nxt is not None and (not chain or nxt.ts_start - max(c.ts_end for c in chain) <= gap):
                chain.append(nxt)
                continue
            if len({c.attack_type for c in chain}) >= 2:
                cid = "CMP-" + hashlib.sha256(f"{src}|{chain[0].incident_id}".encode()).hexdigest()[:6]
                for c in chain:
                    c.campaign_id = cid
            chain = [nxt] if nxt is not None else []


def _incident_id(alert: Alert) -> str:
    day = datetime.fromtimestamp(alert.ts_start, tz=timezone.utc).strftime("%Y-%m-%d")
    digest = hashlib.sha256(
        f"{alert.src_ip}|{alert.dst_ip}|{alert.attack_type}|{alert.ts_start:.3f}".encode()
    ).hexdigest()[:6]
    return f"INC-{day}-{digest}"


class Correlator:
    def __init__(
        self,
        rules: Sequence[Rule],
        assets: AssetRegistry,
        recent_sources: Callable[[str, float], bool] | None = None,
        anomaly_min_flows: int = ANOMALY_MIN_FLOWS,
        known_pair: Callable[[str, str], bool] | None = None,
    ):
        self.windows = {r.id: r.correlation_window for r in rules}
        self.rule_features = {r.id: [c.feature for c in r.when] for r in rules}
        self.assets = assets
        self.recent_sources = recent_sources or (lambda src, ts: False)
        self.anomaly_min_flows = anomaly_min_flows
        self.known_pair = known_pair or (lambda src, dst: False)
        self.watchlist = 0  # anomalous flows that did not form or join an incident
        self.incident_uids: dict[str, set[str]] = {}  # every flow uid an incident's alerts cover

    def correlate(self, alerts: Sequence[Alert]) -> list[Incident]:
        open_: dict[tuple, dict] = {}
        done: list[dict] = []

        rule_alerts = [a for a in alerts if a.engine not in POINT_ENGINES]
        anomaly_alerts = [a for a in alerts if a.engine in POINT_ENGINES]

        for a in sorted(rule_alerts, key=lambda x: x.ts_start):
            key = (a.src_ip, a.dst_ip, a.attack_type)
            window = self.windows.get(a.rule_id or "", DEFAULT_WINDOW)
            if a.dst_ip is None:
                # A destination-less alert (e.g. a Zeek notice) joins an open incident of the
                # same type from the same source rather than opening a parallel one.
                key = next((k for k, g in open_.items() if k[0] == a.src_ip and k[2] == a.attack_type
                            and a.ts_start - g["ts_end"] <= window), key)
            cur = open_.get(key)
            if cur and a.ts_start - cur["ts_end"] <= window:
                self._merge(cur, a)
            else:
                if cur:
                    done.append(cur)
                open_[key] = self._new(a)
        rule_groups = list(open_.values()) + done

        # Anomaly alerts: enrich an overlapping rule incident for the same source, else
        # group into their own "Unclassified Anomaly" incident.
        anomaly_open: dict[tuple, dict] = {}
        anomaly_done: list[dict] = []
        for a in sorted(anomaly_alerts, key=lambda x: x.ts_start):
            host = next(
                (
                    g
                    for g in rule_groups
                    if g["src_ip"] == a.src_ip
                    and g["dst_ip"] in (None, a.dst_ip)
                    and g["ts_start"] - ANOMALY_WINDOW <= a.ts_start <= g["ts_end"] + ANOMALY_WINDOW
                ),
                None,
            )
            if host:
                self._merge(host, a, count_flows=False)
                continue
            key = (a.src_ip, a.dst_ip, a.engine)
            cur = anomaly_open.get(key)
            if cur and a.ts_start - cur["ts_end"] <= ANOMALY_WINDOW:
                self._merge(cur, a)
            else:
                if cur:
                    anomaly_done.append(cur)
                anomaly_open[key] = self._new(a)

        anomaly_groups = list(anomaly_open.values()) + anomaly_done
        kept = [g for g in anomaly_groups if len(g["alerts"]) >= self._min_flows(g)]
        self.watchlist = sum(len(g["alerts"]) for g in anomaly_groups) - sum(len(g["alerts"]) for g in kept)
        groups = rule_groups + kept
        incidents = sorted((self._finalise(g) for g in groups), key=lambda i: i.ts_start)
        link_campaigns(incidents)
        return incidents

    # ------------------------------------------------------------------ helpers
    @staticmethod
    def _new(a: Alert) -> dict:
        return {
            "id": _incident_id(a),
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "attack_type": a.attack_type,
            "attack_id": a.attack_id,
            "ts_start": a.ts_start,
            "ts_end": a.ts_end,
            "alerts": [a],
            "uids": set(a.flow_uids),
            "extra_flows": 0 if a.flow_uids else a.flow_count,
        }

    @staticmethod
    def _merge(g: dict, a: Alert, count_flows: bool = True) -> None:
        g["alerts"].append(a)
        g["ts_start"] = min(g["ts_start"], a.ts_start)
        g["ts_end"] = max(g["ts_end"], a.ts_end)
        if count_flows:
            if a.flow_uids:
                g["uids"].update(a.flow_uids)
            else:
                g["extra_flows"] += a.flow_count

    def _min_flows(self, g: dict) -> int:
        if g["dst_ip"] and self.known_pair(g["src_ip"], g["dst_ip"]):
            return ANOMALY_MIN_FLOWS_KNOWN_PAIR
        return self.anomaly_min_flows

    def _detected_at(self, alerts: list[Alert]) -> float:
        """Earliest moment the incident could have been raised."""
        candidates = [a.emitted_at for a in alerts if a.engine not in POINT_ENGINES]
        for engine in POINT_ENGINES:  # a per-flow engine alone needs its k-th flow
            times = sorted(a.emitted_at for a in alerts if a.engine == engine)
            if len(times) >= self.anomaly_min_flows:
                candidates.append(times[self.anomaly_min_flows - 1])
        if candidates:
            return min(candidates)
        return max(a.emitted_at for a in alerts)

    def _finalise(self, g: dict) -> Incident:
        alerts: list[Alert] = g["alerts"]
        g["flow_count"] = len(g["uids"]) + g["extra_flows"]
        self.incident_uids[g["id"]] = set().union(*(a.flow_uids for a in alerts))
        primary = [a for a in alerts if a.engine not in POINT_ENGINES] or alerts
        confidence = max(a.confidence for a in primary)
        rule_ids = sorted({a.rule_id for a in alerts if a.rule_id})
        engines = sorted({a.engine for a in alerts})
        ports = Counter(p for a in primary for p in a.dst_ports)
        anomaly_scores = [float(a.features["anomaly_score"]) for a in alerts if "anomaly_score" in a.features]

        def peak(feature: str) -> float:
            vals = [float(a.features[feature]) for a in primary if feature in a.features]
            return max(vals) if vals else 0.0

        direction = self.assets.direction(g["src_ip"], g["dst_ip"])
        # For outbound behaviours (beaconing, tunnelling) the asset at risk is the source.
        at_risk = g["src_ip"] if direction == "outbound" or g["dst_ip"] is None else g["dst_ip"]
        asset = self.assets.get(at_risk)
        crit = asset.criticality if asset else self.assets.default_criticality

        severity, reasons = severity_for(
            confidence,
            crit,
            direction,
            known_scanner=g["src_ip"] in self.assets.known_scanners,
            internet_facing_prod=bool(asset and asset.internet_facing and asset.environment == "production"
                                      and direction in ("inbound", "internal")),
            repeat_offender=self.recent_sources(g["src_ip"], g["ts_start"]),
        )

        evidence: dict[str, float | int | str | bool] = {
            "src_ip": g["src_ip"],
            "dst_ip": g["dst_ip"] or "multiple",
            "direction": direction,
            "flow_count": int(g["flow_count"]),
            "duration_s": round(g["ts_end"] - g["ts_start"], 1),
            "detection_engines": "+".join(engines),
        }
        n_ports = int(max(peak("distinct_dst_ports"), len(ports)))
        if ports and n_ports == 1:
            evidence["dst_port"] = ports.most_common(1)[0][0]
        elif ports:
            evidence["distinct_dst_ports"] = n_ports
        if rule_ids:
            evidence["rule_match"] = "+".join(rule_ids)
        # Only the features the matched rules actually tested, plus volume context.
        feats = [f for rid in rule_ids for f in self.rule_features.get(rid, [])]
        feats += [f for f in ("packets_per_second", "bytes_out") if any(f in a.features for a in primary)]
        for feat in dict.fromkeys(feats):
            if feat in evidence or feat == "flow_count" or not any(feat in a.features for a in primary):
                continue
            if feat == "bytes_out" and all(a.engine in POINT_ENGINES for a in primary):
                v = sum(float(a.features.get("bytes_out", 0)) for a in primary)
            else:
                v = peak(feat)
            evidence[feat] = int(v) if feat in INT_FEATURES else round(v, 3)
        if anomaly_scores:
            evidence["anomaly_score"] = round(max(anomaly_scores), 4)
        sup = [float(a.features["supervised_probability"]) for a in alerts if "supervised_probability" in a.features]
        if sup:
            evidence["supervised_probability"] = round(max(sup), 4)
        if asset:
            evidence["asset_name"] = asset.name
            evidence["asset_service"] = asset.service
        evidence["asset_criticality"] = crit

        return Incident(
            incident_id=g["id"],
            ts_start=g["ts_start"],
            ts_end=g["ts_end"],
            detected_at=self._detected_at(alerts),
            src_ip=g["src_ip"],
            dst_ip=g["dst_ip"],
            attack_type=g["attack_type"],
            attack_id=g["attack_id"],
            rule_ids=rule_ids,
            engines=engines,
            confidence=round(confidence, 3),
            severity=severity,  # type: ignore[arg-type]
            severity_reasons=reasons,
            flow_count=int(g["flow_count"]),
            alert_count=len(alerts),
            peak_pps=peak("packets_per_second"),
            dst_ports=[p for p, _ in ports.most_common(32)],
            asset_name=asset.name if asset else None,
            asset_criticality=crit,
            direction=direction,  # type: ignore[arg-type]
            evidence=evidence,
        )
