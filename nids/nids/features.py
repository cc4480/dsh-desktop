"""Plane 2: feature registry and windowed aggregates.

Two feature families:
  * per-flow features, consumed by the unsupervised anomaly engine;
  * per-window aggregates keyed by (src, dst, ...), consumed by the rule engine.

Every feature is declared in FEATURE_REGISTRY with its unit and source so the trainer and
the live path read the same definitions. A feature marked train_only may not be used by a
deployable model.
"""
from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

import numpy as np

from nids.models import DnsQuery, Flow, HttpRequest, Notice, TlsSession

if TYPE_CHECKING:
    from nids.profile import Profile

FEATURE_REGISTRY_VERSION = "2"


@dataclass(frozen=True)
class FeatureSpec:
    name: str
    unit: str
    source: str
    scope: str  # "flow" | "window"
    train_only: bool = False


FEATURE_REGISTRY: dict[str, FeatureSpec] = {
    f.name: f
    for f in [
        # per-flow (anomaly engine). Ports and addresses are deliberately absent: in lab
        # captures they are the label, and the model would memorise the attacker.
        FeatureSpec("log_duration", "log1p(s)", "conn.log", "flow"),
        FeatureSpec("log_orig_pkts", "log1p(count)", "conn.log", "flow"),
        FeatureSpec("log_resp_pkts", "log1p(count)", "conn.log", "flow"),
        FeatureSpec("log_orig_bytes", "log1p(payload bytes)", "conn.log", "flow"),
        FeatureSpec("log_resp_bytes", "log1p(payload bytes)", "conn.log", "flow"),
        FeatureSpec("is_s0", "bool", "conn.log", "flow"),
        FeatureSpec("is_rej", "bool", "conn.log", "flow"),
        FeatureSpec("is_sf", "bool", "conn.log", "flow"),
        FeatureSpec("handshake_done", "bool", "conn.log", "flow"),
        FeatureSpec("history_len", "count", "conn.log", "flow"),
        # windowed (rule engine)
        FeatureSpec("flow_count", "count", "conn.log", "window"),
        FeatureSpec("packets_per_second", "pkt/s", "conn.log", "window"),
        FeatureSpec("syn_ratio", "ratio", "conn.log", "window"),
        FeatureSpec("s0_ratio", "ratio", "conn.log", "window"),
        FeatureSpec("failed_conn_ratio", "ratio", "conn.log", "window"),
        FeatureSpec("distinct_dst_ports", "count", "conn.log", "window"),
        FeatureSpec("distinct_dst_ips", "count", "conn.log", "window"),
        FeatureSpec("bytes_out", "bytes", "conn.log", "window"),
        FeatureSpec("bytes_in", "bytes", "conn.log", "window"),
        FeatureSpec("active_duration", "s", "conn.log", "window"),
        FeatureSpec("iat_mean", "s", "conn.log", "window"),
        FeatureSpec("iat_cv", "ratio", "conn.log", "window"),
        FeatureSpec("handshake_ratio", "ratio", "conn.log", "window"),
        FeatureSpec("mean_duration", "s", "conn.log", "window"),
        FeatureSpec("mean_bytes_out", "bytes", "conn.log", "window"),
        # behavioural, need a baseline profile (nids/profile.py)
        FeatureSpec("new_dst_ratio", "ratio", "conn.log+profile", "window"),
        FeatureSpec("bytes_out_vs_baseline", "x baseline", "conn.log+profile", "window"),
        FeatureSpec("new_fingerprint_ratio", "ratio", "ssl.log+profile", "window"),
        FeatureSpec("query_count", "count", "dns.log", "window"),
        FeatureSpec("mean_label_length", "chars", "dns.log", "window"),
        FeatureSpec("unique_subdomain_ratio", "ratio", "dns.log", "window"),
        FeatureSpec("label_entropy", "bits/char", "dns.log", "window"),
        FeatureSpec("request_count", "count", "http.log", "window"),
        FeatureSpec("client_error_ratio", "ratio", "http.log", "window"),
        FeatureSpec("not_found_ratio", "ratio", "http.log", "window"),
        FeatureSpec("distinct_uri_count", "count", "http.log", "window"),
        FeatureSpec("scanner_ua_ratio", "ratio", "http.log", "window"),
        FeatureSpec("session_count", "count", "ssl.log", "window"),
        FeatureSpec("self_signed_ratio", "ratio", "ssl.log", "window"),
        FeatureSpec("notice_count", "count", "notice.log", "window"),
    ]
}

FLOW_FEATURES: list[str] = [n for n, f in FEATURE_REGISTRY.items() if f.scope == "flow"]
FAILED_STATES = {"S0", "REJ", "RSTOS0", "RSTRH", "SH", "SHR"}


# ---------------------------------------------------------------- per-flow
def flow_vector(f: Flow) -> list[float]:
    hist = f.history
    return [
        math.log1p(max(f.duration, 0.0)),
        math.log1p(f.orig_pkts),
        math.log1p(f.resp_pkts),
        math.log1p(f.orig_bytes),
        math.log1p(f.resp_bytes),
        float(f.conn_state == "S0"),
        float(f.conn_state == "REJ"),
        float(f.conn_state == "SF"),
        float("h" in hist and "A" in hist),
        float(len(hist)),
    ]


def flow_matrix(flows: Sequence[Flow]) -> np.ndarray:
    if not flows:
        return np.empty((0, len(FLOW_FEATURES)))
    return np.asarray([flow_vector(f) for f in flows], dtype=float)


# ---------------------------------------------------------------- windowed
@dataclass
class Window:
    key: tuple[str, ...]
    ts_start: float
    ts_end: float
    flows: list[Flow]
    features: dict[str, float]


def _is_syn_only(f: Flow) -> bool:
    # Zeek history: uppercase = originator. 'S' without a later originator 'A' means the
    # handshake was never completed by the client.
    return "S" in f.history and "A" not in f.history


def conn_window_features(flows: Sequence[Flow]) -> dict[str, float]:
    n = len(flows)
    ts = sorted(f.ts for f in flows)
    span = ts[-1] - ts[0] if n > 1 else 0.0
    pkts = sum(f.orig_pkts for f in flows)
    iats = [b - a for a, b in zip(ts, ts[1:])]
    iat_mean = statistics.fmean(iats) if iats else 0.0
    iat_cv = (statistics.pstdev(iats) / iat_mean) if len(iats) > 1 and iat_mean > 0 else 0.0
    return {
        "flow_count": n,
        "packets_per_second": pkts / max(span, 1.0),
        "syn_ratio": sum(_is_syn_only(f) for f in flows) / n,
        "s0_ratio": sum(f.conn_state == "S0" for f in flows) / n,
        "failed_conn_ratio": sum(f.conn_state in FAILED_STATES for f in flows) / n,
        "distinct_dst_ports": len({f.dst_port for f in flows}),
        "distinct_dst_ips": len({f.dst_ip for f in flows}),
        "bytes_out": sum(f.orig_bytes for f in flows),
        "bytes_in": sum(f.resp_bytes for f in flows),
        "active_duration": span,
        "iat_mean": iat_mean,
        "iat_cv": iat_cv,
        "handshake_ratio": sum("h" in f.history and "A" in f.history for f in flows) / n,
        "mean_duration": statistics.fmean(f.duration for f in flows),
        "mean_bytes_out": statistics.fmean(f.orig_bytes for f in flows),
    }


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def dns_window_features(queries: Sequence[DnsQuery]) -> dict[str, float]:
    n = len(queries)
    first_labels = [q.query.split(".")[0] if q.query else "" for q in queries]
    return {
        "query_count": n,
        "mean_label_length": statistics.fmean(len(lbl) for lbl in first_labels) if n else 0.0,
        "unique_subdomain_ratio": len(set(first_labels)) / n if n else 0.0,
        "label_entropy": statistics.fmean(_entropy(lbl) for lbl in first_labels) if n else 0.0,
    }


def http_window_features(reqs: Sequence[HttpRequest]) -> dict[str, float]:
    n = len(reqs)
    return {
        "request_count": n,
        "client_error_ratio": sum(400 <= r.status_code < 500 for r in reqs) / n,
        "not_found_ratio": sum(r.status_code == 404 for r in reqs) / n,
        "distinct_uri_count": len({r.uri_hash for r in reqs if r.uri_hash}),
        "scanner_ua_ratio": sum(r.ua_category == "scanner" for r in reqs) / n,
    }


def tls_window_features(sessions: Sequence[TlsSession], profile: Profile | None) -> dict[str, float]:
    n = len(sessions)
    out = {
        "session_count": n,
        "self_signed_ratio": sum(t.validation_status == "self_signed" for t in sessions) / n,
    }
    if profile is not None:
        verdicts = [profile.is_new_fingerprint(t.ja4) for t in sessions]
        known = [v for v in verdicts if v is not None]
        if known:  # absent entirely when the sensor computes no fingerprints
            out["new_fingerprint_ratio"] = sum(known) / len(known)
    return out


def profile_conn_features(flows: Sequence[Flow], profile: Profile) -> dict[str, float]:
    src = flows[0].src_ip
    return {
        "new_dst_ratio": sum(profile.is_new_dst(f.src_ip, f.dst_ip) for f in flows) / len(flows),
        "bytes_out_vs_baseline": sum(f.orig_bytes for f in flows) / profile.bytes_baseline(src),
    }


def window_features(source: str, recs: Sequence, profile: Profile | None = None) -> dict[str, float]:
    if source == "conn":
        feats = conn_window_features(recs)
        if profile is not None:
            feats.update(profile_conn_features(recs, profile))
        return feats
    if source == "dns":
        return dns_window_features(recs)
    if source == "http":
        return http_window_features(recs)
    if source == "tls":
        return tls_window_features(recs, profile)
    if source == "notice":
        return {"notice_count": len(recs)}
    raise ValueError(f"unknown source {source!r}")


def hopping_windows(
    records: Iterable[Flow | DnsQuery | HttpRequest | TlsSession | Notice], key_fields: Sequence[str], window_s: float, hop_s: float | None = None
) -> list[tuple[tuple[str, ...], float, list]]:
    """Group records into epoch-aligned windows of window_s that start every hop_s seconds.

    The default hop is half a window, so every burst shorter than window_s / 2 lies whole
    inside at least one window. Tumbling windows (hop == window) can split an attack across
    a boundary and leave each half below threshold.
    """
    hop = hop_s or window_s / 2
    per_window = max(1, round(window_s / hop))
    buckets: dict[tuple, list] = defaultdict(list)
    for r in records:
        key = tuple(str(getattr(r, k)) for k in key_fields)
        last = math.floor(r.ts / hop)
        for n in range(last - per_window + 1, last + 1):
            buckets[(key, n * hop)].append(r)
    return [(key, start, recs) for (key, start), recs in sorted(buckets.items(), key=lambda kv: kv[0][1])]
