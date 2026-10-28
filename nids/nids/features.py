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

import numpy as np

from nids.models import DnsQuery, Flow

FEATURE_REGISTRY_VERSION = "1"


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
        FeatureSpec("query_count", "count", "dns.log", "window"),
        FeatureSpec("mean_label_length", "chars", "dns.log", "window"),
        FeatureSpec("unique_subdomain_ratio", "ratio", "dns.log", "window"),
        FeatureSpec("label_entropy", "bits/char", "dns.log", "window"),
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


def tumbling_windows(
    records: Iterable[Flow | DnsQuery], key_fields: Sequence[str], window_s: float
) -> list[tuple[tuple[str, ...], float, list]]:
    """Group records into fixed, epoch-aligned windows per key."""
    buckets: dict[tuple, list] = defaultdict(list)
    for r in records:
        key = tuple(str(getattr(r, k)) for k in key_fields)
        bucket = math.floor(r.ts / window_s) * window_s
        buckets[(key, bucket)].append(r)
    return [(key, start, recs) for (key, start), recs in sorted(buckets.items(), key=lambda kv: kv[0][1])]
