"""Plane 3c + §3.4: Isolation Forest with a frozen, batch-invariant score.

The blueprint's correction, implemented: raw scores are mapped through the empirical CDF
of a held-out *benign calibration set*, frozen at training time. The score of a flow
then depends only on that flow, never on what else is in the batch.

    score = ECDF_baseline(raw)   # fraction of baseline traffic that is LESS anomalous

So score > 0.99 means "more anomalous than 99% of baseline". (Note: the v2.0 blueprint
snippet writes `1.0 - percentile`; with raw = -score_samples, higher raw is already more
anomalous, so the ECDF value itself is the score. Subtracting from 1 would invert it.)
"""
from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from nids.features import FEATURE_REGISTRY_VERSION, FLOW_FEATURES, flow_matrix
from nids.models import Alert, Flow

ALERT_THRESHOLD = 0.99
CRITICAL_THRESHOLD = 0.999
PSI_BINS = 10
# Conventional PSI reading: < 0.10 stable, 0.10-0.25 moderate shift, > 0.25 significant drift.
PSI_MODERATE, PSI_DRIFT = 0.10, 0.25


@dataclass
class AnomalyModel:
    forest: IsolationForest
    median: np.ndarray
    iqr: np.ndarray
    calib_scores: np.ndarray  # sorted raw scores of the benign calibration set
    feature_names: list[str]
    feature_registry_version: str
    # Per-feature reference histogram of the benign calibration set, for drift (PSI).
    ref_edges: list[np.ndarray] | None = None
    ref_props: list[np.ndarray] | None = None
    trained_at: float = 0.0
    n_train: int = 0

    def _scale(self, X: np.ndarray) -> np.ndarray:
        return (X - self.median) / (self.iqr + 1e-9)

    def raw(self, X: np.ndarray) -> np.ndarray:
        return -self.forest.score_samples(self._scale(X))  # higher = more anomalous

    def score(self, X: np.ndarray) -> np.ndarray:
        """Batch-invariant percentile in [0, 1]."""
        if len(X) == 0:
            return np.empty(0)
        r = self.raw(X)
        return np.searchsorted(self.calib_scores, r, side="right") / len(self.calib_scores)

    def psi(self, X: np.ndarray) -> dict[str, float]:
        """Population stability index of live features against the frozen benign reference.

        This catches distribution change (concept drift); the frozen ECDF only fixes batch
        composition. Note that an attack in progress also shifts the distribution.
        """
        if self.ref_edges is None or self.ref_props is None or len(X) == 0:
            return {}
        out = {}
        for i, name in enumerate(self.feature_names):
            live = _proportions(X[:, i], self.ref_edges[i])
            ref = self.ref_props[i]
            out[name] = round(float(np.sum((live - ref) * np.log(live / ref))), 4)
        return out

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        meta = {
            "feature_names": self.feature_names,
            "feature_registry_version": self.feature_registry_version,
            "n_train": self.n_train,
            "n_calibration": int(len(self.calib_scores)),
            "threshold": ALERT_THRESHOLD,
            "trained_at": self.trained_at,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        path.with_suffix(".json").write_text(json.dumps(meta, indent=2))

    @staticmethod
    def load(path: str | Path) -> "AnomalyModel":
        # Model files are control-plane artefacts: only load ones you built yourself.
        model: AnomalyModel = joblib.load(path)
        if model.feature_names != FLOW_FEATURES:
            raise ValueError("model was trained on a different feature set; retrain it")
        return model


def _edges(col: np.ndarray) -> np.ndarray:
    """Quantile bin edges, de-duplicated so binary / heavily tied features still work."""
    inner = np.unique(np.quantile(col, np.linspace(0, 1, PSI_BINS + 1)[1:-1]))
    return np.concatenate([[-np.inf], inner, [np.inf]])


def _proportions(col: np.ndarray, edges: np.ndarray, eps: float = 1e-4) -> np.ndarray:
    # Right-closed bins so a tied value (e.g. 0 in a binary feature) falls in one bin.
    idx = np.searchsorted(edges[1:-1], col, side="left")
    counts = np.bincount(idx, minlength=len(edges) - 1).astype(float)
    return np.clip(counts / max(len(col), 1), eps, None)


def train(benign: Sequence[Flow], calib_fraction: float = 0.3, seed: int = 42) -> AnomalyModel:
    """Fit on benign flows only; freeze the ECDF on a disjoint benign calibration split."""
    X = flow_matrix(benign)
    if len(X) < 200:
        raise ValueError(f"need at least 200 benign flows to train, got {len(X)}")
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(X))
    n_cal = int(len(X) * calib_fraction)
    X_cal, X_fit = X[idx[:n_cal]], X[idx[n_cal:]]

    median = np.median(X_fit, axis=0)
    iqr = np.subtract(*np.percentile(X_fit, [75, 25], axis=0))
    iqr = np.where(iqr == 0, 1.0, iqr)
    forest = IsolationForest(n_estimators=300, contamination="auto", random_state=seed)
    forest.fit((X_fit - median) / (iqr + 1e-9))
    model = AnomalyModel(forest, median, iqr, np.empty(0), list(FLOW_FEATURES), FEATURE_REGISTRY_VERSION)
    model.calib_scores = np.sort(model.raw(X_cal))
    model.ref_edges = [_edges(X_cal[:, i]) for i in range(X.shape[1])]
    model.ref_props = [_proportions(X_cal[:, i], e) for i, e in enumerate(model.ref_edges)]
    model.trained_at = time.time()
    model.n_train = int(len(X_fit))
    return model


def confidence_for(score: float) -> float:
    """Anomaly-only detections stay below the 0.70 'medium' line unless extreme."""
    return 0.75 if score > CRITICAL_THRESHOLD else 0.6


def detect(model: AnomalyModel, flows: Sequence[Flow], threshold: float = ALERT_THRESHOLD) -> list[Alert]:
    scores = model.score(flow_matrix(flows))
    alerts = []
    for f, s in zip(flows, scores):
        if s <= threshold:
            continue
        alerts.append(
            Alert(
                ts_start=f.ts,
                ts_end=f.ts + f.duration,
                engine="anomaly",
                attack_type="Unclassified Anomaly",
                confidence=confidence_for(float(s)),
                src_ip=f.src_ip,
                dst_ip=f.dst_ip,
                dst_ports=[f.dst_port],
                flow_count=1,
                features={"anomaly_score": round(float(s), 4), "bytes_out": f.orig_bytes},
                emitted_at=f.ts + f.duration,
                flow_uids=[f.uid],
            )
        )
    return alerts
