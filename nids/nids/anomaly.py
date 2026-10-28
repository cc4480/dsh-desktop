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

import json
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


@dataclass
class AnomalyModel:
    forest: IsolationForest
    median: np.ndarray
    iqr: np.ndarray
    calib_scores: np.ndarray  # sorted raw scores of the benign calibration set
    feature_names: list[str]
    feature_registry_version: str

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

    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self, path)
        meta = {
            "feature_names": self.feature_names,
            "feature_registry_version": self.feature_registry_version,
            "n_calibration": int(len(self.calib_scores)),
            "threshold": ALERT_THRESHOLD,
        }
        path.with_suffix(".json").write_text(json.dumps(meta, indent=2))

    @staticmethod
    def load(path: str | Path) -> "AnomalyModel":
        # Model files are control-plane artefacts: only load ones you built yourself.
        model: AnomalyModel = joblib.load(path)
        if model.feature_names != FLOW_FEATURES:
            raise ValueError("model was trained on a different feature set; retrain it")
        return model


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
            )
        )
    return alerts
