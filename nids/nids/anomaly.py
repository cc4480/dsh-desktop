"""Plane 3c + §3.4: Isolation Forest + autoencoder, each with a frozen, batch-invariant score.

The blueprint's correction, implemented: raw scores are mapped through the empirical CDF
of a held-out *benign calibration set*, frozen at training time. The score of a flow
then depends only on that flow, never on what else is in the batch.

    score = ECDF_baseline(raw)   # fraction of baseline traffic that is LESS anomalous

So score > 0.99 means "more anomalous than 99% of baseline". (Note: the v2.0 blueprint
snippet writes `1.0 - percentile`; with raw = -score_samples, higher raw is already more
anomalous, so the ECDF value itself is the score. Subtracting from 1 would invert it.)

Two detectors with different failure modes:
  * Isolation Forest   global novelty: few, easy-to-isolate points
  * autoencoder        multivariate novelty: combinations of individually normal values,
                       error weighted by per-feature inverse residual variance (diagonal
                       Mahalanobis) so high-variance features cannot dominate

Combination rule (documented, not learned):
    anomalous  <=>  both > ALERT_THRESHOLD   or   either > CRITICAL_THRESHOLD
expressed as one score: max(if, ae) when that exceeds CRITICAL_THRESHOLD, else min(if, ae).
Requiring agreement lowers the per-flow false-positive rate, by less than independence
would suggest because the detectors' errors are correlated (synthetic demo: 245 benign
flows over 0.99 for the forest alone, 203 for the autoencoder, 153 combined).

Calibration is per hour of day (UTC) where the baseline has enough flows in that hour, so
"unusual" means "unusual for this hour"; otherwise the global calibration is used.

A point-wise autoencoder is NOT an exfiltration detector: a single exfil flow is often
statistically ordinary. Exfiltration is carried by the behavioural rules (profile.py).
"""
from __future__ import annotations

import hashlib
import json
import time
import warnings
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.exceptions import ConvergenceWarning
from sklearn.neural_network import MLPRegressor

from nids import integrity
from nids.features import FEATURE_REGISTRY_VERSION, FLOW_FEATURES, flow_matrix
from nids.models import Alert, Flow

ALERT_THRESHOLD = 0.99
CRITICAL_THRESHOLD = 0.999
MIN_HOUR_CALIBRATION = 500  # flows needed in an hour of day before it gets its own ECDF
CLEAN_QUANTILE = 0.99  # majority-vote cleaning drops the top 1% of either detector
PSI_BINS = 10
# Conventional PSI reading: < 0.10 stable, 0.10-0.25 moderate shift, > 0.25 significant drift.
PSI_MODERATE, PSI_DRIFT = 0.10, 0.25


def hours_of(flows: Sequence[Flow]) -> np.ndarray:
    return ((np.asarray([f.ts for f in flows], dtype=float) // 3600) % 24).astype(int)


@dataclass
class Calibration:
    if_scores: np.ndarray  # sorted raw scores of benign calibration flows
    ae_scores: np.ndarray

    @staticmethod
    def pct(sorted_ref: np.ndarray, raw: np.ndarray) -> np.ndarray:
        return np.searchsorted(sorted_ref, raw, side="right") / len(sorted_ref)


@dataclass
class AnomalyModel:
    forest: IsolationForest
    autoencoder: MLPRegressor
    median: np.ndarray
    iqr: np.ndarray
    ae_inv_var: np.ndarray
    calibration: Calibration
    feature_names: list[str]
    feature_registry_version: str
    by_hour: dict[int, Calibration] = field(default_factory=dict)
    # Per-feature reference histogram of the benign calibration set, for drift (PSI).
    ref_edges: list[np.ndarray] | None = None
    ref_props: list[np.ndarray] | None = None
    trained_at: float = 0.0
    n_train: int = 0
    n_cleaned: int = 0

    @property
    def calib_scores(self) -> np.ndarray:
        return self.calibration.if_scores

    def _scale(self, X: np.ndarray) -> np.ndarray:
        return (X - self.median) / (self.iqr + 1e-9)

    def raw_if(self, X: np.ndarray) -> np.ndarray:
        return -self.forest.score_samples(self._scale(X))  # higher = more anomalous

    def raw_ae(self, X: np.ndarray) -> np.ndarray:
        Xs = self._scale(X)
        return (((Xs - self.autoencoder.predict(Xs)) ** 2) * self.ae_inv_var).sum(axis=1)

    def raw(self, X: np.ndarray) -> np.ndarray:
        return self.raw_if(X)

    def scores(self, X: np.ndarray, hours: np.ndarray | None = None) -> tuple[np.ndarray, np.ndarray]:
        """(isolation-forest percentile, autoencoder percentile), each batch-invariant."""
        if len(X) == 0:
            return np.empty(0), np.empty(0)
        ri, ra = self.raw_if(X), self.raw_ae(X)
        s_if = Calibration.pct(self.calibration.if_scores, ri)
        s_ae = Calibration.pct(self.calibration.ae_scores, ra)
        if hours is not None and self.by_hour:
            for h, cal in self.by_hour.items():
                m = hours == h
                if m.any():
                    s_if[m] = Calibration.pct(cal.if_scores, ri[m])
                    s_ae[m] = Calibration.pct(cal.ae_scores, ra[m])
        return s_if, s_ae

    def score(self, X: np.ndarray, hours: np.ndarray | None = None) -> np.ndarray:
        """Combined percentile: see the module docstring for the rule."""
        s_if, s_ae = self.scores(X, hours)
        hi, lo = np.maximum(s_if, s_ae), np.minimum(s_if, s_ae)
        return np.where(hi > CRITICAL_THRESHOLD, hi, lo)

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
        integrity.sign(path)
        meta = {
            "detectors": ["isolation_forest", "autoencoder"],
            "combination": f"both > {ALERT_THRESHOLD} or either > {CRITICAL_THRESHOLD}",
            "feature_names": self.feature_names,
            "feature_registry_version": self.feature_registry_version,
            "n_train": self.n_train,
            "n_cleaned": self.n_cleaned,
            "n_calibration": len(self.calibration.if_scores),
            "hours_calibrated": sorted(self.by_hour),
            "threshold": ALERT_THRESHOLD,
            "trained_at": self.trained_at,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        path.with_suffix(".json").write_text(json.dumps(meta, indent=2), encoding="utf-8")

    @staticmethod
    def load(path: str | Path) -> AnomalyModel:
        integrity.verify(path)  # a pickle runs code on load: only a model we signed at training time
        model: AnomalyModel = joblib.load(path)
        if not hasattr(model, "autoencoder") or model.feature_names != FLOW_FEATURES:
            raise ValueError("model was trained by an older version or on a different feature set; retrain it")
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


def _fit_detectors(Xs: np.ndarray, seed: int) -> tuple[IsolationForest, MLPRegressor, np.ndarray]:
    forest = IsolationForest(n_estimators=300, contamination="auto", random_state=seed).fit(Xs)
    ae = MLPRegressor(hidden_layer_sizes=(16, 4, 16), activation="tanh", max_iter=300, early_stopping=True,
                      random_state=seed)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", ConvergenceWarning)
        ae.fit(Xs, Xs)
    resid_var = ((Xs - ae.predict(Xs)) ** 2).mean(axis=0)
    return forest, ae, 1.0 / np.maximum(resid_var, 1e-3)


def train(
    benign: Sequence[Flow],
    calib_fraction: float = 0.3,
    seed: int = 42,
    exclude_uids: set[str] | None = None,
    clean: bool = True,
) -> AnomalyModel:
    """Fit on benign flows only; freeze the ECDFs on a disjoint benign calibration split.

    Majority-vote cleaning (blueprint §3c): "clean baseline" is aspirational, so flows any
    rule fired on (exclude_uids) are removed, then flows in the top 1% of either detector
    are removed and both detectors are refitted. The calibration split is left untouched,
    so the thresholds still describe the real baseline.
    """
    flows = list(benign)
    X = flow_matrix(flows)
    if len(X) < 200:
        raise ValueError(f"need at least 200 benign flows to train, got {len(X)}")
    hours = hours_of(flows)
    rng = np.random.default_rng(seed)
    idx = rng.permutation(len(X))
    n_cal = int(len(X) * calib_fraction)
    cal_idx, fit_idx = idx[:n_cal], idx[n_cal:]
    excluded = exclude_uids or set()
    fit_idx = np.array([i for i in fit_idx if flows[i].uid not in excluded])
    n_rule_removed = len(idx) - n_cal - len(fit_idx)
    X_fit = X[fit_idx]

    median = np.median(X_fit, axis=0)
    iqr = np.subtract(*np.percentile(X_fit, [75, 25], axis=0))
    iqr = np.where(iqr == 0, 1.0, iqr)
    Xs = (X_fit - median) / (iqr + 1e-9)
    forest, ae, inv_var = _fit_detectors(Xs, seed)

    n_vote_removed = 0
    if clean:
        r_if = -forest.score_samples(Xs)
        r_ae = (((Xs - ae.predict(Xs)) ** 2) * inv_var).sum(axis=1)
        keep = (r_if <= np.quantile(r_if, CLEAN_QUANTILE)) & (r_ae <= np.quantile(r_ae, CLEAN_QUANTILE))
        n_vote_removed = int((~keep).sum())
        Xs = Xs[keep]
        forest, ae, inv_var = _fit_detectors(Xs, seed)

    model = AnomalyModel(forest, ae, median, iqr, inv_var, Calibration(np.empty(0), np.empty(0)),
                         list(FLOW_FEATURES), FEATURE_REGISTRY_VERSION)
    X_cal, h_cal = X[cal_idx], hours[cal_idx]
    ri, ra = model.raw_if(X_cal), model.raw_ae(X_cal)
    model.calibration = Calibration(np.sort(ri), np.sort(ra))
    for h in np.unique(h_cal):
        m = h_cal == h
        if m.sum() >= MIN_HOUR_CALIBRATION:
            model.by_hour[int(h)] = Calibration(np.sort(ri[m]), np.sort(ra[m]))
    model.ref_edges = [_edges(X_cal[:, i]) for i in range(X.shape[1])]
    model.ref_props = [_proportions(X_cal[:, i], e) for i, e in enumerate(model.ref_edges)]
    model.trained_at = time.time()
    model.n_train = len(Xs)
    model.n_cleaned = n_rule_removed + n_vote_removed
    return model


def confidence_for(score: float) -> float:
    """Anomaly-only detections stay below the 0.70 'medium' line unless extreme."""
    return 0.75 if score > CRITICAL_THRESHOLD else 0.6


def detect(model: AnomalyModel, flows: Sequence[Flow], threshold: float = ALERT_THRESHOLD) -> list[Alert]:
    X, hours = flow_matrix(flows), hours_of(flows)
    s_if, s_ae = model.scores(X, hours)
    hi, lo = np.maximum(s_if, s_ae), np.minimum(s_if, s_ae)
    combined = np.where(hi > CRITICAL_THRESHOLD, hi, lo)
    alerts = []
    for f, s, a, b in zip(flows, combined, s_if, s_ae):
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
                features={"anomaly_score": round(float(s), 4), "if_score": round(float(a), 4),
                          "ae_score": round(float(b), 4), "bytes_out": f.orig_bytes},
                emitted_at=f.ts + f.duration,
                flow_uids=[f.uid],
            )
        )
    return alerts
