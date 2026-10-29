"""Plane 3b at runtime: a CIC-IDS2017-trained classifier scoring live Zeek flows.

The train<->live adapter (blueprint §3.1) is this file. Zeek's conn.log carries per-flow
totals and a TCP history string, not per-packet timing or lengths, so only a small subset
of CICFlowMeter's 78 features can be reproduced honestly:

  Flow Duration           conn.duration, seconds -> microseconds (CIC unit)
  Total Fwd/Bwd Packets   orig_pkts / resp_pkts
  Flow/Fwd/Bwd Packets/s  packets / duration; 0 when duration is 0 (what the trainer's
                          inf -> 0 cleaning makes of CIC's "Infinity")
  Down/Up Ratio           resp_pkts / orig_pkts
  FIN/SYN/RST/ACK Flag    presence in Zeek's history string (CIC counts packets; for
    Count                 most flows these are 0/1, but this is an approximation)

Byte-length features are excluded: CICFlowMeter and Zeek both count payload bytes, but
their flow-expiry rules differ, so totals over a flow's lifetime do not line up. A model
trained on anything outside ZEEK_CIC_FEATURES is refused at load time rather than fed
zeros. Train one with: python ml/train_supervised.py --data <dir> --feature-set zeek
"""
from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from nids.models import Alert, Flow

ZEEK_CIC_FEATURES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets", "Flow Packets/s", "Fwd Packets/s",
    "Bwd Packets/s", "Down/Up Ratio", "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "ACK Flag Count",
]
ALERT_PROBABILITY = 0.90
ATTACK_TYPE = "Supervised Detection: Malicious Flow"


def zeek_to_cic(flows: Sequence[Flow]) -> pd.DataFrame:
    rows = []
    for f in flows:
        h = f.history
        d = max(f.duration, 0.0)
        rows.append({
            "Flow Duration": d * 1e6,
            "Total Fwd Packets": f.orig_pkts,
            "Total Backward Packets": f.resp_pkts,
            "Flow Packets/s": (f.orig_pkts + f.resp_pkts) / d if d > 0 else 0.0,
            "Fwd Packets/s": f.orig_pkts / d if d > 0 else 0.0,
            "Bwd Packets/s": f.resp_pkts / d if d > 0 else 0.0,
            "Down/Up Ratio": f.resp_pkts / f.orig_pkts if f.orig_pkts else 0.0,
            "FIN Flag Count": float("F" in h or "f" in h),
            "SYN Flag Count": float(any(c in h for c in "SsHh")),
            "RST Flag Count": float("R" in h or "r" in h),
            "ACK Flag Count": float(any(c in h for c in "AaHhDd")),
        })
    return pd.DataFrame(rows, columns=ZEEK_CIC_FEATURES).astype("float32")


@dataclass
class SupervisedModel:
    model: object
    features: list[str]
    report: dict

    @staticmethod
    def load(path: str | Path) -> "SupervisedModel":
        # Model files are control-plane artefacts: only load ones you built yourself.
        bundle = joblib.load(path)
        missing = [c for c in bundle["features"] if c not in ZEEK_CIC_FEATURES]
        if missing:
            raise ValueError(f"model uses features the Zeek adapter cannot produce: {missing[:5]}; "
                             "retrain with --feature-set zeek")
        report_path = Path(path).with_name("supervised_report.json")
        report = {}
        if report_path.exists():
            import json

            report = json.loads(report_path.read_text(encoding="utf-8"))
        return SupervisedModel(bundle["model"], list(bundle["features"]), report)

    def predict(self, flows: Sequence[Flow]) -> np.ndarray:
        if not flows:
            return np.empty(0)
        X = zeek_to_cic(flows)[self.features]
        return self.model.predict_proba(X)[:, 1]  # type: ignore[attr-defined]


def detect(model: SupervisedModel, flows: Sequence[Flow], threshold: float = ALERT_PROBABILITY) -> list[Alert]:
    probs = model.predict(flows)
    alerts = []
    for f, p in zip(flows, probs):
        if p < threshold:
            continue
        alerts.append(Alert(
            ts_start=f.ts,
            ts_end=f.ts + f.duration,
            engine="supervised",
            attack_type=ATTACK_TYPE,
            # Binary verdict from a benchmark-trained model: corroborating, not decisive.
            confidence=0.75 if p >= 0.99 else 0.65,
            src_ip=f.src_ip,
            dst_ip=f.dst_ip,
            dst_ports=[f.dst_port],
            flow_count=1,
            features={"supervised_probability": round(float(p), 4), "bytes_out": f.orig_bytes},
            emitted_at=f.ts + f.duration,
            flow_uids=[f.uid],
        ))
    return alerts
