"""M2: supervised detector on CIC-IDS2017 with the leakage-aware protocol (blueprint §6.2).

    python ml/train_supervised.py --data /path/to/MachineLearningCVE --out models/

Works with the original CIC release and with the corrected, relabelled release (Engelen
et al. 2021, Liu et al. 2022), which is recommended: column names are matched in a
normalised form ("Total Fwd Packet" == "Total Fwd Packets" == "Total Forward Packets"),
and labels ending in "Attempted" (attacks that did not succeed) follow --attempted.

Protocol, in order:
  1. load the per-day CSVs and tag each row with its day (from the file name)
  2. drop exact duplicate rows BEFORE splitting
  3. temporal split: train Mon-Wed, validate Thu, test Fri
  4. drop identifier columns (Flow ID, IPs, ports, timestamp): in a lab capture they are the label
  5. fit all preprocessing and the calibrator on train / validation only
  6. three feature sets, each reported:
       zeek        exactly what nids/supervised.py computes from conn.log; saved as
                   models/supervised.joblib, the model the live pipeline loads
       deployable  all features except payload-byte ones (the blueprint's headline set)
       all         every feature, for the size of the deployability cost
     plus the naive random-split model, so the leak is quantified, not hidden

The task is binary (benign vs attack): Friday's attacks (PortScan, DDoS, Bot) do not
appear in Mon-Wed, so a multi-class model cannot be honestly tested on them.
"""
from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

import sys

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.frozen import FrozenEstimator
from sklearn.metrics import average_precision_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from nids.supervised import ZEEK_CIC_FEATURES  # noqa: E402

DAYS = ["monday", "tuesday", "wednesday", "thursday", "friday"]
SPLIT = {"train": ["monday", "tuesday", "wednesday"], "val": ["thursday"], "test": ["friday"]}
ID_COLUMNS = {"flow id", "source ip", "src ip", "destination ip", "dst ip", "source port", "src port",
              "destination port", "dst port", "timestamp", "protocol", "id"}
_SYNONYMS = {"backward": "bwd", "forward": "fwd", "packets": "packet", "pkts": "packet", "pkt": "packet",
             "source": "src", "destination": "dst", "bytes": "byte", "flags": "flag", "count": "cnt"}


def canonical(name: str) -> str:
    """Spelling-insensitive column key, so both CIC releases map onto the same names."""
    tokens = re.findall(r"[a-z0-9]+", name.lower())
    return "_".join(_SYNONYMS.get(t, t) for t in tokens)


# Canonical key -> the original release's spelling, which the rest of the code uses.
CANONICAL_NAMES = {canonical(c): c for c in [*ZEEK_CIC_FEATURES, "Label", "Flow ID", "Source IP", "Source Port",
                                               "Destination IP", "Destination Port", "Timestamp", "Protocol"]}


def normalise_columns(df: pd.DataFrame) -> pd.DataFrame:
    df.columns = [CANONICAL_NAMES.get(canonical(c), c.strip()) for c in df.columns]
    return df


def apply_attempted(df: pd.DataFrame, policy: str) -> tuple[pd.DataFrame, int]:
    """Corrected release: "X - Attempted" marks attacks that did not succeed.

    drop    (default) exclude them: neither a clean attack nor benign traffic
    benign  count them as benign (nothing malicious happened on the wire)
    attack  count them as attacks (the intent was malicious)
    """
    attempted = df["Label"].astype(str).str.contains("attempted", case=False)
    n = int(attempted.sum())
    if policy == "drop":
        df = df[~attempted].copy()
    elif policy == "benign":
        df.loc[attempted, "Label"] = "BENIGN"
    elif policy != "attack":
        raise ValueError(f"unknown --attempted policy {policy!r}")
    return df, n


# Payload-length features: CICFlowMeter counts payload bytes, live sensors count wire bytes.
BYTE_FEATURE = re.compile(r"length|bytes|segment size|packet size|avg bwd|avg fwd", re.IGNORECASE)
KEEP_DESPITE_NAME = re.compile(r"init_win_bytes", re.IGNORECASE)  # TCP window: a header field


def load(data_dir: Path, attempted: str = "drop") -> tuple[pd.DataFrame, dict]:
    frames = []
    for csv in sorted(data_dir.glob("*.csv")):
        day = next((d for d in DAYS if d in csv.name.lower()), None)
        if day is None:
            continue
        df = normalise_columns(pd.read_csv(csv, low_memory=False, encoding="latin-1"))
        df["__day"] = day
        frames.append(df)
    if not frames:
        raise SystemExit(f"no CIC-IDS2017 day CSVs found in {data_dir}")
    df = pd.concat(frames, ignore_index=True)
    if "Label" not in df.columns:
        raise SystemExit("no Label column found after normalising column names")
    df, n_attempted = apply_attempted(df, attempted)
    df["__y"] = (df["Label"].astype(str).str.strip().str.upper() != "BENIGN").astype(int)
    missing = [c for c in ZEEK_CIC_FEATURES if c not in df.columns]
    info = {"variant": "corrected (has Attempted labels)" if n_attempted else "original or unlabelled-attempts",
            "attempted_rows": n_attempted, "attempted_policy": attempted,
            "zeek_features_missing": missing}
    return df, info


def dedupe(df: pd.DataFrame) -> tuple[pd.DataFrame, int]:
    feature_cols = [c for c in df.columns if c != "__day"]
    before = len(df)
    df = df.drop_duplicates(subset=feature_cols, keep="first")
    return df, before - len(df)


def feature_columns(df: pd.DataFrame, deployable: bool, zeek: bool = False) -> list[str]:
    if zeek:  # exactly what the live Zeek adapter produces, in its order
        return [c for c in ZEEK_CIC_FEATURES if c in df.columns]
    cols = []
    for c in df.columns:
        if c.startswith("__") or c == "Label" or c.lower() in ID_COLUMNS or canonical(c) in {
                canonical(x) for x in ID_COLUMNS}:
            continue
        if not pd.api.types.is_numeric_dtype(df[c]):
            continue
        if deployable and BYTE_FEATURE.search(c) and not KEEP_DESPITE_NAME.search(c):
            continue
        cols.append(c)
    return cols


def clean(X: pd.DataFrame) -> pd.DataFrame:
    return X.replace([np.inf, -np.inf], np.nan).fillna(0.0).astype("float32")


def make_model(seed: int = 42):
    try:
        from xgboost import XGBClassifier

        return XGBClassifier(n_estimators=400, max_depth=8, learning_rate=0.1, subsample=0.8,
                             colsample_bytree=0.8, tree_method="hist", n_jobs=-1, random_state=seed,
                             eval_metric="aucpr")
    except ImportError:
        from sklearn.ensemble import HistGradientBoostingClassifier

        return HistGradientBoostingClassifier(max_iter=400, learning_rate=0.1, random_state=seed)


def metrics(y, p, threshold: float = 0.5) -> dict:
    pred = (p >= threshold).astype(int)
    return {
        "pr_auc": round(float(average_precision_score(y, p)), 4),
        "f1": round(float(f1_score(y, pred, zero_division=0)), 4),
        "precision": round(float(precision_score(y, pred, zero_division=0)), 4),
        "recall": round(float(recall_score(y, pred, zero_division=0)), 4),
        "support_attack": int(y.sum()),
        "support_benign": int(len(y) - y.sum()),
    }


def per_class_recall(df: pd.DataFrame, p: np.ndarray, threshold: float = 0.5) -> dict:
    out = {}
    labels = df["Label"].astype(str).str.strip()
    for lbl in sorted(labels.unique()):
        if lbl.upper() == "BENIGN":
            continue
        m = (labels == lbl).to_numpy()
        out[lbl] = {"recall": round(float((p[m] >= threshold).mean()), 4), "support": int(m.sum())}
    return out


def temporal(df: pd.DataFrame, deployable: bool, seed: int = 42, zeek: bool = False) -> tuple[dict, object, list[str]]:
    cols = feature_columns(df, deployable, zeek)
    parts = {k: df[df["__day"].isin(v)] for k, v in SPLIT.items()}
    model = make_model(seed)
    model.fit(clean(parts["train"][cols]), parts["train"]["__y"])
    # Isotonic calibration on the validation day only, never on the test day.
    cal = CalibratedClassifierCV(FrozenEstimator(model), method="isotonic")
    cal.fit(clean(parts["val"][cols]), parts["val"]["__y"])
    p_test = cal.predict_proba(clean(parts["test"][cols]))[:, 1]
    return {
        "features": len(cols),
        "test": metrics(parts["test"]["__y"].to_numpy(), p_test),
        "test_per_class": per_class_recall(parts["test"], p_test),
    }, cal, cols


def naive(df_raw: pd.DataFrame, seed: int = 42) -> dict:
    """The common, leaky protocol: no dedupe, random split, identifier columns kept."""
    cols = [c for c in df_raw.columns if not c.startswith("__") and c != "Label"
            and pd.api.types.is_numeric_dtype(df_raw[c])]
    tr, te = train_test_split(df_raw, test_size=0.3, random_state=seed, stratify=df_raw["__y"])
    model = make_model(seed)
    model.fit(clean(tr[cols]), tr["__y"])
    p = model.predict_proba(clean(te[cols]))[:, 1]
    return {"features": len(cols), "test": metrics(te["__y"].to_numpy(), p)}


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--data", type=Path, required=True, help="directory of CIC-IDS2017 per-day CSVs")
    ap.add_argument("--out", type=Path, default=Path("models"))
    ap.add_argument("--skip-naive", action="store_true")
    ap.add_argument("--attempted", choices=["drop", "benign", "attack"], default="drop",
                    help="corrected release only: how to treat '... - Attempted' labels (default: drop)")
    a = ap.parse_args(argv)

    raw, info = load(a.data, a.attempted)
    if info["zeek_features_missing"]:
        print(f"warning: Zeek-compatible features missing: {info['zeek_features_missing']}", file=sys.stderr)
    df, n_dup = dedupe(raw)
    report = {
        "dataset": info,
        "rows_raw": len(raw),
        "duplicates_dropped": n_dup,
        "duplicate_fraction": round(n_dup / len(raw), 4),
        "split": SPLIT,
    }
    report["zeek_temporal"], zeek_model, zeek_cols = temporal(df, deployable=True, zeek=True)
    report["deployable_temporal"], model, cols = temporal(df, deployable=True)
    report["all_features_temporal"], _, _ = temporal(df, deployable=False)
    if not a.skip_naive:
        report["naive_random_split"] = naive(raw)
        report["naive_minus_honest_f1"] = round(
            report["naive_random_split"]["test"]["f1"] - report["deployable_temporal"]["test"]["f1"], 4)

    a.out.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump({"model": model, "features": cols}, a.out / "supervised_deployable.joblib")
    # The live pipeline loads this one (nids/supervised.py refuses any other feature set).
    joblib.dump({"model": zeek_model, "features": zeek_cols}, a.out / "supervised.joblib")
    (a.out / "supervised_report.json").write_text(json.dumps(report, indent=2))
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
