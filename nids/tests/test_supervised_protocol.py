"""The §6.2 protocol helpers, on a tiny CIC-shaped frame (the real dataset is not in CI)."""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "ml"))
import train_supervised as ts  # noqa: E402


def _frame(seed=0):
    rng = np.random.default_rng(seed)
    rows = []
    for day in ts.DAYS:
        for i in range(200):
            attack = day != "monday" and i % 4 == 0
            rows.append({
                "Destination Port": 80 if attack else int(rng.integers(1, 65535)),
                "Flow Duration": float(rng.exponential(1000 if attack else 50000)),
                "Total Fwd Packets": int(rng.integers(1, 3) if attack else rng.integers(3, 50)),
                "Total Length of Fwd Packets": float(rng.integers(0, 1500)),
                "Fwd Packet Length Max": float(rng.integers(0, 1500)),
                "Flow Bytes/s": float(rng.random() * 1e5),
                "Init_Win_bytes_forward": int(rng.integers(0, 65535)),
                "Flow IAT Mean": float(rng.exponential(100 if attack else 5000)),
                "Label": ("PortScan" if day == "friday" else "DoS") if attack else "BENIGN",
                "__day": day,
            })
    df = pd.DataFrame(rows)
    df["__y"] = (df["Label"] != "BENIGN").astype(int)
    return pd.concat([df, df.iloc[:50]], ignore_index=True)  # inject exact duplicates


def test_dedupe_happens_before_split():
    df, n = ts.dedupe(_frame())
    assert n == 50 and not df.duplicated(subset=[c for c in df.columns if c != "__day"]).any()


def test_identifier_and_byte_features_excluded():
    df = _frame()
    deploy = ts.feature_columns(df, deployable=True)
    full = ts.feature_columns(df, deployable=False)
    assert "Destination Port" not in full
    for byte_col in ("Total Length of Fwd Packets", "Fwd Packet Length Max", "Flow Bytes/s"):
        assert byte_col in full and byte_col not in deploy
    assert "Init_Win_bytes_forward" in deploy and "Flow IAT Mean" in deploy


def test_temporal_split_never_trains_on_test_day():
    df, _ = ts.dedupe(_frame())
    report, _, cols = ts.temporal(df, deployable=True)
    assert report["test"]["support_attack"] == int(df[df["__day"] == "friday"]["__y"].sum())
    assert "PortScan" in report["test_per_class"]
    assert set(cols) == set(ts.feature_columns(df, deployable=True))


def _corrected_csv(tmp_path):
    """Headers and labels in the corrected release's style (Engelen et al. 2021)."""
    rng = np.random.default_rng(1)
    for day in ts.DAYS:
        rows = []
        for i in range(60):
            attack = day != "monday" and i % 4 == 0
            rows.append({
                "id": i, "Flow ID": f"f{i}", "Src IP": "10.0.0.1", "Dst Port": 80, "Timestamp": "x",
                "Flow Duration": float(rng.exponential(1000)), "Total Fwd Packet": int(rng.integers(1, 9)),
                "Total Bwd packets": int(rng.integers(0, 9)), "Flow Packets/s": float(rng.random()),
                "Fwd Packets/s": float(rng.random()), "Bwd Packets/s": float(rng.random()),
                "Down/Up Ratio": float(rng.random()), "FIN Flag Count": 0, "SYN Flag Count": 1,
                "RST Flag Count": 0, "ACK Flag Count": 1,
                "label": ("DoS Hulk - Attempted" if i % 8 == 0 else "DoS Hulk") if attack else "BENIGN",
            })
        pd.DataFrame(rows).to_csv(tmp_path / f"{day}.csv", index=False)
    return tmp_path


def test_corrected_release_headers_normalise(tmp_path):
    df, info = ts.load(_corrected_csv(tmp_path))
    assert info["zeek_features_missing"] == []
    assert {"Total Fwd Packets", "Total Backward Packets", "Source IP", "Destination Port", "Label"} <= set(df.columns)
    cols = ts.feature_columns(df, deployable=False)
    assert "id" not in cols and "Destination Port" not in cols
    assert ts.feature_columns(df, deployable=True, zeek=True) == list(ts.ZEEK_CIC_FEATURES)


def test_attempted_policies(tmp_path):
    d = _corrected_csv(tmp_path)
    dropped, info = ts.load(d, "drop")
    assert info["attempted_rows"] > 0 and info["variant"].startswith("corrected")
    assert not dropped["Label"].str.contains("Attempted").any()
    benign, _ = ts.load(d, "benign")
    attack, _ = ts.load(d, "attack")
    assert len(benign) == len(attack) == len(dropped) + info["attempted_rows"]
    assert benign["__y"].sum() == dropped["__y"].sum()
    assert attack["__y"].sum() == dropped["__y"].sum() + info["attempted_rows"]
