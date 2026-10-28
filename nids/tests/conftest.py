import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nids.lab import generate  # noqa: E402


@pytest.fixture(scope="session")
def lab(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("lab")
    generate.main(["--out", str(out), "--baseline-minutes", "5", "--demo-minutes", "15"])
    return out


@pytest.fixture(scope="session")
def anomaly_model(lab, tmp_path_factory):
    from nids import anomaly
    from nids.sensing import zeek

    path = tmp_path_factory.mktemp("models") / "anomaly.joblib"
    anomaly.train(zeek.read_conn(lab / "baseline" / "conn.log")).save(path)
    return path
