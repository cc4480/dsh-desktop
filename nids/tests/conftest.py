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
def trained(lab, tmp_path_factory) -> dict[str, Path]:
    """Anomaly model + behavioural profile, built exactly as `python -m nids train` does."""
    from nids import __main__ as cli

    d = tmp_path_factory.mktemp("models")
    paths = {"anomaly": d / "anomaly.joblib", "profile": d / "profile.json"}
    cli.main(["train", str(lab / "baseline"), "--out", str(paths["anomaly"]),
              "--profile-out", str(paths["profile"])])
    return paths


@pytest.fixture(scope="session")
def anomaly_model(trained) -> Path:
    return trained["anomaly"]


@pytest.fixture
def config(trained, tmp_path):
    """Pipeline config pointing at the session's trained artefacts and a fresh database."""
    from nids import pipeline

    def make(**kw):
        return pipeline.Config(db_path=tmp_path / "nids.db", model_path=trained["anomaly"],
                               profile_path=trained["profile"], supervised_path=None, **kw)

    return make
