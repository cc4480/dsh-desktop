"""§3.4: the anomaly score must be a property of the flow, not of the batch."""
import numpy as np

from nids import anomaly
from nids.features import flow_matrix
from nids.sensing import zeek


def test_score_is_batch_invariant(lab, anomaly_model):
    model = anomaly.AnomalyModel.load(anomaly_model)
    flows = zeek.read_conn(lab / "demo" / "conn.log")
    benign = [f for f in flows if f.src_ip.startswith("192.168.1.1") and f.src_ip != "192.168.1.105"][:500]
    flood = [f for f in flows if f.src_ip == "192.168.1.105"][:500]

    x = flow_matrix(benign[:1])
    alone = model.score(x)[0]
    with_benign = model.score(flow_matrix(benign))[0]
    with_attack = model.score(np.vstack([x, flow_matrix(flood)]))[0]
    assert alone == with_benign == with_attack


def test_all_benign_batch_does_not_light_up(lab, anomaly_model):
    """Batch min-max would push the most extreme benign flow to 1.0; the frozen ECDF does not."""
    model = anomaly.AnomalyModel.load(anomaly_model)
    flows = zeek.read_conn(lab / "demo" / "conn.log")
    benign = [f for f in flows if f.ts < flows[0].ts + 60]
    rate = float((model.score(flow_matrix(benign)) > anomaly.ALERT_THRESHOLD).mean())
    assert rate < 0.05, rate


def test_scores_are_percentiles(anomaly_model):
    model = anomaly.AnomalyModel.load(anomaly_model)
    assert np.all(np.diff(model.calib_scores) >= 0)
    s = model.score(np.zeros((3, len(model.feature_names))))
    assert np.all((0 <= s) & (s <= 1))
