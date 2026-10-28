"""Plane 3a: YAML rule engine. No eval(), no expression strings."""
from __future__ import annotations

import operator
from collections.abc import Sequence
from pathlib import Path

import yaml
from pydantic import BaseModel, field_validator

from nids.features import FEATURE_REGISTRY, conn_window_features, dns_window_features, tumbling_windows
from nids.models import ALLOWED_INTENTS, Alert, DnsQuery, Flow

OPS = {">": operator.gt, ">=": operator.ge, "<": operator.lt, "<=": operator.le, "==": operator.eq}


class Condition(BaseModel):
    feature: str
    op: str
    value: float

    @field_validator("feature")
    @classmethod
    def _known_feature(cls, v: str) -> str:
        if v not in FEATURE_REGISTRY:
            raise ValueError(f"unknown feature {v!r}")
        if FEATURE_REGISTRY[v].train_only:
            raise ValueError(f"feature {v!r} is train_only and cannot drive a live rule")
        return v

    @field_validator("op")
    @classmethod
    def _known_op(cls, v: str) -> str:
        if v not in OPS:
            raise ValueError(f"unknown operator {v!r}")
        return v

    def holds(self, features: dict[str, float]) -> bool:
        return OPS[self.op](features[self.feature], self.value)


class Rule(BaseModel):
    id: str
    source: str
    group_by: list[str]
    window: float
    correlation_window: float
    when: list[Condition]
    confidence: float
    attack_type: str
    attack_id: str
    default_intent: str
    allowed_intents: list[str]

    @field_validator("default_intent")
    @classmethod
    def _intent(cls, v: str) -> str:
        if v not in ALLOWED_INTENTS:
            raise ValueError(f"intent {v!r} not allowlisted")
        return v

    @field_validator("allowed_intents")
    @classmethod
    def _intents(cls, v: list[str]) -> list[str]:
        bad = set(v) - ALLOWED_INTENTS
        if bad:
            raise ValueError(f"intents {sorted(bad)} not allowlisted")
        return v


def load_rules(path: str | Path) -> list[Rule]:
    with Path(path).open(encoding="utf-8") as fh:
        return [Rule.model_validate(r) for r in yaml.safe_load(fh)]


def evaluate(rules: Sequence[Rule], flows: Sequence[Flow], dns: Sequence[DnsQuery] = ()) -> list[Alert]:
    alerts: list[Alert] = []
    for rule in rules:
        records = flows if rule.source == "conn" else dns
        featurise = conn_window_features if rule.source == "conn" else dns_window_features
        for key, _start, recs in tumbling_windows(records, rule.group_by, rule.window):
            feats = featurise(recs)
            if not all(c.holds(feats) for c in rule.when):
                continue
            keyed = dict(zip(rule.group_by, key))
            ports = sorted({r.dst_port for r in recs}) if rule.source == "conn" else []
            alerts.append(
                Alert(
                    ts_start=min(r.ts for r in recs),
                    ts_end=max(r.ts for r in recs),
                    engine="rule",
                    rule_id=rule.id,
                    attack_type=rule.attack_type,
                    attack_id=rule.attack_id,
                    confidence=rule.confidence,
                    src_ip=keyed.get("src_ip", recs[0].src_ip),
                    dst_ip=keyed.get("dst_ip"),
                    dst_ports=ports[:64],
                    flow_count=len(recs),
                    features={k: round(v, 4) for k, v in feats.items()},
                )
            )
    return sorted(alerts, key=lambda a: a.ts_start)
