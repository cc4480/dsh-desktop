"""Plane 3a: YAML rule engine. No eval(), no expression strings."""
from __future__ import annotations

import operator
from collections.abc import Sequence
from pathlib import Path
from typing import TYPE_CHECKING

import yaml
from pydantic import BaseModel, field_validator

from nids.features import FEATURE_REGISTRY, hopping_windows, window_features
from nids.models import ALLOWED_INTENTS, Alert, DnsQuery, Flow
from nids.sensing.zeek import LogBundle

if TYPE_CHECKING:
    from nids.profile import Profile

SOURCES = {"conn", "dns", "http", "tls", "notice"}
FILTERABLE = {"dst_port", "src_port", "proto", "service", "name", "method", "ua_category", "validation_status"}

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
        # A feature the window cannot provide (e.g. a profile feature with no profile
        # loaded, or JA4 when the sensor does not compute it) never matches.
        if self.feature not in features:
            return False
        return OPS[self.op](features[self.feature], self.value)


class Rule(BaseModel):
    id: str
    source: str
    # Keep only records whose field is one of the listed values, before windowing.
    filter: dict[str, list[str | int]] = {}
    group_by: list[str]
    window: float
    correlation_window: float
    when: list[Condition]
    confidence: float
    attack_type: str
    attack_id: str
    default_intent: str
    allowed_intents: list[str]

    @field_validator("source")
    @classmethod
    def _source(cls, v: str) -> str:
        if v not in SOURCES:
            raise ValueError(f"unknown source {v!r}")
        return v

    @field_validator("filter")
    @classmethod
    def _filter(cls, v: dict) -> dict:
        bad = set(v) - FILTERABLE
        if bad:
            raise ValueError(f"cannot filter on {sorted(bad)}")
        return v

    @property
    def needs_profile(self) -> bool:
        return any("profile" in FEATURE_REGISTRY[c.feature].source for c in self.when)

    def keep(self, record) -> bool:
        return all(getattr(record, k, None) in vals for k, vals in self.filter.items())

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


def evaluate(
    rules: Sequence[Rule],
    logs: LogBundle | Sequence[Flow],
    dns: Sequence[DnsQuery] = (),
    profile: Profile | None = None,
) -> list[Alert]:
    bundle = logs if isinstance(logs, LogBundle) else LogBundle(flows=list(logs), dns=list(dns))
    alerts: list[Alert] = []
    for rule in rules:
        if rule.needs_profile and profile is None:
            continue
        records = [r for r in bundle.records(rule.source) if rule.keep(r)]
        for key, start, recs in hopping_windows(records, rule.group_by, rule.window):
            feats = window_features(rule.source, recs, profile)
            if not all(c.holds(feats) for c in rule.when):
                continue
            fired = first_fire(rule, recs, profile, start + rule.window)
            keyed = dict(zip(rule.group_by, key))
            ports = sorted({r.dst_port for r in recs if hasattr(r, "dst_port")})
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
                    # Notices are not flows (and have no uid to de-duplicate overlapping
                    # windows on); they show up as notice_count in the evidence instead.
                    flow_count=0 if rule.source == "notice" else len(recs),
                    features={k: round(v, 4) for k, v in feats.items()},
                    emitted_at=fired,
                    flow_uids=[r.uid for r in recs if getattr(r, "uid", None)],
                )
            )
    return sorted(alerts, key=lambda a: a.ts_start)


def _visible_at(r) -> float:
    # A conn record only exists once Zeek logs it, at the end of the connection.
    return r.ts + getattr(r, "duration", 0.0)


def first_fire(rule: Rule, recs: Sequence, profile: Profile | None, window_close: float, steps: int = 50) -> float:
    """Earliest moment the rule's condition held, as a live sensor would see it.

    Records are replayed in the order they become visible; the condition is re-checked on
    growing prefixes (at most `steps` checks). Detection latency then reflects the attack,
    not where it sits inside a window. Falls back to window close if no prefix fires.
    """
    ordered = sorted(recs, key=_visible_at)
    n = len(ordered)
    stride = max(1, n // steps)
    for end in [*range(stride, n, stride), n]:
        prefix = ordered[:end]
        if all(c.holds(window_features(rule.source, prefix, profile)) for c in rule.when):
            return min(_visible_at(prefix[-1]), window_close)
    return window_close


def inactive(rules: Sequence[Rule], profile: Profile | None) -> list[str]:
    """Rules that cannot fire in this run, so the UI can say so instead of staying silent."""
    return [r.id for r in rules if r.needs_profile and profile is None]
