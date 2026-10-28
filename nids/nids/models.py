"""Typed records that flow between planes.

Nothing in here carries raw packet bytes. Free-text fields that originate on the
untrusted side of the trust boundary are sanitised before they are stored.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field

Severity = Literal["critical", "high", "medium", "low", "informational"]
SEVERITY_ORDER: list[str] = ["informational", "low", "medium", "high", "critical"]

RemediationIntent = Literal[
    "block_source_ip",
    "rate_limit_destination_port",
    "isolate_host",
    "enable_verbose_logging",
    "review_account_activity",
    "no_action",
]
ALLOWED_INTENTS: frozenset[str] = frozenset(RemediationIntent.__args__)  # type: ignore[attr-defined]


class Flow(BaseModel):
    """One Zeek conn.log record, reduced to typed fields."""

    ts: float
    uid: str
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    service: str | None = None
    duration: float = 0.0
    orig_bytes: int = 0
    resp_bytes: int = 0
    conn_state: str = "OTH"
    history: str = ""
    orig_pkts: int = 0
    resp_pkts: int = 0
    community_id: str | None = None


class DnsQuery(BaseModel):
    ts: float
    uid: str
    src_ip: str
    dst_ip: str
    query: str  # sanitised; used only to compute numeric features, never sent to the LLM


class Alert(BaseModel):
    """A detection on a window of flows, before correlation."""

    ts_start: float
    ts_end: float
    engine: Literal["rule", "anomaly", "supervised"]
    rule_id: str | None = None
    attack_type: str
    attack_id: str | None = None
    confidence: float = Field(ge=0.0, le=1.0)
    src_ip: str
    dst_ip: str | None = None
    dst_ports: list[int] = Field(default_factory=list)
    flow_count: int = 1
    features: dict[str, float | int | str] = Field(default_factory=dict)
    # When the engine could first have raised this alert: window close for rules, flow
    # end for the anomaly engine. Drives detection-latency measurement.
    emitted_at: float = 0.0
    # Zeek uids covered, so overlapping (hopping) windows never double-count flows.
    flow_uids: list[str] = Field(default_factory=list, exclude=True)


class Incident(BaseModel):
    """One attack episode. This is the unit the LLM and the UI see."""

    incident_id: str
    ts_start: float
    ts_end: float
    detected_at: float = 0.0
    src_ip: str
    dst_ip: str | None
    attack_type: str
    attack_id: str | None
    rule_ids: list[str] = Field(default_factory=list)
    engines: list[str] = Field(default_factory=list)
    confidence: float
    severity: Severity
    severity_reasons: list[str] = Field(default_factory=list)
    flow_count: int
    alert_count: int
    peak_pps: float = 0.0
    dst_ports: list[int] = Field(default_factory=list)
    asset_name: str | None = None
    asset_criticality: int | None = None
    direction: Literal["inbound", "outbound", "internal", "external"] = "inbound"
    evidence: dict[str, float | int | str | bool] = Field(default_factory=dict)
    status: Literal["open", "closed"] = "open"
    # [[t, pps], ...] for the dashboard chart. UI only: never part of the LLM evidence.
    timeline: list[list[float]] = Field(default_factory=list)

    @property
    def started_at(self) -> datetime:
        return datetime.fromtimestamp(self.ts_start, tz=timezone.utc)


class Narrative(BaseModel):
    """Schema the LLM must return. Enforced fields are overwritten after validation."""

    summary: str
    attack_type: str
    severity_level: Severity
    affected_assets: list[str] = Field(default_factory=list)
    technical_evidence: list[str] = Field(default_factory=list)
    confidence_note: str = ""
    remediation_intent: RemediationIntent
    data_quality_flags: list[str] = Field(default_factory=list)
