"""Deterministic narrative validator (blueprint §3.6). No model involved.

Reject-and-fallback on anything structural; override the fields we own. Returns the
verdict plus the list of reasons so the pass rate and failure modes are measurable.
"""
from __future__ import annotations

import math
import re

from pydantic import ValidationError

from nids.models import ALLOWED_INTENTS, Incident, Narrative

CVE = re.compile(r"\bCVE-\d{4}-\d{3,}\b", re.IGNORECASE)
# Commands must never appear in prose; the policy engine owns them.
COMMANDISH = re.compile(r"(\biptables\b|\bnft\b|\bsudo\b|\brm\s+-|\bcurl\b|\bwget\b|`|\$\(|;\s*\w+\s+-)", re.IGNORECASE)
MAX_SENTENCES = 3


def _values_match(cited: str, actual: object) -> bool:
    cited = cited.strip().strip("'\"")
    if isinstance(actual, bool):
        return cited.lower() == str(actual).lower()
    if isinstance(actual, int | float):
        try:
            c = float(cited)
        except ValueError:
            return False
        return math.isclose(c, float(actual), rel_tol=0.01, abs_tol=1e-3)
    return cited == str(actual)


def validate(
    raw: dict, incident: Incident, evidence: dict, allowed_intents: list[str], default_intent: str
) -> tuple[bool, Narrative | None, list[str]]:
    reasons: list[str] = []
    try:
        n = Narrative.model_validate(raw)
    except ValidationError as e:
        bad_intent = raw.get("remediation_intent") not in ALLOWED_INTENTS if isinstance(raw, dict) else True
        reasons.append("remediation_intent not in enum" if bad_intent else f"schema: {e.error_count()} errors")
        return False, None, reasons

    if not n.summary.strip():
        reasons.append("empty summary")
    if not n.technical_evidence:
        reasons.append("no evidence cited")
    for cite in n.technical_evidence:
        if "=" not in cite:
            reasons.append(f"citation without '=': {cite[:40]!r}")
            continue
        field, value = (p.strip() for p in cite.split("=", 1))
        if field not in evidence:
            reasons.append(f"hallucinated field: {field[:40]!r}")
        elif not _values_match(value, evidence[field]):
            reasons.append(f"wrong value for {field}")

    prose = " ".join([n.summary, n.confidence_note, *n.technical_evidence])
    if CVE.search(prose):
        reasons.append("mentions a CVE identifier")
    if COMMANDISH.search(prose):
        reasons.append("contains command-like text")

    if reasons:
        return False, None, reasons

    # Fields we own are overwritten, never trusted.
    flags = list(n.data_quality_flags)
    if n.attack_type != incident.attack_type:
        flags.append("attack_type overridden by classifier")
    if n.severity_level != incident.severity:
        flags.append("severity overridden by severity table")
    intent = n.remediation_intent
    if intent not in allowed_intents:
        flags.append(f"intent {intent} not permitted for this attack type; using {default_intent}")
        intent = default_intent

    sentences = re.split(r"(?<=[.!?])\s+", n.summary.strip())
    summary = " ".join(sentences[:MAX_SENTENCES])

    assets = []
    if incident.asset_name:
        target = incident.src_ip if incident.direction == "outbound" or not incident.dst_ip else incident.dst_ip
        assets.append(f"{incident.asset_name} ({target})")
    elif incident.dst_ip:
        assets.append(incident.dst_ip)

    return True, n.model_copy(update={
        "summary": summary,
        "attack_type": incident.attack_type,
        "severity_level": incident.severity,
        "affected_assets": assets,
        "remediation_intent": intent,
        "data_quality_flags": [f[:120] for f in flags][:10],
    }), []
