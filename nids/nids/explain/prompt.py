"""Prompt assembly. This file is the trust boundary: read it to know exactly what bytes
reach the model.

Only the incident's typed evidence dict and its deterministic classification are sent.
Values are scalars (int/float/bool) or short strings that already passed edge
sanitisation; they are re-checked here, and anything that is not a plain token is
dropped rather than escaped.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

from nids.models import Incident

PROMPT_VERSION = "2"
SYSTEM_PROMPT = (Path(__file__).resolve().parents[2] / "prompts" / "system_prompt.txt").read_text(encoding="utf-8")
_TOKEN = re.compile(r"^[A-Za-z0-9._:+\-]{0,64}$")


def safe_evidence(incident: Incident) -> dict[str, float | int | str | bool]:
    out: dict[str, float | int | str | bool] = {}
    for k, v in incident.evidence.items():
        if isinstance(v, bool | int | float):
            out[k] = v
        elif isinstance(v, str) and _TOKEN.match(v):
            out[k] = v
        # else: drop. A value that is not a plain token has no business in a prompt.
    return out


def classification(incident: Incident, allowed_intents: list[str]) -> dict:
    return {
        "attack_type": incident.attack_type,
        "attack_id": incident.attack_id,
        "confidence": incident.confidence,
        "severity": incident.severity,
        "severity_reasons": incident.severity_reasons,
        "allowed_remediation_intents": allowed_intents,
    }


def user_message(evidence: dict, cls: dict) -> str:
    return (
        "<CLASSIFICATION>\n" + json.dumps(cls, indent=2, sort_keys=True) + "\n</CLASSIFICATION>\n\n"
        "<EVIDENCE>\n" + json.dumps(evidence, indent=2, sort_keys=True) + "\n</EVIDENCE>"
    )


def fingerprint(evidence: dict, cls: dict, model: str) -> str:
    """Cache key. Volatile counters are bucketed so a still-growing flood reuses its narrative."""
    stable = {k: v for k, v in evidence.items() if k not in ("flow_count", "duration_s", "packets_per_second")}
    blob = json.dumps({"e": stable, "c": cls, "m": model, "v": PROMPT_VERSION}, sort_keys=True)
    return hashlib.sha256(blob.encode()).hexdigest()
