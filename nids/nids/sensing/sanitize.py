"""Edge sanitisation for attacker-controlled strings (blueprint §5.2, Ingest/Feature rows).

Untrusted free text (DNS queries, HTTP hosts, user agents, SNI) is escaped, length-capped
and charset-filtered *before* it enters any record. Values that fail are replaced with a
placeholder rather than dropped, so the record stays countable.
"""
from __future__ import annotations

import ipaddress
import re

MAX_LEN = 64
_HOSTLIKE = re.compile(r"[^A-Za-z0-9._\-]")


def hostlike(value: object, max_len: int = MAX_LEN) -> str:
    """Keep only DNS-name characters, capped at max_len."""
    if value is None:
        return ""
    text = _HOSTLIKE.sub("", str(value))
    return text[:max_len]


def ip(value: object) -> str:
    """Return a canonical IP string or raise ValueError."""
    return str(ipaddress.ip_address(str(value).strip()))


def safe_int(value: object, default: int = 0) -> int:
    try:
        if value in (None, "-", ""):
            return default
        return int(float(value))  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def safe_float(value: object, default: float = 0.0) -> float:
    try:
        if value in (None, "-", ""):
            return default
        return float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return default


def enum_token(value: object, max_len: int = 16) -> str:
    """Short alphanumeric token such as a conn_state or a history string."""
    if value is None:
        return ""
    return re.sub(r"[^A-Za-z0-9^]", "", str(value))[:max_len]
