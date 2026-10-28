"""Zeek log readers (Plane 1).

Reads conn.log and dns.log in either JSON (`LogAscii::use_json=T`) or the default TSV
format. Every field passes through sanitize.* on the way in. http.log is deliberately
not parsed into any record that reaches the LLM: user agents and URIs are the classic
prompt-injection substrate.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

from nids.models import DnsQuery, Flow
from nids.sensing import sanitize as s


def _records(path: Path) -> Iterator[dict]:
    fields: list[str] | None = None
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line:
                continue
            if line.startswith("{"):
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    continue
            elif line.startswith("#fields"):
                fields = line.split("\t")[1:]
            elif line.startswith("#"):
                continue
            elif fields:
                # TSV marks unset fields "-" and empty sets "(empty)"; JSON omits them.
                yield {k: v for k, v in zip(fields, line.split("\t")) if v not in ("-", "(empty)")}


def read_conn(path: str | Path) -> list[Flow]:
    flows: list[Flow] = []
    for r in _records(Path(path)):
        try:
            flows.append(
                Flow(
                    ts=s.safe_float(r.get("ts")),
                    uid=s.enum_token(r.get("uid"), 32),
                    src_ip=s.ip(r.get("id.orig_h")),
                    src_port=s.safe_int(r.get("id.orig_p")),
                    dst_ip=s.ip(r.get("id.resp_h")),
                    dst_port=s.safe_int(r.get("id.resp_p")),
                    proto=s.enum_token(r.get("proto"), 8) or "tcp",
                    service=s.hostlike(r.get("service"), 16) or None,
                    duration=s.safe_float(r.get("duration")),
                    orig_bytes=s.safe_int(r.get("orig_bytes")),
                    resp_bytes=s.safe_int(r.get("resp_bytes")),
                    conn_state=s.enum_token(r.get("conn_state"), 8) or "OTH",
                    history=s.enum_token(r.get("history"), 32),
                    orig_pkts=s.safe_int(r.get("orig_pkts")),
                    resp_pkts=s.safe_int(r.get("resp_pkts")),
                    community_id=s.enum_token(r.get("community_id"), 64) or None,
                )
            )
        except ValueError:
            continue  # unparseable address: drop the record, never guess
    flows.sort(key=lambda f: f.ts)
    return flows


def read_dns(path: str | Path) -> list[DnsQuery]:
    out: list[DnsQuery] = []
    p = Path(path)
    if not p.exists():
        return out
    for r in _records(p):
        try:
            out.append(
                DnsQuery(
                    ts=s.safe_float(r.get("ts")),
                    uid=s.enum_token(r.get("uid"), 32),
                    src_ip=s.ip(r.get("id.orig_h")),
                    dst_ip=s.ip(r.get("id.resp_h")),
                    query=s.hostlike(r.get("query"), 253),
                )
            )
        except ValueError:
            continue
    out.sort(key=lambda q: q.ts)
    return out
