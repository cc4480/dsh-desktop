"""Zeek log readers (Plane 1).

Reads Zeek logs in either JSON (`LogAscii::use_json=T`) or the default TSV format.
Every field passes through sanitize.* on the way in. Attacker-controlled text (URIs,
User-Agents, SNI, DNS names) is reduced to numbers, hashes or enums here, at the edge:
user agents and URIs are the classic prompt-injection substrate, and nothing parsed
from them can reach the LLM.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from nids.models import DnsQuery, Flow, HttpRequest, Notice, SensorHealth, TlsSession
from nids.sensing import sanitize as s
from nids.sensing.community_id import community_id

_CID = re.compile(r"^1:[A-Za-z0-9+/=]{20,44}$")
HTTP_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "CONNECT", "TRACE", "PROPFIND"}
_SCANNER_UA = re.compile(r"nikto|sqlmap|nmap|masscan|zgrab|gobuster|dirbuster|dirb|wfuzz|ffuf|nuclei|"
                         r"acunetix|nessus|openvas|wpscan|feroxbuster|httpx|whatweb", re.IGNORECASE)
_CLI_UA = re.compile(r"^(curl|wget|python-requests|python-urllib|go-http-client|libwww-perl|java/|okhttp|"
                     r"powershell|httpie)", re.IGNORECASE)
_BROWSER_UA = re.compile(r"mozilla/\d|opera/\d", re.IGNORECASE)
VALIDATION = [("ok", "ok"), ("self signed", "self_signed"), ("expired", "expired"),
              ("unable to get local issuer", "untrusted"), ("untrusted", "untrusted")]


class LineParser:
    """Parses Zeek log lines one at a time, remembering the TSV #fields header."""

    def __init__(self) -> None:
        self.fields: list[str] | None = None

    def parse(self, line: str) -> dict | None:
        line = line.rstrip("\n")
        if not line:
            return None
        if line.startswith("{"):
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                return None
            return rec if isinstance(rec, dict) else None
        if line.startswith("#fields"):
            self.fields = line.split("\t")[1:]
            return None
        if line.startswith("#") or not self.fields:
            return None
        # TSV marks unset fields "-" and empty sets "(empty)"; JSON omits them.
        return {k: v for k, v in zip(self.fields, line.split("\t")) if v not in ("-", "(empty)")}


def _records(path: Path) -> Iterator[dict]:
    parser = LineParser()
    with path.open(encoding="utf-8", errors="replace") as fh:
        for line in fh:
            rec = parser.parse(line)
            if rec is not None:
                yield rec


def _iter(source: str | Path | Iterable[dict]) -> Iterator[dict]:
    """A log file path, or records already read (watch mode tails files itself)."""
    if isinstance(source, str | Path):
        p = Path(source)
        return _records(p) if p.exists() else iter(())
    return iter(source)


def read_conn(path: str | Path | Iterable[dict]) -> list[Flow]:
    flows: list[Flow] = []
    for r in _iter(path):
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
                    community_id=_cid(r),
                )
            )
        except ValueError:
            continue  # unparseable address: drop the record, never guess
    flows.sort(key=lambda f: f.ts)
    return flows


def _cid(r: dict) -> str | None:
    given = str(r.get("community_id") or "")
    if _CID.match(given):
        return given
    try:
        return community_id(s.ip(r.get("id.orig_h")), s.safe_int(r.get("id.orig_p")), s.ip(r.get("id.resp_h")),
                            s.safe_int(r.get("id.resp_p")), str(r.get("proto") or "tcp"))
    except ValueError:
        return None


def read_dns(path: str | Path | Iterable[dict]) -> list[DnsQuery]:
    out: list[DnsQuery] = []
    for r in _iter(path):
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


def ua_category(ua: object) -> str:
    """Classify a User-Agent into an enum. The text itself is discarded."""
    text = str(ua or "").strip()
    if not text:
        return "empty"
    if _SCANNER_UA.search(text):
        return "scanner"
    if _CLI_UA.search(text):
        return "cli"
    if _BROWSER_UA.search(text):
        return "browser"
    return "other"


def _validation(status: object) -> str:
    text = str(status or "").lower()
    if not text:
        return "unknown"
    return next((v for k, v in VALIDATION if k in text), "other")


def read_ssl(path: str | Path | Iterable[dict]) -> list[TlsSession]:
    out: list[TlsSession] = []
    for r in _iter(path):
        try:
            out.append(TlsSession(
                ts=s.safe_float(r.get("ts")),
                uid=s.enum_token(r.get("uid"), 32),
                src_ip=s.ip(r.get("id.orig_h")),
                dst_ip=s.ip(r.get("id.resp_h")),
                dst_port=s.safe_int(r.get("id.resp_p")),
                version=s.enum_token(r.get("version"), 12),
                server_name=s.hostlike(r.get("server_name"), 64),
                established=str(r.get("established")).lower() in ("t", "true"),
                validation_status=_validation(r.get("validation_status")),
                ja3=re.sub(r"[^0-9a-f]", "", str(r.get("ja3") or "").lower())[:32],
                ja4=re.sub(r"[^A-Za-z0-9_]", "", str(r.get("ja4") or ""))[:40],
            ))
        except ValueError:
            continue
    out.sort(key=lambda t: t.ts)
    return out


def read_http(path: str | Path | Iterable[dict]) -> list[HttpRequest]:
    out: list[HttpRequest] = []
    for r in _iter(path):
        try:
            method = str(r.get("method") or "").upper()
            uri = str(r.get("uri") or "")
            out.append(HttpRequest(
                ts=s.safe_float(r.get("ts")),
                uid=s.enum_token(r.get("uid"), 32),
                src_ip=s.ip(r.get("id.orig_h")),
                dst_ip=s.ip(r.get("id.resp_h")),
                dst_port=s.safe_int(r.get("id.resp_p")),
                method=method if method in HTTP_METHODS else "OTHER",
                status_code=s.safe_int(r.get("status_code")),
                uri_len=len(uri),
                uri_hash=hashlib.sha1(uri.encode("utf-8", "replace")).hexdigest()[:12] if uri else "",
                ua_category=ua_category(r.get("user_agent")),
                request_body_len=s.safe_int(r.get("request_body_len")),
                response_body_len=s.safe_int(r.get("response_body_len")),
            ))
        except ValueError:
            continue
    out.sort(key=lambda h: h.ts)
    return out


def _opt_ip(v: object) -> str | None:
    try:
        return s.ip(v) if v not in (None, "") else None
    except ValueError:
        return None


def parse_notices(records: Iterable[dict], kind: str) -> list[Notice]:
    name_field = "note" if kind == "notice" else "name"
    out: list[Notice] = []
    for r in records:
        name = re.sub(r"[^A-Za-z0-9_:\-]", "", str(r.get(name_field) or ""))[:64]
        if not name:
            continue
        out.append(Notice(ts=s.safe_float(r.get("ts")), kind=kind, name=name,  # type: ignore[arg-type]
                          src_ip=_opt_ip(r.get("src") or r.get("id.orig_h")),
                          dst_ip=_opt_ip(r.get("dst") or r.get("id.resp_h"))))
    return out


def read_notices(logdir: Path) -> list[Notice]:
    out = parse_notices(_iter(logdir / "notice.log"), "notice") + parse_notices(_iter(logdir / "weird.log"), "weird")
    out.sort(key=lambda n: n.ts)
    return out


def read_health(logdir: Path, notices: list[Notice]) -> SensorHealth:
    h = SensorHealth(notices=sum(n.kind == "notice" for n in notices),
                     weirds=sum(n.kind == "weird" for n in notices),
                     logs_present=sorted(p.stem for p in logdir.glob("*.log")))
    loss = logdir / "capture_loss.log"
    if loss.exists():
        vals = [s.safe_float(r.get("percent_lost")) for r in _records(loss)]
        h.capture_loss_pct = round(max(vals), 3) if vals else None
    stats = logdir / "stats.log"
    if stats.exists():
        for r in _records(stats):
            h.pkts_proc += s.safe_int(r.get("pkts_proc"))
            h.pkts_dropped += s.safe_int(r.get("pkts_dropped"))
    return h


@dataclass
class LogBundle:
    """Everything the pipeline reads from one Zeek log directory."""

    flows: list[Flow]
    dns: list[DnsQuery] = field(default_factory=list)
    tls: list[TlsSession] = field(default_factory=list)
    http: list[HttpRequest] = field(default_factory=list)
    notices: list[Notice] = field(default_factory=list)
    health: SensorHealth = field(default_factory=SensorHealth)

    def records(self, source: str) -> list:
        return {"conn": self.flows, "dns": self.dns, "tls": self.tls, "http": self.http,
                "notice": [n for n in self.notices if n.kind == "notice" and n.src_ip]}[source]


def read_dir(logdir: str | Path) -> LogBundle:
    d = Path(logdir)
    notices = read_notices(d)
    return LogBundle(
        flows=read_conn(d / "conn.log"),
        dns=read_dns(d / "dns.log"),
        tls=read_ssl(d / "ssl.log"),
        http=read_http(d / "http.log"),
        notices=notices,
        health=read_health(d, notices),
    )
