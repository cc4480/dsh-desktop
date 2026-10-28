"""Plane 6: deterministic policy engine. The LLM picks an intent; this code renders it.

Never executes anything. Every argument that reaches a template is re-validated here
(IPs through ipaddress, ports and rates as ints, the interface and nft names against a
strict pattern), so even a compromised upstream cannot smuggle text into a command.

Backends: iptables (ip6tables for IPv6 sources) or nftables (config/policy.yaml). nft
rules carry a `nids-<incident>` comment so the rollback deletes exactly the rule that was
added, by handle, instead of guessing.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from nids.assets import AssetRegistry
from nids.models import ALLOWED_INTENTS, Incident

_NAME = re.compile(r"^[A-Za-z0-9_.\-]{1,32}$")

COMMON: dict[str, tuple[str, str]] = {
    "isolate_host": (
        "# 1. snapshot evidence for {host_ip}  2. move it to the quarantine VLAN at the switch  3. preserve host state",
        "# rollback: reconnect {host_ip} to its production VLAN",
    ),
    "enable_verbose_logging": (
        "sudo timeout {capture_seconds} tcpdump -i {iface} -nn -s0 -w /var/tmp/{incident_id}.pcap host {src_ip}",
        "sudo pkill -f '/var/tmp/{incident_id}.pcap'",
    ),
    "review_account_activity": (
        "# review authentication events for accounts on {host_ip} in the 30 minutes before {timestamp}",
        "# no rollback required (read-only action)",
    ),
    "no_action": ("# no automated response recommended", "# n/a"),
}

IPTABLES: dict[str, tuple[str, str]] = {
    "block_source_ip": (
        "sudo {ipt} -I INPUT -s {src_ip} -j DROP",
        "sudo {ipt} -D INPUT -s {src_ip} -j DROP",
    ),
    "rate_limit_destination_port": (
        "sudo {ipt} -I INPUT -p tcp --dport {dst_port} --syn -m limit --limit {rate}/s --limit-burst {burst} -j ACCEPT\n"
        "sudo {ipt} -I INPUT 2 -p tcp --dport {dst_port} --syn -j DROP",
        "sudo {ipt} -D INPUT -p tcp --dport {dst_port} --syn -j DROP\n"
        "sudo {ipt} -D INPUT -p tcp --dport {dst_port} --syn -m limit --limit {rate}/s --limit-burst {burst} -j ACCEPT",
    ),
}
IPTABLES_DRY_RUN = {
    "block_source_ip": "sudo {ipt} -C INPUT -s {src_ip} -j DROP  # exit 0 = rule already present",
    "rate_limit_destination_port": "sudo {ipt} -S INPUT | grep -- '--dport {dst_port}'",
}

_NFT_DELETE = ("sudo nft -a list chain {fam} {table} {chain} | awk '/\"nids-{incident_id}\"/ {{print $NF}}' "
               "| xargs -r -n1 sudo nft delete rule {fam} {table} {chain} handle")
NFTABLES: dict[str, tuple[str, str]] = {
    "block_source_ip": (
        "sudo nft add rule {fam} {table} {chain} {nfaddr} saddr {src_ip} drop comment \"nids-{incident_id}\"",
        _NFT_DELETE,
    ),
    "rate_limit_destination_port": (
        "sudo nft add rule {fam} {table} {chain} tcp dport {dst_port} tcp flags syn "
        "limit rate over {rate}/second burst {burst} packets drop comment \"nids-{incident_id}\"",
        _NFT_DELETE,
    ),
}
NFTABLES_DRY_RUN = {
    "block_source_ip": "sudo nft list chain {fam} {table} {chain} | grep -c 'nids-{incident_id}'  # 0 = not yet applied",
    "rate_limit_destination_port": "sudo nft list chain {fam} {table} {chain} | grep -c 'nids-{incident_id}'",
}

# Kept for callers that enumerate what can be rendered.
INTENT_TEMPLATES = {**COMMON, **IPTABLES}


@dataclass
class Rendered:
    intent: str
    command: str | None
    rollback: str | None
    dry_run: str | None
    refused_reason: str | None = None


class PolicyEngine:
    def __init__(self, assets: AssetRegistry, iface: str = "eth0", rate: int = 50, burst: int = 100,
                 firewall: str = "iptables", capture_seconds: int = 900, nft: dict | None = None):
        self.assets = assets
        self.iface = iface if _NAME.match(iface) else "eth0"
        self.rate, self.burst = int(rate), int(burst)
        self.capture_seconds = int(capture_seconds)
        if firewall not in ("iptables", "nftables"):
            raise ValueError(f"unknown firewall {firewall!r}")
        self.firewall = firewall
        nft = nft or {}
        self.nft = {k: nft.get(k, d) for k, d in (("family", "inet"), ("table", "filter"), ("chain", "input"))}
        if not all(_NAME.match(str(v)) for v in self.nft.values()):
            raise ValueError("invalid nftables family/table/chain name")

    @classmethod
    def from_config(cls, path: str | Path | None, assets: AssetRegistry) -> "PolicyEngine":
        if not path or not Path(path).exists():
            return cls(assets)
        c = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        rl = c.get("rate_limit", {})
        return cls(assets, iface=str(c.get("iface", "eth0")), rate=rl.get("per_second", 50),
                   burst=rl.get("burst", 100), firewall=c.get("firewall", "iptables"),
                   capture_seconds=c.get("capture_seconds", 900), nft=c.get("nftables"))

    def render(self, intent: str, incident: Incident) -> Rendered:
        if intent not in ALLOWED_INTENTS:  # defence in depth
            return Rendered(intent, None, None, None, f"intent {intent!r} is not allowlisted")
        try:
            src_addr = ipaddress.ip_address(incident.src_ip)
            src = str(src_addr)
            dst_port = int(incident.evidence.get("dst_port", incident.dst_ports[0] if incident.dst_ports else 0))
            host = src if incident.direction == "outbound" or not incident.dst_ip \
                else str(ipaddress.ip_address(incident.dst_ip))
        except (ValueError, TypeError):
            return Rendered(intent, None, None, None, "evidence failed re-validation")

        if intent == "block_source_ip":
            if src in self.assets.protected_ips:
                return Rendered(intent, None, None, None, f"refusing to block protected host {src}")
            if self.assets.is_internal(src) and self.assets.get(src):
                return Rendered(intent, None, None, None,
                                f"{src} is a registered internal asset; use isolate_host via change approval")
        if intent == "rate_limit_destination_port":
            if not 0 < dst_port < 65536:
                return Rendered(intent, None, None, None, "no single destination port to rate-limit")
            if dst_port in self.assets.critical_service_ports:
                return Rendered(intent, None, None, None, f"port {dst_port} is a critical service; requires change approval")
        if intent == "isolate_host" and host in self.assets.protected_ips:
            return Rendered(intent, None, None, None, f"refusing to isolate protected host {host}")

        v6 = src_addr.version == 6
        params = {
            "src_ip": src,
            "dst_port": dst_port,
            "host_ip": host,
            "iface": self.iface,
            "rate": self.rate,
            "burst": self.burst,
            "capture_seconds": self.capture_seconds,
            "incident_id": incident.incident_id,
            "timestamp": incident.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "ipt": "ip6tables" if v6 else "iptables",
            "nfaddr": "ip6" if v6 else "ip",
            "fam": self.nft["family"], "table": self.nft["table"], "chain": self.nft["chain"],
        }
        if intent in COMMON:
            cmd, rollback = COMMON[intent]
            dry = None
        elif self.firewall == "nftables":
            cmd, rollback = NFTABLES[intent]
            dry = NFTABLES_DRY_RUN.get(intent)
        else:
            cmd, rollback = IPTABLES[intent]
            dry = IPTABLES_DRY_RUN.get(intent)
        return Rendered(intent, cmd.format(**params), rollback.format(**params), dry.format(**params) if dry else None)
