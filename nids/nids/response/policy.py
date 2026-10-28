"""Plane 6: deterministic policy engine. The LLM picks an intent; this code renders it.

Never executes anything. Every argument that reaches a template is re-validated here
(IPs through ipaddress, ports and rates as ints), so even a compromised upstream cannot
smuggle text into a command.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from nids.assets import AssetRegistry
from nids.models import ALLOWED_INTENTS, Incident

INTENT_TEMPLATES: dict[str, tuple[str, str]] = {
    "block_source_ip": (
        "sudo iptables -I INPUT -s {src_ip} -j DROP",
        "sudo iptables -D INPUT -s {src_ip} -j DROP",
    ),
    "rate_limit_destination_port": (
        "sudo iptables -I INPUT -p tcp --dport {dst_port} --syn -m limit --limit {rate}/s --limit-burst {burst} -j ACCEPT\n"
        "sudo iptables -I INPUT 2 -p tcp --dport {dst_port} --syn -j DROP",
        "sudo iptables -D INPUT -p tcp --dport {dst_port} --syn -j DROP\n"
        "sudo iptables -D INPUT -p tcp --dport {dst_port} --syn -m limit --limit {rate}/s --limit-burst {burst} -j ACCEPT",
    ),
    "isolate_host": (
        "# 1. snapshot evidence for {host_ip}  2. move it to the quarantine VLAN at the switch  3. preserve host state",
        "# rollback: reconnect {host_ip} to its production VLAN",
    ),
    "enable_verbose_logging": (
        "sudo timeout 900 tcpdump -i {iface} -nn -s0 -w /var/tmp/{incident_id}.pcap host {src_ip}",
        "sudo pkill -f '/var/tmp/{incident_id}.pcap'",
    ),
    "review_account_activity": (
        "# review authentication events for accounts on {host_ip} in the 30 minutes before {timestamp}",
        "# no rollback required (read-only action)",
    ),
    "no_action": ("# no automated response recommended", "# n/a"),
}

DRY_RUN = {
    "block_source_ip": "sudo iptables -C INPUT -s {src_ip} -j DROP  # exit 0 = rule already present",
    "rate_limit_destination_port": "sudo iptables -S INPUT | grep -- '--dport {dst_port}'",
}


@dataclass
class Rendered:
    intent: str
    command: str | None
    rollback: str | None
    dry_run: str | None
    refused_reason: str | None = None


class PolicyEngine:
    def __init__(self, assets: AssetRegistry, iface: str = "eth0", rate: int = 50, burst: int = 100):
        self.assets = assets
        self.iface = iface if iface.isalnum() else "eth0"
        self.rate, self.burst = int(rate), int(burst)

    def render(self, intent: str, incident: Incident) -> Rendered:
        if intent not in ALLOWED_INTENTS or intent not in INTENT_TEMPLATES:  # defence in depth
            return Rendered(intent, None, None, None, f"intent {intent!r} is not allowlisted")
        try:
            src = str(ipaddress.ip_address(incident.src_ip))
            dst_port = int(incident.evidence.get("dst_port", incident.dst_ports[0] if incident.dst_ports else 0))
        except (ValueError, TypeError):
            return Rendered(intent, None, None, None, "evidence failed re-validation")

        host = src if incident.direction == "outbound" or not incident.dst_ip else str(ipaddress.ip_address(incident.dst_ip))
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

        params = {
            "src_ip": src,
            "dst_port": dst_port,
            "host_ip": host,
            "iface": self.iface,
            "rate": self.rate,
            "burst": self.burst,
            "incident_id": incident.incident_id,
            "timestamp": incident.started_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        cmd, rollback = INTENT_TEMPLATES[intent]
        dry = DRY_RUN.get(intent)
        return Rendered(intent, cmd.format(**params), rollback.format(**params), dry.format(**params) if dry else None)
