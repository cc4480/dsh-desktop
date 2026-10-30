"""Plane 0: asset registry lookups."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from nids.sensing.sanitize import hostlike


@dataclass(frozen=True)
class Asset:
    ip: str
    name: str
    service: str
    owner: str
    criticality: int
    internet_facing: bool
    environment: str


@dataclass
class AssetRegistry:
    assets: dict[str, Asset] = field(default_factory=dict)
    internal_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = field(default_factory=list)
    known_scanners: set[str] = field(default_factory=set)
    protected_ips: set[str] = field(default_factory=set)
    critical_service_ports: set[int] = field(default_factory=set)
    default_criticality: int = 2

    @classmethod
    def load(cls, path: str | Path) -> AssetRegistry:
        raw = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        assets = {}
        for a in raw.get("assets", []):
            ip = str(ipaddress.ip_address(a["ip"]))
            assets[ip] = Asset(
                ip=ip,
                name=hostlike(a["name"]),
                service=hostlike(a.get("service", "")),
                owner=hostlike(a.get("owner", "")),
                criticality=int(a.get("criticality", 2)),
                internet_facing=bool(a.get("internet_facing", False)),
                environment=hostlike(a.get("environment", "")),
            )
        return cls(
            assets=assets,
            internal_networks=[ipaddress.ip_network(n) for n in raw.get("internal_networks", [])],
            known_scanners={str(ipaddress.ip_address(i)) for i in raw.get("known_scanners", [])},
            protected_ips={str(ipaddress.ip_address(i)) for i in raw.get("protected_ips", [])},
            critical_service_ports={int(p) for p in raw.get("critical_service_ports", [])},
            default_criticality=int(raw.get("default_criticality", 2)),
        )

    def get(self, ip: str | None) -> Asset | None:
        return self.assets.get(ip) if ip else None

    def is_internal(self, ip: str | None) -> bool:
        if not ip:
            return False
        addr = ipaddress.ip_address(ip)
        return any(addr in net for net in self.internal_networks)

    def direction(self, src: str, dst: str | None) -> str:
        si, di = self.is_internal(src), self.is_internal(dst)
        if si and di:
            return "internal"
        if si:
            return "outbound"
        if di:
            return "inbound"
        return "external"
