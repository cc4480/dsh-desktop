"""Plane 2: behavioural baseline profile, learned from benign Zeek logs.

What a point-wise anomaly score cannot see, a per-host memory can: "this host has
never talked to that destination", "this host never sends this much", "this TLS client
fingerprint has never been seen here". Rules consume these as ordinary window features
(new_dst_ratio, bytes_out_vs_baseline, new_fingerprint_ratio). A rule that needs a profile
feature simply never fires when no profile is loaded.
"""
from __future__ import annotations

import json
import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from nids.sensing.zeek import LogBundle

BYTES_FLOOR = 10_000_000  # never treat "10 MB per hour" as abnormal, however quiet a host is
VOLUME_WINDOW = 3600.0


@dataclass
class Profile:
    known_dsts: dict[str, set[str]] = field(default_factory=dict)  # src -> destinations seen
    hourly_bytes_out: dict[str, float] = field(default_factory=dict)  # src -> max bytes sent per hour
    ja4_seen: set[str] = field(default_factory=set)
    built_at: float = 0.0
    baseline_hours: float = 0.0
    n_flows: int = 0

    # ------------------------------------------------------------ lookups
    def is_new_dst(self, src: str, dst: str) -> bool:
        return dst not in self.known_dsts.get(src, set())

    def bytes_baseline(self, src: str) -> float:
        return max(self.hourly_bytes_out.get(src, 0.0), BYTES_FLOOR)

    def is_new_fingerprint(self, ja4: str) -> bool | None:
        """Has this TLS client (JA4) fingerprint been seen in the baseline?

        JA4 only. JA3 is not used: its upstream is archived, and it hashes the client's
        extension order, which Chrome (since version 110) randomises per connection, so
        "unseen JA3" fires on ordinary browsing. JA4 sorts the extensions first.

        None means "cannot say": the sensor computes no JA4, or the baseline was captured
        without one (so every live fingerprint would look new).
        """
        if not ja4 or not self.ja4_seen:
            return None
        return ja4 not in self.ja4_seen

    # ------------------------------------------------------------ persistence
    def save(self, path: str | Path) -> None:
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({
            "known_dsts": {k: sorted(v) for k, v in self.known_dsts.items()},
            "hourly_bytes_out": self.hourly_bytes_out,
            "ja4_seen": sorted(self.ja4_seen),
            "built_at": self.built_at,
            "baseline_hours": self.baseline_hours,
            "n_flows": self.n_flows,
        }, indent=1), encoding="utf-8")

    @staticmethod
    def load(path: str | Path) -> "Profile":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return Profile(
            known_dsts={k: set(v) for k, v in raw["known_dsts"].items()},
            hourly_bytes_out={k: float(v) for k, v in raw["hourly_bytes_out"].items()},
            ja4_seen=set(raw.get("ja4_seen", [])),
            built_at=raw.get("built_at", 0.0),
            baseline_hours=raw.get("baseline_hours", 0.0),
            n_flows=raw.get("n_flows", 0),
        )

    def summary(self) -> dict:
        return {"hosts": len(self.known_dsts), "destinations": len(set().union(*self.known_dsts.values()))
                if self.known_dsts else 0, "ja4": len(self.ja4_seen),
                "baseline_hours": round(self.baseline_hours, 2), "built_at": self.built_at}


def build(bundle: LogBundle) -> Profile:
    p = Profile(built_at=time.time(), n_flows=len(bundle.flows))
    dsts: dict[str, set[str]] = defaultdict(set)
    per_hour: dict[tuple[str, int], float] = defaultdict(float)
    for f in bundle.flows:
        dsts[f.src_ip].add(f.dst_ip)
        per_hour[(f.src_ip, math.floor(f.ts / VOLUME_WINDOW))] += f.orig_bytes
    p.known_dsts = dict(dsts)
    for (src, _), b in per_hour.items():
        p.hourly_bytes_out[src] = max(p.hourly_bytes_out.get(src, 0.0), b)
    for t in bundle.tls:
        if t.ja4:
            p.ja4_seen.add(t.ja4)
    if bundle.flows:
        p.baseline_hours = (bundle.flows[-1].ts - bundle.flows[0].ts) / 3600
    return p
