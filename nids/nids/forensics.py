"""Forensic retrieval: from a dashboard incident to its packets (tshark/tcpdump as responders,
never on the hot path).

Each incident carries a BPF filter, a time range and a sample of Community IDs. The same
Community ID appears in Zeek (with the community-id package), Suricata and Wireshark, so
one value pivots across tools. Filters are built only from re-validated IPs and ints.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from nids.models import Flow, Incident

PAD = 5.0


def _ip(v: str | None) -> str | None:
    return str(ipaddress.ip_address(v)) if v else None


def build(incident: Incident, flows: Sequence[Flow], uids: set[str], sample: int = 10) -> dict:
    src, dst = _ip(incident.src_ip), _ip(incident.dst_ip)
    port = incident.evidence.get("dst_port")
    bpf = f"host {src}" + (f" and host {dst}" if dst else "") + (f" and port {int(port)}" if port else "")
    fam = "ipv6" if ipaddress.ip_address(src).version == 6 else "ip"
    display = f"{fam}.addr == {src}" + (f" && {fam}.addr == {dst}" if dst else "")
    if port:
        display += f" && (tcp.port == {int(port)} || udp.port == {int(port)})"
    start, end = incident.ts_start - PAD, incident.ts_end + PAD
    display_timed = f"{display} && frame.time_epoch >= {start:.3f} && frame.time_epoch <= {end:.3f}"
    cids = []
    for f in flows:
        if f.uid in uids and f.community_id and f.community_id not in cids:
            cids.append(f.community_id)
            if len(cids) >= sample:
                break
    return {"bpf": bpf, "display_filter": display_timed, "start": round(start, 3), "end": round(end, 3),
            "community_ids": cids}


def commands(forensics: dict, pcap: str = "capture.pcap", out: str = "incident.pcap") -> dict[str, str]:
    cmds = {
        "tshark": f"tshark -r {pcap} -2 -R '{forensics['display_filter']}' -w {out}",
        "tcpdump": f"tcpdump -r {pcap} -w {out} '{forensics['bpf']}'   # no time filter",
    }
    if forensics.get("community_ids"):
        cid = forensics["community_ids"][0]
        cmds["community_id"] = f"tshark -r {pcap} --enable-protocol communityid -Y 'communityid == \"{cid}\"'"
    return cmds


def extract(forensics: dict, pcap: Path, out: Path) -> tuple[bool, str]:
    """Cut the incident's packets out of a capture. Returns (ok, message)."""
    if not pcap.exists():
        return False, f"no capture at {pcap}"
    if shutil.which("tshark"):
        argv = ["tshark", "-r", str(pcap), "-2", "-R", forensics["display_filter"], "-w", str(out)]
    elif shutil.which("tcpdump"):
        argv = ["tcpdump", "-r", str(pcap), "-w", str(out), forensics["bpf"]]
    else:
        return False, "neither tshark nor tcpdump is installed; run one of:\n" + "\n".join(
            commands(forensics, str(pcap), str(out)).values())
    proc = subprocess.run(argv, capture_output=True, text=True, timeout=300)  # no shell, fixed argv
    if proc.returncode != 0:
        return False, proc.stderr.strip()[-500:]
    return True, f"wrote {out} ({'time-bounded' if argv[0] == 'tshark' else 'whole capture, BPF only'})"
