"""Community ID v1 flow hashing (https://github.com/corelight/community-id-spec).

The same 5-tuple hashes to the same ID in Zeek (with the community-id package),
Suricata and Wireshark, so a dashboard incident can be pivoted to the exact packets.
Computed here when the sensor did not add it.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import struct

PROTO = {"icmp": 1, "tcp": 6, "udp": 17, "icmp6": 58, "sctp": 132}


def community_id(src: str, sport: int, dst: str, dport: int, proto: str, seed: int = 0) -> str | None:
    p = PROTO.get(proto.lower())
    if p is None:
        return None
    a, b = ipaddress.ip_address(src).packed, ipaddress.ip_address(dst).packed
    # Order the endpoints so both directions of a flow hash identically.
    if (a, sport) > (b, dport):
        a, b, sport, dport = b, a, dport, sport
    blob = struct.pack("!H", seed) + a + b + struct.pack("!BB", p, 0) + struct.pack("!HH", sport, dport)
    digest = hashlib.sha1(blob, usedforsecurity=False).digest()  # SHA-1 is fixed by the Community ID spec
    return "1:" + base64.b64encode(digest).decode()
