"""Deterministic fallback narrative (ablation arm B, and what the UI shows when the LLM
is unavailable or its output fails validation)."""
from __future__ import annotations

from nids.models import Incident, Narrative

_LEADS = {
    "SYN_FLOOD": "{src} is sending a TCP SYN flood at {target} (~{pps} packets/s) without completing handshakes.",
    "HORIZONTAL_PORT_SCAN": "{src} probed {ports} distinct ports on {target}; nearly all connection attempts failed.",
    "HOST_SWEEP": "{src} probed {ips} hosts on port {port}; nearly all connection attempts failed.",
    "DNS_TUNNELING": "{src} issued {queries} DNS queries with long, mostly unique labels, consistent with data tunnelled over DNS.",
    "BEACONING": "{src} contacts {target} on port {port} at a near-constant interval of ~{iat}s, consistent with C2 beaconing.",
    "BRUTE_FORCE": "{src} opened {flows} short login sessions to {target} on port {port}, consistent with password guessing.",
    "ZEEK_SSH_PASSWORD_GUESSING": "Zeek's SSH detector flagged {src} for password guessing against {target}.",
    "HTTP_WORDLIST_SCAN": "{src} requested {uris} distinct paths on {target}, most returning 404, consistent with a wordlist scan.",
    "SCANNER_USER_AGENT": "{src} sent {requests} HTTP requests to {target} identifying as a known scanning tool.",
    "SELF_SIGNED_TLS_REPEATED": "{src} repeatedly opened TLS sessions to {target} on port {port} that present a self-signed certificate.",
    "NEW_TLS_FINGERPRINT": "{src} opened TLS sessions to {target} with a client fingerprint never seen in the baseline.",
    "NEW_DESTINATION_BULK_UPLOAD": "{src} sent {mb} MB to {target}, a destination it never contacted in the baseline (~{ratio}x its normal hourly volume).",
    "": "{src} produced traffic to {target} that is more anomalous than {pct} of baseline traffic ({mb} MB sent).",
}

_CITE_ORDER = ["rule_match", "packets_per_second", "syn_ratio", "s0_ratio", "failed_conn_ratio",
               "distinct_dst_ports", "distinct_dst_ips", "mean_label_length", "unique_subdomain_ratio",
               "iat_mean", "iat_cv", "handshake_ratio", "mean_duration", "request_count", "not_found_ratio",
               "distinct_uri_count", "scanner_ua_ratio", "session_count", "self_signed_ratio", "new_fingerprint_ratio",
               "new_dst_ratio", "bytes_out_vs_baseline", "notice_count", "bytes_out", "anomaly_score",
               "supervised_probability", "flow_count"]


def render(incident: Incident, intent: str) -> Narrative:
    e = incident.evidence
    outbound = incident.direction == "outbound" or not incident.dst_ip
    src = f"{incident.asset_name} ({incident.src_ip})" if outbound and incident.asset_name else incident.src_ip
    target = (f"{incident.asset_name} ({incident.dst_ip})" if incident.asset_name and not outbound
              else incident.dst_ip or "multiple hosts")
    rule = incident.rule_ids[0] if incident.rule_ids else ""
    lead = _LEADS.get(rule, _LEADS[""])
    text = lead.format(
        src=src, target=target, pps=e.get("packets_per_second", "?"),
        ports=e.get("distinct_dst_ports", "?"), ips=e.get("distinct_dst_ips", "?"), port=e.get("dst_port", "?"),
        queries=e.get("query_count", "?"), iat=e.get("iat_mean", "?"),
        pct=f"{float(e.get('anomaly_score', 0)) * 100:.1f}%", mb=f"{float(e.get('bytes_out', 0)) / 1e6:,.0f}",
        flows=e.get("flow_count", "?"), uris=e.get("distinct_uri_count", "?"), requests=e.get("request_count", "?"),
        ratio=f"{float(e.get('bytes_out_vs_baseline', 0)):,.0f}",
    )
    summary = (
        f"{text} Classified as {incident.attack_type} ({incident.attack_id or 'no ATT&CK mapping'}) "
        f"with confidence {incident.confidence:.2f}; severity {incident.severity} because "
        f"{incident.severity_reasons[0] if incident.severity_reasons else 'of the severity table'}."
    )
    cites = [f"{k}={e[k]}" for k in _CITE_ORDER if k in e][:6]
    assets = [src if outbound else target] if incident.asset_name or not outbound else []
    return Narrative(
        summary=summary,
        attack_type=incident.attack_type,
        severity_level=incident.severity,
        affected_assets=assets,
        technical_evidence=cites,
        confidence_note="Deterministic template; no language model involved.",
        remediation_intent=intent,  # type: ignore[arg-type]
        data_quality_flags=[],
    )
