"""Plane 7 UI. Reads the incident store only; never runs capture or detection itself.

    NIDS_DASHBOARD_PASSWORD=... streamlit run dashboard/app.py --server.address 127.0.0.1
"""
from __future__ import annotations

import hmac
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nids.storage import Store  # noqa: E402

DB = Path(os.environ.get("NIDS_DB", ROOT / "data" / "nids.db"))
RUNBOOKS = ROOT / "runbooks"
SEV_COLOUR = {"critical": "#c62828", "high": "#ef6c00", "medium": "#f9a825", "low": "#1e88e5",
              "informational": "#78909c"}
SEV_RANK = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "informational"])}

st.set_page_config(page_title="NIDS Incident Triage", layout="wide")


def gate() -> str:
    """Minimal password gate. Production needs SSO + RBAC; see README."""
    expected = os.environ.get("NIDS_DASHBOARD_PASSWORD") or (st.secrets.get("password") if _has_secrets() else None)
    if not expected:
        st.error("Set NIDS_DASHBOARD_PASSWORD (or `password` in .streamlit/secrets.toml) to open the dashboard.")
        st.stop()
    if st.session_state.get("authed"):
        return st.session_state["viewer"]
    with st.form("login"):
        viewer = st.text_input("Analyst name")
        pw = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in"):
            if viewer.strip() and hmac.compare_digest(pw.encode(), expected.encode()):
                st.session_state.update(authed=True, viewer=viewer.strip()[:40])
                st.rerun()
            st.error("Invalid credentials")
    st.stop()


def _has_secrets() -> bool:
    try:
        return bool(st.secrets)
    except Exception:
        return False


def ts(x: float) -> str:
    return datetime.fromtimestamp(x, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


viewer = gate()
store = Store(DB)


@st.fragment(run_every=5)
def banner() -> None:
    run = store.last_run()
    if not run:
        st.info("No pipeline run yet. Run `python -m nids run <zeek-log-dir>`.")
        return
    stats = run["stats"]
    rows = store.incidents()
    open_crit = sum(r["incident"]["severity"] in ("critical", "high") for r in rows)
    c = st.columns(6)
    c[0].metric("Mean pps", f"{stats.get('mean_pps', 0):,.0f}")
    c[1].metric("Flows", f"{run['flows']:,}")
    c[2].metric("Alerts → incidents", f"{run['alerts']:,} → {run['incidents']}")
    c[3].metric("Critical / high", open_crit)
    c[4].metric("Anomaly watchlist", stats.get("anomaly_watchlist", 0))
    if stats.get("backend", "none") == "none":
        c[5].metric("Narratives", "template", help="No LLM backend configured; deterministic templates only.")
    else:
        c[5].metric("LLM narratives validated", f"{stats.get('narrative_validation_pass', 0)}/{run['incidents']}",
                    help=f"LLM backend: {stats.get('backend')}. Rejected narratives fall back to the template.")
    st.caption(f"Last run {ts(run['started_at'])} on `{Path(run['source']).parent.name}` · "
               f"timings (ms): {stats.get('timing_ms')}")


def card(r: dict) -> None:
    i, n = r["incident"], r["narrative"]
    colour = SEV_COLOUR[i["severity"]]
    asset = f"{i['asset_name']} (crit {i['asset_criticality']})" if i.get("asset_name") else f"crit {i['asset_criticality']}"
    st.markdown(
        f"<div style='border-left:6px solid {colour};padding:4px 12px;margin:4px 0'>"
        f"<b style='color:{colour}'>{i['severity'].upper()}</b> · <code>{i['incident_id']}</code> · {ts(i['ts_start'])}<br>"
        f"<b>{i['attack_type']}</b> ({i.get('attack_id') or 'no ATT&CK id'}) · "
        f"{i['src_ip']} → {i.get('dst_ip') or 'multiple'} · {asset} · conf {i['confidence']:.2f} · "
        f"{i['flow_count']:,} flows" + (f" · peak {i['peak_pps']:,.0f} pps" if i.get("peak_pps") else "") +
        "</div>",
        unsafe_allow_html=True,  # every interpolated value is typed or sanitised upstream
    )
    with st.expander("Explanation & response"):
        if n:
            badge = "✅ grounded (validator passed)" if r["validation_passed"] else (
                "🧾 deterministic template" + (f" — LLM output rejected: {', '.join(r['validation_reasons'])}"
                                              if r["narrative_source"] == "template" and r["validation_reasons"]
                                              and r["validation_reasons"] != ["no LLM backend configured"] else ""))
            st.caption(badge)
            st.write(n["summary"])
            st.markdown("**Grounded evidence**")
            st.code("\n".join(n["technical_evidence"]), language="text")
            if n.get("confidence_note"):
                st.caption(n["confidence_note"])
            if n.get("data_quality_flags"):
                st.warning("Data quality flags: " + "; ".join(n["data_quality_flags"]))
        st.markdown("**Why this severity**")
        st.write(" · ".join(i["severity_reasons"]))
        for rid in i.get("rule_ids") or ["ANOMALY"]:
            rb = RUNBOOKS / f"{rid}.md"
            if rb.exists():
                with st.popover(f"Runbook: {rid}"):
                    st.markdown(rb.read_text(encoding="utf-8"))

        cmd = store.latest_command(i["incident_id"])
        st.markdown("**Response** (copy only; never auto-executed)")
        if cmd and cmd["command"]:
            if st.toggle("Show command", key=f"show-{i['incident_id']}"):
                store.log_view(i["incident_id"], viewer)
                st.code(cmd["command"], language="bash")
                st.caption("Rollback")
                st.code(cmd["rollback"], language="bash")
                if cmd["dry_run"]:
                    st.caption("Check first")
                    st.code(cmd["dry_run"], language="bash")
                st.caption(f"Rendered by the policy engine from intent `{cmd['intent']}`. Requires human approval.")
        elif cmd:
            st.error(f"Policy engine refused intent `{cmd['intent']}`: {cmd['refused_reason']}")
        with st.popover("Raw incident evidence"):
            st.json(i["evidence"])


st.title("NIDS — Incident Triage")
st.caption(f"Signed in as {viewer}. The LLM explains. It never decides, and it never executes.")
banner()

rows = store.incidents()
c1, c2, c3 = st.columns([2, 2, 3])
sev = c1.multiselect("Severity", list(SEV_COLOUR), default=[s for s in SEV_COLOUR if s != "informational"])
types = sorted({r["incident"]["attack_type"] for r in rows})
kind = c2.multiselect("Attack type", types, default=types)
q = c3.text_input("Search IP / asset / incident id")

shown = [
    r for r in rows
    if r["incident"]["severity"] in sev and r["incident"]["attack_type"] in kind
    and (not q or q in " ".join(str(v) for v in (r["incident"]["incident_id"], r["incident"]["src_ip"],
                                                 r["incident"].get("dst_ip"), r["incident"].get("asset_name"))))
]
shown.sort(key=lambda r: (SEV_RANK[r["incident"]["severity"]], -r["incident"]["ts_start"]))
st.subheader(f"Incidents ({len(shown)} of {len(rows)})")
for r in shown:
    card(r)
