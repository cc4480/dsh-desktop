"""Plane 7 UI. Reads the incident store only; never runs capture or detection itself.

    NIDS_DASHBOARD_PASSWORD=... streamlit run dashboard/app.py --server.address 127.0.0.1
"""
from __future__ import annotations

import hmac
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nids.anomaly import PSI_DRIFT, PSI_MODERATE  # noqa: E402
from nids.storage import Store  # noqa: E402

DB = Path(os.environ.get("NIDS_DB", ROOT / "data" / "nids.db"))
EVAL_DIR = Path(os.environ.get("NIDS_EVAL_DIR", ROOT / "data" / "eval"))
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


def to_dt(xs) -> pd.Series:
    return pd.to_datetime(pd.Series(xs, dtype=float), unit="s", utc=True)


viewer = gate()
store = Store(DB)


# --------------------------------------------------------------------------- banner
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
    c[4].metric("Anomaly watchlist", stats.get("anomaly_watchlist", 0),
                help="Anomalous flows that did not form or join an incident (≈1% of benign traffic by design).")
    if stats.get("backend", "none") == "none":
        c[5].metric("Narratives", "template", help="No LLM backend configured; deterministic templates only.")
    else:
        c[5].metric("LLM narratives validated", f"{stats.get('narrative_validation_pass', 0)}/{run['incidents']}",
                    help=f"LLM backend: {stats.get('backend')}. Rejected narratives fall back to the template.")

    series = stats.get("series") or {}
    if series.get("t"):
        df = pd.DataFrame({"time": to_dt(series["t"]), "pps": series["pps"]})
        marks = pd.DataFrame([{"time": to_dt([r["incident"]["detected_at"] or r["incident"]["ts_start"]])[0],
                               "incident": f"{r['incident']['severity']}: {r['incident']['attack_type']}",
                               "severity": r["incident"]["severity"]} for r in rows])
        area = alt.Chart(df).mark_area(opacity=0.35, line=True).encode(
            x=alt.X("time:T", title=None), y=alt.Y("pps:Q", title="packets/s", scale=alt.Scale(type="symlog")))
        chart = area
        if not marks.empty:
            rules_ = alt.Chart(marks).mark_rule(strokeWidth=2).encode(
                x="time:T", tooltip=["incident", "time:T"],
                color=alt.Color("severity:N", scale=alt.Scale(domain=list(SEV_COLOUR), range=list(SEV_COLOUR.values())),
                                legend=alt.Legend(orient="top", title=None)))
            chart = area + rules_
        st.altair_chart(chart.properties(height=150), use_container_width=True)
    st.caption(f"Last run {ts(run['started_at'])} on `{Path(run['source']).parent.name}` · vertical lines = "
               f"incident detection time · timings (ms): {stats.get('timing_ms')}")


# --------------------------------------------------------------------------- incidents
def timeline_chart(i: dict) -> None:
    if not i.get("timeline"):
        return
    df = pd.DataFrame(i["timeline"], columns=["t", "pps"])
    df["time"] = to_dt(df["t"])
    band = pd.DataFrame({"start": to_dt([i["ts_start"]]), "end": to_dt([i["ts_end"]])})
    chart = (alt.Chart(band).mark_rect(opacity=0.12, color=SEV_COLOUR[i["severity"]]).encode(x="start:T", x2="end:T")
             + alt.Chart(df).mark_line(color=SEV_COLOUR[i["severity"]]).encode(
                 x=alt.X("time:T", title=None), y=alt.Y("pps:Q", title=f"{i['src_ip']} pkts/s"),
                 tooltip=["time:T", "pps:Q"]))
    if i.get("detected_at"):
        det = pd.DataFrame({"time": to_dt([i["detected_at"]]), "label": ["detected"]})
        chart += alt.Chart(det).mark_rule(strokeDash=[4, 3]).encode(x="time:T", tooltip=["label", "time:T"])
    st.altair_chart(chart.properties(height=160), use_container_width=True)


def decision_badge(incident_id: str) -> str:
    d = store.decisions(incident_id)
    if not d:
        return ""
    last = d[0]
    icon = "✅" if last["decision"] == "approved" else "⛔"
    return f" · {icon} {last['decision']} by {last['viewer']}"


def response_panel(i: dict) -> None:
    iid = i["incident_id"]
    cmd = store.latest_command(iid)
    st.markdown("**Response** (copy only; never auto-executed)")
    if not cmd:
        return
    if not cmd["command"]:
        st.error(f"Policy engine refused intent `{cmd['intent']}`: {cmd['refused_reason']}")
        return
    if not st.toggle("Show command", key=f"show-{iid}"):
        return
    seen = st.session_state.setdefault("viewed", set())
    if iid not in seen:  # one audit row per viewing, not per Streamlit rerun
        store.log_view(iid, viewer)
        seen.add(iid)
    st.code(cmd["command"], language="bash")
    st.caption("Rollback")
    st.code(cmd["rollback"], language="bash")
    if cmd["dry_run"]:
        st.caption("Check first")
        st.code(cmd["dry_run"], language="bash")
    st.caption(f"Rendered by the policy engine from intent `{cmd['intent']}`. Requires human approval.")

    if cmd["intent"] == "no_action":
        return
    with st.form(f"decide-{iid}", clear_on_submit=True):
        note = st.text_input("Note for the audit log (change ticket, reason)", max_chars=500)
        a, b = st.columns(2)
        approve = a.form_submit_button("Approve — I will apply it", type="primary")
        reject = b.form_submit_button("Reject")
    if approve or reject:
        store.record_decision(iid, cmd["id"], "approved" if approve else "rejected", viewer, note)
        st.rerun()
    for d in store.decisions(iid):
        st.caption(f"{ts(d['decided_at'])} · {d['viewer']} **{d['decision']}**" + (f" — {d['note']}" if d["note"] else ""))


def card(r: dict) -> None:
    i, n = r["incident"], r["narrative"]
    colour = SEV_COLOUR[i["severity"]]
    asset = f"{i['asset_name']} (crit {i['asset_criticality']})" if i.get("asset_name") else f"crit {i['asset_criticality']}"
    st.markdown(
        f"<div style='border-left:6px solid {colour};padding:4px 12px;margin:4px 0'>"
        f"<b style='color:{colour}'>{i['severity'].upper()}</b> · <code>{i['incident_id']}</code> · {ts(i['ts_start'])}"
        f"{decision_badge(i['incident_id'])}<br>"
        f"<b>{i['attack_type']}</b> ({i.get('attack_id') or 'no ATT&CK id'}) · "
        f"{i['src_ip']} → {i.get('dst_ip') or 'multiple'} · {asset} · conf {i['confidence']:.2f} · "
        f"{i['flow_count']:,} flows" + (f" · peak {i['peak_pps']:,.0f} pps" if i.get("peak_pps") else "") +
        "</div>",
        unsafe_allow_html=True,  # every interpolated value is typed or sanitised upstream
    )
    with st.expander("Explanation & response"):
        timeline_chart(i)
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
        response_panel(i)
        with st.popover("Raw incident evidence"):
            st.json(i["evidence"])


def incidents_tab() -> None:
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


# --------------------------------------------------------------------------- model health
def psi_chart(values: dict[str, float]) -> pd.DataFrame:
    df = pd.DataFrame({"feature": list(values), "psi": list(values.values())})
    df["status"] = pd.cut(df["psi"], [-1, PSI_MODERATE, PSI_DRIFT, 1e9], labels=["stable", "moderate", "drift"])
    top = max(0.3, float(df["psi"].max()) * 1.05)
    bars = alt.Chart(df).mark_bar().encode(
        y=alt.Y("feature:N", sort="-x", title=None), x=alt.X("psi:Q", title="PSI", scale=alt.Scale(domain=[0, top])),
        color=alt.Color("status:N", scale=alt.Scale(domain=["stable", "moderate", "drift"],
                                                     range=["#43a047", "#f9a825", "#c62828"])),
        tooltip=["feature", alt.Tooltip("psi:Q", format=".4f"), "status"])
    guides = alt.Chart(pd.DataFrame({"x": [PSI_MODERATE, PSI_DRIFT]})).mark_rule(strokeDash=[4, 3]).encode(x="x:Q")
    st.altair_chart((bars + guides).properties(height=24 * len(df)), use_container_width=True)
    return df


def model_tab() -> None:
    run = store.last_run()
    if not run:
        st.info("No runs yet.")
        return
    stats = run["stats"]
    meta = stats.get("model") or {}
    st.subheader("Anomaly model")
    if not meta:
        st.warning("No anomaly model was loaded for the last run (rules only).")
    else:
        c = st.columns(5)
        c[0].metric("Version (sha256)", meta.get("sha256", "?")[:12])
        c[1].metric("Trained", ts(meta["trained_at"])[:10] if meta.get("trained_at") else "?")
        c[2].metric("Training flows", f"{meta.get('n_train', 0):,}")
        c[3].metric("Calibration flows", f"{meta.get('n_calibration', 0):,}")
        c[4].metric("Alert percentile", f"> {meta.get('threshold')}",
                    help="Score = fraction of benign calibration traffic that is less anomalous (frozen ECDF).")
        st.caption(f"Feature registry v{meta.get('feature_registry_version')}: {', '.join(meta.get('feature_names', []))}")

    psi = stats.get("psi") or {}
    if "background" in psi:
        st.subheader("Feature drift (PSI vs. frozen benign reference)")
        bg = psi_chart(psi["background"])
        drifted = bg[bg["status"] == "drift"]["feature"].tolist()
        if drifted:
            st.error(f"Background drift on: {', '.join(drifted)}. Recalibrate or retrain if this persists.")
        else:
            st.caption(f"Background traffic ({psi.get('background_flows', 0):,} flows not in any incident) is stable. "
                       "Dashed lines: 0.10 moderate, 0.25 drift.")
        with st.expander("All traffic, including incidents"):
            psi_chart(psi["all"])
            st.caption("An attack shifts these by itself (a flood is mostly half-open flows), which is why the "
                       "background figure above is the drift signal.")

    st.subheader("Alert rate over time")
    series = stats.get("series") or {}
    if series.get("t"):
        df = pd.DataFrame({"time": to_dt(series["t"]), "anomalous flows": series["anomalies"]})
        st.altair_chart(alt.Chart(df).mark_bar().encode(
            x=alt.X("time:T", title=None),
            y=alt.Y("anomalous flows:Q", scale=alt.Scale(type="symlog"))).properties(height=150),
                        use_container_width=True)
    runs = store.runs()
    if len(runs) > 1:
        st.subheader("Run history")
        st.dataframe(pd.DataFrame([{
            "run": ts(r["started_at"]), "source": Path(r["source"]).parent.name, "flows": r["flows"],
            "alerts": r["alerts"], "incidents": r["incidents"],
            "watchlist": r["stats"].get("anomaly_watchlist"),
            "max background PSI": max(((r["stats"].get("psi") or {}).get("background") or {"-": 0}).values()),
        } for r in runs]), hide_index=True, use_container_width=True)


# --------------------------------------------------------------------------- evaluation
def evaluation_tab() -> None:
    reports = sorted(EVAL_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    if not reports:
        st.info("No evaluation yet. Run `python -m nids evaluate <zeek-log-dir>` on a capture with ground truth.")
        return
    pick = st.selectbox("Report", reports, format_func=lambda p: f"{p.stem}  ({ts(p.stat().st_mtime)})")
    r = json.loads(pick.read_text())
    c = r["capture"]
    st.caption(f"{c['flows']:,} flows over {c['hours'] * 60:.1f} min · {c['episodes']} ground-truth episodes")

    st.subheader("Baselines: does each engine earn its place?")
    rows = []
    for name, m in r["incident_level"].items():
        if "status" in m:
            rows.append({"config": name, "episodes detected": m["status"]})
            continue
        fl = (r.get("flow_level") or {}).get("engines", {}).get(name, {})
        rows.append({
            "config": name,
            "episodes detected": f"{m['episodes_detected']}/{m['episodes']}",
            "false incidents / h": m["false_incidents_per_hour"],
            "incident precision": m["incident_precision"],
            "ATT&CK correct": f"{m['classified_correctly']}/{m['classifiable']}",
            "latency p50 (s)": m["latency_s"]["p50"],
            "latency max (s)": m["latency_s"]["max"],
            "flow precision": fl.get("precision"),
            "flow recall": fl.get("recall"),
            "flow PR-AUC": fl.get("pr_auc"),
        })
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)
    st.caption(f"supervised: {r['supervised']['status']} — {r['supervised']['reason']}")

    ens = r["incident_level"].get("ensemble", {})
    if "per_episode" in ens:
        st.subheader("Ensemble, per episode")
        st.dataframe(pd.DataFrame([{
            "episode": e["attack"], "expect": e["expect"], "detected": "yes" if e["detected"] else "NO",
            "incidents": e["incidents"], "severity": ", ".join(e["severity"]),
            "severity as expected": e["severity_as_expected"], "ATT&CK": ", ".join(e["attack_ids"]),
            "latency (s)": e["latency_s"],
        } for e in ens["per_episode"]]), hide_index=True, use_container_width=True)
        if ens.get("false_incident_examples"):
            st.warning("False incidents: " + "; ".join(
                f"{x['src']} → {x['dst']} ({x['attack_type']}, {x['severity']})" for x in ens["false_incident_examples"]))

    fl = r.get("flow_level")
    if fl:
        st.subheader("Per-episode flow recall by engine")
        df = pd.DataFrame([{"engine": eng, "episode": ep, "recall": v}
                           for eng, m in fl["engines"].items() for ep, v in m["per_episode_recall"].items()])
        base = alt.Chart(df).encode(x=alt.X("episode:N", title=None, axis=alt.Axis(labelAngle=0, orient="top",
                                                                                  labelLimit=200)),
                                    y=alt.Y("engine:N", title=None, sort=["rules", "anomaly", "ensemble"]))
        heat = base.mark_rect().encode(
            color=alt.Color("recall:Q", scale=alt.Scale(domain=[0, 1], scheme="redyellowgreen"), legend=None),
            tooltip=["engine", "episode", "recall"])
        text = base.mark_text(fontWeight="bold").encode(text=alt.Text("recall:Q", format=".2f"))
        st.altair_chart((heat + text).properties(height=44 * df["engine"].nunique()), use_container_width=True)
    st.caption("Latency = first packet of the episode to the first moment the detection logic could fire; "
               "excludes Zeek's own connection-logging delay.")


# --------------------------------------------------------------------------- audit
def audit_tab() -> None:
    rows = store.audit()
    if not rows:
        st.info("No command views or decisions yet.")
        return
    df = pd.DataFrame(rows)
    df["at"] = to_dt(df["at"])
    st.dataframe(df[["at", "viewer", "action", "incident_id", "note"]], hide_index=True, use_container_width=True)
    st.download_button("Download audit log (CSV)", df.to_csv(index=False), "nids-audit.csv", "text/csv")


st.title("NIDS — Incident Triage")
st.caption(f"Signed in as {viewer}. The LLM explains. It never decides, and it never executes.")
banner()
t1, t2, t3, t4 = st.tabs(["Incidents", "Model health", "Evaluation", "Audit"])
with t1:
    incidents_tab()
with t2:
    model_tab()
with t3:
    evaluation_tab()
with t4:
    audit_tab()
