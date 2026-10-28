"""Plane 7 UI. Reads the incident store only; never runs capture or detection itself.

    python -m nids add-user alice --role approver      # per-user logins (recommended)
    streamlit run dashboard/app.py                     # binds 127.0.0.1 (.streamlit/config.toml)

Without config/users.yaml it falls back to one shared password (NIDS_DASHBOARD_PASSWORD),
which gives no per-person accountability and says so on screen.
"""
from __future__ import annotations

import hmac
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import altair as alt
import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from nids import auth, forensics, study  # noqa: E402
from nids.anomaly import PSI_DRIFT, PSI_MODERATE  # noqa: E402
from nids.rules import load_rules  # noqa: E402
from nids.storage import Store  # noqa: E402

DB = Path(os.environ.get("NIDS_DB", ROOT / "data" / "nids.db"))
EVAL_DIR = Path(os.environ.get("NIDS_EVAL_DIR", ROOT / "data" / "eval"))
USERS = Path(os.environ.get("NIDS_USERS", auth.USERS_PATH))
RUNBOOKS = ROOT / "runbooks"
SEV_COLOUR = {"critical": "#c62828", "high": "#ef6c00", "medium": "#f9a825", "low": "#1e88e5",
              "informational": "#78909c"}
SEV_RANK = {s: i for i, s in enumerate(["critical", "high", "medium", "low", "informational"])}
STATUS_ICON = {"open": "🔴 open", "acknowledged": "🟡 acknowledged", "closed": "⚪ closed"}

st.set_page_config(page_title="NIDS Incident Triage", layout="wide")


# --------------------------------------------------------------------------- auth
def _has_secrets() -> bool:
    try:
        return bool(st.secrets)
    except Exception:
        return False


def gate() -> tuple[str, str]:
    """Returns (viewer, role). Per-user accounts if config/users.yaml exists."""
    if st.session_state.get("authed"):
        return st.session_state["viewer"], st.session_state["role"]
    users = auth.load_users(USERS)
    shared = os.environ.get("NIDS_DASHBOARD_PASSWORD") or (st.secrets.get("password") if _has_secrets() else None)
    if not users and not shared:
        st.error("No logins configured. Run `python -m nids add-user <name> --role approver`, "
                 "or set NIDS_DASHBOARD_PASSWORD for a shared demo password.")
        st.stop()
    with st.form("login"):
        viewer = st.text_input("Name" if users else "Analyst name")
        pw = st.text_input("Password", type="password")
        if st.form_submit_button("Sign in"):
            viewer = viewer.strip()[:40]
            role = None
            if users:
                role = auth.authenticate(viewer, pw, USERS)
            elif viewer and hmac.compare_digest(pw.encode(), str(shared).encode()):
                role = "approver"
            if role:
                st.session_state.update(authed=True, viewer=viewer, role=role, shared=not users)
                st.rerun()
            time.sleep(1)  # slow down guessing
            st.error("Invalid credentials")
    st.stop()


def ts(x: float) -> str:
    return datetime.fromtimestamp(x, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def to_dt(xs) -> pd.Series:
    return pd.to_datetime(pd.Series(xs, dtype=float), unit="s", utc=True)


viewer, role = gate()
store = Store(DB)


@st.cache_data(ttl=60)
def allowed_by_type() -> dict[str, list[str]]:
    try:
        return {r.attack_type: r.allowed_intents for r in load_rules(ROOT / "config" / "rules.yaml")}
    except Exception:
        return {}


# --------------------------------------------------------------------------- banner
@st.fragment(run_every=5)
def banner() -> None:
    run = store.last_run()
    if not run:
        st.info("No pipeline run yet. Run `python -m nids run <zeek-log-dir>` or `python -m nids watch <dir>`.")
        return
    stats = run["stats"]
    rows = store.incidents()
    active = [r for r in rows if r["status"] != "closed"]
    c = st.columns(7)
    c[0].metric("Mean pps", f"{stats.get('mean_pps', 0):,.0f}")
    c[1].metric("Flows", f"{run['flows']:,}")
    c[2].metric("Incidents", run["incidents"], help=f"Correlated from {run['alerts']:,} alerts")
    c[3].metric("Open critical / high", sum(r["incident"]["severity"] in ("critical", "high") for r in active))
    c[4].metric("Anomaly watchlist", stats.get("anomaly_watchlist", 0),
                help="Anomalous flows that did not form or join an incident (≈1% of benign traffic by design).")
    sensor = stats.get("sensor") or {}
    loss = sensor.get("capture_loss_pct")
    c[5].metric("Capture loss", "n/a" if loss is None else f"{loss:.2f}%",
                help="From Zeek's capture_loss.log. Above ~1% the sensor is missing traffic.")
    if stats.get("backend", "none") == "none":
        c[6].metric("Narratives", "template", help="No LLM backend configured; deterministic templates only.")
    else:
        lat = stats.get("narrative_latency_ms") or {}
        c[6].metric("LLM narratives validated", f"{stats.get('narrative_validation_pass', 0)}/{run['incidents']}",
                    help=f"Backend {stats.get('backend')}; latency p50 {lat.get('p50')} ms, p99 {lat.get('p99')} ms. "
                         "Rejected narratives fall back to the template.")

    warnings = []
    if loss is not None and loss > 1:
        warnings.append(f"Sensor capture loss {loss:.2f}%: detections may be incomplete.")
    if stats.get("inactive_rules"):
        warnings.append(f"Rules that cannot fire (no behavioural profile): {', '.join(stats['inactive_rules'])}. "
                        "Run `python -m nids train <baseline-logs>`.")
    for w in warnings:
        st.warning(w)

    series = stats.get("series") or {}
    if series.get("t"):
        df = pd.DataFrame({"time": to_dt(series["t"]), "pps": series["pps"]})
        marks = pd.DataFrame([{"time": to_dt([r["incident"]["detected_at"] or r["incident"]["ts_start"]])[0],
                               "incident": f"{r['incident']['severity']}: {r['incident']['attack_type']}",
                               "severity": r["incident"]["severity"]} for r in rows])
        chart = alt.Chart(df).mark_area(opacity=0.35, line=True).encode(
            x=alt.X("time:T", title=None), y=alt.Y("pps:Q", title="packets/s", scale=alt.Scale(type="symlog")))
        if not marks.empty:
            chart += alt.Chart(marks).mark_rule(strokeWidth=2).encode(
                x="time:T", tooltip=["incident", "time:T"],
                color=alt.Color("severity:N", scale=alt.Scale(domain=list(SEV_COLOUR), range=list(SEV_COLOUR.values())),
                                legend=alt.Legend(orient="top", title=None)))
        st.altair_chart(chart.properties(height=150), use_container_width=True)
    live = (f"**LIVE** · pass {stats['passes']} · log time {ts(stats['log_time'])} · " if stats.get("live") else "")
    st.caption(f"{live}Last update {ts(run['started_at'])} on `{Path(run['source']).parent.name}` · "
               f"engines {stats.get('engines', {})} · vertical lines = incident detection time")


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
    return f" · {'✅' if last['decision'] == 'approved' else '⛔'} {last['decision']} by {last['viewer']}"


def status_controls(iid: str, status: str) -> None:
    targets = [s for s in ("acknowledged", "closed", "open") if s != status]
    cols = st.columns([1] * len(targets) + [5])
    labels = {"acknowledged": "Acknowledge", "closed": "Close", "open": "Reopen"}
    for col, target in zip(cols, targets):
        if col.button(labels[target], key=f"st-{iid}-{target}"):
            store.set_status(iid, target, viewer)
            st.rerun()


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
    if cmd["intent"] != "no_action":
        if auth.can(role, "approve"):
            with st.form(f"decide-{iid}", clear_on_submit=True):
                note = st.text_input("Note for the audit log (change ticket, reason)", max_chars=500)
                a, b = st.columns(2)
                approve = a.form_submit_button("Approve — I will apply it", type="primary")
                reject = b.form_submit_button("Reject")
            if approve or reject:
                store.record_decision(iid, cmd["id"], "approved" if approve else "rejected", viewer, note)
                st.rerun()
        else:
            st.info("Approving a command needs the approver role.")
    for d in store.decisions(iid):
        st.caption(f"{ts(d['decided_at'])} · {d['viewer']} **{d['decision']}**" + (f" — {d['note']}" if d["note"] else ""))


def forensics_panel(i: dict) -> None:
    f = i.get("forensics") or {}
    if not f:
        return
    with st.popover("Forensics: get the packets"):
        st.caption(f"Window {ts(f['start'])} → {ts(f['end'])}")
        st.markdown("BPF filter")
        st.code(f["bpf"], language="text")
        cmds = forensics.commands(f)
        st.markdown("Extract from the sensor's capture")
        st.code(f"python -m nids pcap {i['incident_id']} --pcap capture.pcap", language="bash")
        for name, c in cmds.items():
            st.caption(name)
            st.code(c, language="bash")
        if f.get("community_ids"):
            st.markdown("Community IDs (same value in Zeek, Suricata, Wireshark)")
            st.code("\n".join(f["community_ids"]), language="text")


def card(r: dict) -> None:
    i, n = r["incident"], r["narrative"]
    colour = SEV_COLOUR[i["severity"]]
    asset = f"{i['asset_name']} (crit {i['asset_criticality']})" if i.get("asset_name") else f"crit {i['asset_criticality']}"
    camp = f" · 🔗 {i['campaign_id']}" if i.get("campaign_id") else ""
    st.markdown(
        f"<div style='border-left:6px solid {colour};padding:4px 12px;margin:4px 0;"
        f"opacity:{0.55 if r['status'] == 'closed' else 1}'>"
        f"<b style='color:{colour}'>{i['severity'].upper()}</b> · {STATUS_ICON[r['status']]} · "
        f"<code>{i['incident_id']}</code> · {ts(i['ts_start'])}{camp}{decision_badge(i['incident_id'])}<br>"
        f"<b>{i['attack_type']}</b> ({i.get('attack_id') or 'no ATT&CK id'}) · "
        f"{i['src_ip']} → {i.get('dst_ip') or 'multiple'} · {asset} · conf {i['confidence']:.2f} · "
        f"{i['flow_count']:,} flows" + (f" · peak {i['peak_pps']:,.0f} pps" if i.get("peak_pps") else "") +
        "</div>",
        unsafe_allow_html=True,  # every interpolated value is typed or sanitised upstream
    )
    with st.expander("Explanation & response"):
        status_controls(i["incident_id"], r["status"])
        timeline_chart(i)
        if n:
            badge = "✅ grounded (validator passed)" if r["validation_passed"] else (
                "🧾 deterministic template" + (f" — LLM output rejected: {', '.join(r['validation_reasons'])}"
                                              if r["narrative_source"] == "template" and r["validation_reasons"]
                                              and r["validation_reasons"] != ["no LLM backend configured"] else ""))
            st.caption(badge + (f" · {r['latency_ms']:.0f} ms" if r.get("latency_ms") else ""))
            st.write(n["summary"])
            st.markdown("**Grounded evidence**")
            st.code("\n".join(n["technical_evidence"]), language="text")
            if n.get("confidence_note"):
                st.caption(n["confidence_note"])
            if n.get("data_quality_flags"):
                st.warning("Data quality flags: " + "; ".join(n["data_quality_flags"]))
        st.markdown("**Why this severity**")
        st.write(" · ".join(i["severity_reasons"]))
        cols = st.columns(4)
        k = 0
        for rid in i.get("rule_ids") or ["ANOMALY"]:
            rb = RUNBOOKS / f"{rid}.md"
            if rb.exists():
                with cols[k % 4].popover(f"Runbook: {rid}"):
                    st.markdown(rb.read_text(encoding="utf-8"))
                k += 1
        response_panel(i)
        c1, c2 = st.columns(2)
        with c1:
            forensics_panel(i)
        with c2.popover("Raw incident evidence"):
            st.json(i["evidence"])


def incidents_tab() -> None:
    rows = store.incidents()
    c1, c2, c3, c4 = st.columns([2, 2, 2, 3])
    sev = c1.multiselect("Severity", list(SEV_COLOUR), default=[s for s in SEV_COLOUR if s != "informational"])
    statuses = c2.multiselect("Status", list(STATUS_ICON), default=["open", "acknowledged"])
    types = sorted({r["incident"]["attack_type"] for r in rows})
    kind = c3.multiselect("Attack type", types, default=types)
    q = c4.text_input("Search IP / asset / incident / campaign id")
    shown = [
        r for r in rows
        if r["incident"]["severity"] in sev and r["status"] in statuses and r["incident"]["attack_type"] in kind
        and (not q or q in " ".join(str(v) for v in (
            r["incident"]["incident_id"], r["incident"]["src_ip"], r["incident"].get("dst_ip"),
            r["incident"].get("asset_name"), r["incident"].get("campaign_id"))))
    ]
    shown.sort(key=lambda r: (SEV_RANK[r["incident"]["severity"]], -r["incident"]["ts_start"]))
    campaigns: dict[str, list[dict]] = {}
    for r in rows:
        if r["incident"].get("campaign_id"):
            campaigns.setdefault(r["incident"]["campaign_id"], []).append(r["incident"])
    if campaigns:
        with st.expander(f"🔗 {len(campaigns)} multi-stage campaign(s)", expanded=True):
            for cid, incs in campaigns.items():
                incs.sort(key=lambda x: x["ts_start"])
                st.markdown(f"**{cid}** · source `{incs[0]['src_ip']}` · " +
                            " → ".join(f"{x['attack_type']} ({x['severity']})" for x in incs))
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
    st.subheader("Engines")
    st.dataframe(pd.DataFrame([{"engine": k, "status": v} for k, v in (stats.get("engines") or {}).items()]),
                 hide_index=True)
    meta = stats.get("model") or {}
    if meta:
        st.subheader("Anomaly model (Isolation Forest + autoencoder)")
        c = st.columns(5)
        c[0].metric("Version (sha256)", meta.get("sha256", "?")[:12])
        c[1].metric("Trained", ts(meta["trained_at"])[:10] if meta.get("trained_at") else "?")
        c[2].metric("Training flows", f"{meta.get('n_train', 0):,}",
                    help=f"{meta.get('n_cleaned', 0):,} removed by majority-vote cleaning (rule hits + top-1% votes)")
        c[3].metric("Calibration flows", f"{meta.get('n_calibration', 0):,}")
        c[4].metric("Alert percentile", f"> {meta.get('threshold')}",
                    help="Score = fraction of benign calibration traffic that is less anomalous (frozen ECDF).")
        st.caption(f"Combination: {meta.get('combination', 'isolation forest only')} · hours with their own "
                   f"calibration (UTC): {meta.get('hours_calibrated', [])} · feature registry "
                   f"v{meta.get('feature_registry_version')}: {', '.join(meta.get('feature_names', []))}")
    prof = stats.get("profile") or {}
    if prof:
        st.subheader("Behavioural profile")
        c = st.columns(4)
        c[0].metric("Hosts", prof.get("hosts", 0))
        c[1].metric("Known destinations", prof.get("destinations", 0))
        c[2].metric("TLS client fingerprints (JA4)", prof.get("ja4", 0),
                    help="0 means the sensor does not compute JA4: use the lab sensor image (lab/sensor).")
        c[3].metric("Baseline hours", prof.get("baseline_hours", 0))
    sup = stats.get("supervised") or {}
    if sup:
        st.subheader("Supervised model (CIC-IDS2017, Zeek-compatible features, Friday test day)")
        c = st.columns(4)
        for col, k in zip(c, ("pr_auc", "f1", "precision", "recall")):
            col.metric(k.upper().replace("_", "-"), sup.get(k))

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

    sensor = stats.get("sensor") or {}
    if sensor:
        st.subheader("Sensor")
        c = st.columns(4)
        c[0].metric("Packets processed", f"{sensor.get('pkts_proc', 0):,}")
        c[1].metric("Packets dropped", f"{sensor.get('pkts_dropped', 0):,}")
        c[2].metric("Zeek notices", sensor.get("notices", 0))
        c[3].metric("Protocol weirds", sensor.get("weirds", 0))
        st.caption(f"Logs present: {', '.join(sensor.get('logs_present', []))} · records parsed: {stats.get('records')}")

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
    st.caption(f"{c['flows']:,} flows over {c['hours'] * 60:.1f} min · {c['episodes']} ground-truth episodes · "
               f"engines {r.get('engines', {})}")
    if r.get("inactive_rules"):
        st.warning(f"Rules that could not fire (no profile): {', '.join(r['inactive_rules'])}")

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
    sup = r.get("supervised") or {}
    if "status" in sup:
        st.caption(f"supervised model: {sup['status']} — {sup['reason']}")
    elif "zeek_temporal" in sup:
        t = sup["zeek_temporal"]["test"]
        st.caption(f"Supervised model offline (CIC-IDS2017 Friday, Zeek-compatible features): PR-AUC {t['pr_auc']}, "
                   f"F1 {t['f1']} · naive-split F1 {sup.get('naive_random_split', {}).get('test', {}).get('f1')}")

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
                                    y=alt.Y("engine:N", title=None,
                                            sort=["rules", "anomaly", "supervised", "ensemble"]))
        heat = base.mark_rect().encode(
            color=alt.Color("recall:Q", scale=alt.Scale(domain=[0, 1], scheme="redyellowgreen"), legend=None),
            tooltip=["engine", "episode", "recall"])
        text = base.mark_text(fontWeight="bold").encode(text=alt.Text("recall:Q", format=".2f"))
        st.altair_chart((heat + text).properties(height=44 * df["engine"].nunique()), use_container_width=True)
    st.caption("Latency = first packet of the episode to the first moment the detection logic could fire; "
               "excludes Zeek's own connection-logging delay and, in watch mode, the pass interval.")


# --------------------------------------------------------------------------- study (§6.4)
def study_tab() -> None:
    st.subheader("Analyst study: raw alert vs. template vs. LLM narrative")
    st.caption("Blinded: you see each incident once, in one randomly assigned version, and are timed on two "
               "questions. Answer from what is on screen only.")
    rows = [r for r in store.incidents() if r.get("template")]
    if not rows:
        st.info("No incidents with narratives yet.")
        return
    done = {r["incident_id"] for r in store.study_responses(viewer)}
    items = [it for it in study.assign(viewer, rows, allowed_by_type()) if it.incident_id not in done]
    st.progress(len(done) / max(len(rows), 1), text=f"{len(done)} of {len(rows)} answered")
    if not items:
        st.success("All done, thank you.")
        if auth.can(role, "approve"):
            st.markdown(study.to_markdown(study.report(store.study_responses())))
        return
    it = items[0]
    s = st.session_state.setdefault("study", {})
    if s.get("item") != it.incident_id:
        s.clear()
        s.update(item=it.incident_id, t0=time.time(), stage="what")

    with st.container(border=True):
        b = it.body
        if b["kind"] == "raw":
            st.code("\n".join(f"{k}={v}" for k, v in b["fields"].items()), language="text")
        else:
            st.write(b["summary"])
            st.code("\n".join(b["evidence"]), language="text")
    whats = study.what_options(rows)
    if s["stage"] == "what":
        with st.form("q-what"):
            ans = st.radio("What happened?", whats, index=None)
            if st.form_submit_button("Answer") and ans:
                s.update(what=ans, t_what=time.time() - s["t0"], t1=time.time(), stage="action")
                st.rerun()
    elif s["stage"] == "action":
        with st.form("q-action"):
            ans = st.radio("What should be done first?", list(study.INTENT_LABELS),
                           format_func=lambda k: study.INTENT_LABELS[k], index=None)
            if st.form_submit_button("Answer") and ans:
                s.update(action=ans, t_action=time.time() - s["t1"], stage="rate")
                st.rerun()
    else:
        with st.form("q-rate"):
            act = st.slider("How actionable was this? (1 = not at all, 5 = I know exactly what to do)", 1, 5, 3)
            conf = st.slider("How confident are you in your answers?", 1, 5, 3)
            if st.form_submit_button("Submit and continue"):
                store.save_study_response(
                    analyst=viewer, incident_id=it.incident_id, version=it.version, answer_what=s["what"],
                    answer_action=s["action"], correct_what=s["what"] == it.correct_what,
                    correct_action=s["action"] in it.acceptable_actions, seconds_what=s["t_what"],
                    seconds_action=s["t_action"], actionability=act, confidence=conf)
                s.clear()
                st.rerun()


# --------------------------------------------------------------------------- audit
def audit_tab() -> None:
    rows = store.audit()
    if not rows:
        st.info("No command views, decisions or status changes yet.")
        return
    df = pd.DataFrame(rows)
    df["at"] = to_dt(df["at"])
    st.dataframe(df[["at", "viewer", "action", "incident_id", "note"]], hide_index=True, use_container_width=True)
    st.download_button("Download audit log (CSV)", df.to_csv(index=False), "nids-audit.csv", "text/csv")


st.title("NIDS — Incident Triage")
shared_note = " · ⚠ shared password: no per-person accountability" if st.session_state.get("shared") else ""
st.caption(f"Signed in as {viewer} ({role}){shared_note}. The LLM explains. It never decides, and it never executes.")
banner()
tabs = st.tabs(["Incidents", "Model health", "Evaluation", "Study", "Audit"])
with tabs[0]:
    incidents_tab()
with tabs[1]:
    model_tab()
with tabs[2]:
    evaluation_tab()
with tabs[3]:
    study_tab()
with tabs[4]:
    audit_tab()
