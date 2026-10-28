# NIDS — ML-powered detection with grounded LLM incident interpretation

> **The LLM explains. It never decides, and it never executes.**

Implementation of *System Architecture & Technical Blueprint v2.0*. Everything that
detects, scores, correlates, sets severity or renders a command is deterministic,
tested code. The LLM writes prose about a classification it is given. That prose
must cite real evidence fields, which a validator checks. If it fails, a template
is shown instead.

## Quick start

```bash
pip install -r requirements-dev.txt
python -m nids lab                              # synthetic Zeek logs with ground truth
python -m nids train-anomaly data/lab/baseline  # Isolation Forest + frozen baseline ECDF
python -m nids run data/lab/demo --fresh        # detect -> correlate -> explain -> render -> store
python -m nids evaluate data/lab/demo           # rules vs anomaly vs ensemble, against ground truth
NIDS_DASHBOARD_PASSWORD=change-me streamlit run dashboard/app.py   # http://127.0.0.1:8501
python -m pytest -q                             # 42 tests, incl. the prompt-injection suite
```

Or run everything at once: `NIDS_DASHBOARD_PASSWORD=change-me scripts/demo.sh`.

With a local model (recommended; no telemetry leaves the host):

```bash
ollama pull llama3.1:8b
python -m nids run data/lab/demo --fresh --backend ollama --model llama3.1:8b
```

`--backend openai` works with any OpenAI-compatible endpoint (`OPENAI_API_KEY`,
`OPENAI_BASE_URL`). Before anything is sent, internal IPs and asset names become
stable placeholders, and every payload sent is logged to the `egress_log` table.

On real traffic, `scripts/zeek_from_pcap.sh capture.pcap data/lab/real` turns a
capture into JSON Zeek logs using the `zeek/zeek` image. Then run
`python -m nids run data/lab/real`.

### The Docker lab (M0)

`lab/` is a reproducible, isolated lab with real TCP/IP stacks. Zeek is the sensor,
and the attack scripts write their own ground truth as they run. The compose network
is `internal`, so nothing can reach the internet.

| Container | Address | Role |
|---|---|---|
| target | 172.28.0.10 | nginx :80 and :8443 (fake C2), dnsmasq :53, upload sink :9000 |
| sensor | (target's namespace) | `zeek -i eth0`, JSON logs to `data/lab-docker/<mode>/` |
| client | 172.28.0.100 | always-on benign web and DNS traffic |
| attacker | 172.28.0.66 | poisoned User-Agent, `hping3` SYN flood (~12.5k pps, 4 s), `nmap -sS` 1–1024 |
| implant | 172.28.0.60 | 60 s beacon ×12, DNS tunnel (150 queries), 3 × 200 MB upload |

```bash
lab/run_lab.sh baseline 1200     # 20 min benign only
lab/run_lab.sh attack            # 60 s negative control, then the scenario (~15 min)
python -m nids train-anomaly data/lab-docker/baseline --out models/anomaly-lab.joblib
LAB="--assets config/assets.lab.yaml --anomaly-model models/anomaly-lab.joblib"
python -m nids run data/lab-docker/attack --fresh $LAB
python -m nids evaluate data/lab-docker/attack $LAB
```

Scenario length is set with `WARMUP`, `BEACONS` and `TUNNEL_QUERIES`. **The lab has
not been run yet:** there was no Docker daemon where it was written. The compose
file and scripts were only syntax-checked. Expect to tune rule thresholds on the
first real capture, then freeze them.

## Where each plane lives

| Plane | Code | Notes |
|---|---|---|
| 0 Context | `config/assets.yaml`, `nids/assets.py`, `runbooks/` | criticality, internet-facing, known scanners, protected IPs, critical ports |
| 1 Sensing | `nids/sensing/zeek.py`, `sanitize.py` | Zeek `conn.log`/`dns.log`, JSON or TSV. Every field is typed or charset-filtered at the edge. `http.log` is never parsed into anything the LLM sees. |
| 2 Features | `nids/features.py` | Versioned `FEATURE_REGISTRY` (per-flow features and windowed aggregates). No ports or IPs in model features. |
| 3a Rules | `config/rules.yaml`, `nids/rules.py` | Structured `(feature, op, value)` conditions with no `eval`. Unknown features are rejected at load time. ATT&CK IDs are attached here. |
| 3b Supervised | `ml/train_supervised.py` | CIC-IDS2017 with the §6.2 protocol (see M2 below). |
| 3c Unsupervised | `nids/anomaly.py` | Isolation Forest scored against a **frozen benign ECDF**, so scores don't depend on the batch. |
| 4 Correlation | `nids/correlation.py` | One incident per `(src, dst, attack_type)` episode, plus the deterministic severity table and its modifiers. |
| 5 Explanation | `nids/explain/` and `prompts/system_prompt.txt` | `prompt.py` is the trust boundary. The validator checks the schema, intent enum, field **and value** of each citation, CVEs and command-like text, then overrides the fields we own. On failure the template is used. Results are cached by fingerprint. |
| 6 Response | `nids/response/policy.py` | intent → allowlisted template, with arguments re-validated. Guards for protected IPs, registered assets and critical ports. Always shows a rollback, never executes. |
| 7 Storage/UI | `nids/storage.py`, `dashboard/app.py` | SQLite (schema is plain SQL, ready for Postgres/Timescale). Audit tables for rendered commands, command views, approve/reject decisions and LLM egress. Streamlit has a password gate, auto-refresh and no usage telemetry. Tabs below. |
| Evaluation | `nids/evaluate.py` | rules / anomaly / ensemble against ground truth, at incident and flow level, with detection latency. |

### Dashboard

- **Banner:** traffic for the whole capture, with a line at each incident's detection time.
- **Incidents:** a severity-sorted feed. Each card has:
  - the incident's own packets/s chart (shaded window, dashed line at detection)
  - the grounded narrative and why it got its severity
  - the runbook and a copy-only command with rollback and dry-run
  - an **Approve / Reject** form that records analyst, note and command id. Approving executes nothing.
- **Model health:** model version (sha256), training size and threshold. **Feature drift (PSI) on
  background traffic**, i.e. flows in no incident. All-traffic PSI is in a collapsed section,
  because an attack shifts that by itself. Also the alert rate over time and run history.
- **Evaluation:** the baselines table, per-episode detection, and a per-engine recall heatmap.
- **Audit:** every command view and decision, downloadable as CSV.

## Results on the synthetic demo capture

The demo capture is 15 minutes, 46,580 flows (~3.2k pps on average, peaking at
12,450 pps). It was generated with a different seed and day than the training
baseline. The first 60 s are benign only (the negative control). From
`python -m nids evaluate data/lab/demo`:

| Config | Episodes detected | False incidents / h | ATT&CK correct | Latency p50 / max (s) | Flow P / R | PR-AUC |
|---|---|---|---|---|---|---|
| rules only | 5/6 (misses the novel upload) | 0 | 5/5 | 30 / 450 | 1.00 / 1.00 | — |
| anomaly only | 5/6 (misses DNS tunnelling) | 0 | 0/4 | 0.2 / 803 | 0.99 / 0.99 | 0.99 |
| **ensemble** | **6/6** | **0** | **5/5** | 45 / 803 | 1.00 / 1.00 | — |
| supervised | not evaluated: no Zeek→CIC feature adapter yet | | | | | |

Per-episode latency for the ensemble:

| Episode | Latency | Why |
|---|---|---|
| SYN flood | 5 s | 10 s window, 5 s hop |
| Port scan | 10 s | |
| DNS tunnel | 60 s | |
| Beacon | 450 s | needs 8 check-ins inside a 15-minute window |
| Bulk upload | 803 s | Zeek logs a connection only when it ends |

Latency is measured to the first moment the detection logic could fire. It does
not include Zeek's own logging delay.

What the table shows:

- Each engine misses something the other catches.
- The anomaly model alone never names an attack.
- **About 1% of benign flows score above the 0.99 percentile, as designed (231 here).**
  Incident formation keeps them out of the feed, so they land on the watchlist.
- Background-traffic PSI stays below 0.003. All-traffic PSI reaches 3.3, because of the flood.

These numbers show that the plumbing works. They don't show detection quality: the
traffic is synthetic and the rules were written with these attacks in mind. Real
numbers need the Docker lab (M0) and CIC-IDS2017 (M2).

## Where this deliberately departs from the blueprint text

1. **The ECDF sign.** §3.4 writes `score = 1 - ECDF(raw)` with `raw = -score_samples`.
   Higher `raw` already means more anomalous, so `ECDF(raw)` *is* the score. Subtracting
   from 1 would invert it. `test_calibration.py` pins the corrected behaviour.
2. **A lone anomalous flow is not an incident.** At a 0.99 threshold, 1% of benign
   flows exceed it by construction: 223 of 19,985 in the demo, which gave 233 incidents
   in the first run. A standalone anomaly incident now needs ≥ 3 anomalous flows on the
   same pair. Lone flows are counted on the watchlist, and they can still enrich a rule
   incident they overlap.
3. **The validator checks values, not only field names.** `packets_per_second=3` is
   rejected when the evidence says 12450 (1% tolerance).
4. **Intents are constrained per attack type** (`allowed_intents` in `rules.yaml`).
   Informational incidents only ever get `no_action`.
5. **`block_source_ip` drops all traffic from the source**, not just `--syn`. The policy
   engine refuses to block a registered internal asset and points to `isolate_host`.
6. **Overlapping (hopping) windows instead of fixed ones.** Each window is offset by
   half its length, so a burst that straddles a window boundary is still seen whole.
   `test_scan_straddling_a_window_boundary_is_still_caught` fails with fixed windows.
   Flows are counted by unique Zeek uid, so the overlap never double-counts.
7. **`SYN_FLOOD` no longer requires `conn_state == S0`.** On a real stack the target
   answers SYN-ACK and the attacker's kernel sends RST, so Zeek reports S0, REJ or
   RSTOS0 depending on timing. The rule tests "the originator never completed the
   handshake" instead, which holds in every case.
8. **The supervised task is binary.** Friday's attack classes (PortScan, DDoS, Bot) never
   appear Monday–Wednesday, so an honest temporal split can't test a multi-class model.
   Per-class recall on Friday is still reported.

## Roadmap status

| Milestone | Status |
|---|---|
| M0 Lab & ground truth | **Built, not yet run.** The Docker lab in `lab/` writes its own ground truth. The synthetic generator (`nids/lab/generate.py`) remains the offline fallback and is what the tests use. |
| M1 Baseline detector | **Done.** Rules, correlation, severity, template narrative, policy engine, store, dashboard. |
| M2 Honest ML | **Script ready, not run.** `ml/train_supervised.py`: dedupe → Mon–Wed/Thu/Fri split → drop identifiers → deployable (no payload-byte) features → isotonic calibration on Thursday → naive-vs-honest gap. Needs the CIC-IDS2017 CSVs. Not wired into the live path until a Zeek→CIC feature adapter exists. |
| M3 LLM tier | **Done; needs a real model run.** Ollama/OpenAI clients, grounding validator, fallback, cache, redaction. Tested with scripted fake models only. |
| M4 Dashboard & response | **Done** with SQLite: traffic charts, model health and drift, an approve/reject audit trail. TimescaleDB is optional. |
| M5 Evaluation | **Mostly done.** Evaluation harness, baselines table and adversarial suite are done. The analyst ablation (raw / template / LLM) is not. |

## Next steps

1. **M0 for real:** run `lab/run_lab.sh baseline` and `lab/run_lab.sh attack` on a machine
   with Docker, then `evaluate`. Tune the rule thresholds on *that* data, then freeze them
   and re-run on a fresh capture.
2. **M2:** download CIC-IDS2017 (MachineLearningCVE CSVs) and run
   `python ml/train_supervised.py --data <dir>`. Publish `models/supervised_report.json`
   (baseline table and naive-vs-honest gap).
3. **M3:** `ollama pull llama3.1:8b`, run with `--backend ollama`, and record the
   narrative validation pass rate and p99 latency.
4. **Streaming:** the pipeline is batch over a log directory today. Next, tail Zeek's
   rotating logs, keep correlator state between runs, and close incidents automatically.
5. **The analyst ablation (§6.4):** export blinded raw / template / LLM versions of each incident.

## Honest limitations

- Synthetic traffic proves the plumbing, not the detectors.
- Point-wise Isolation Forest is weak at exfiltration: the 2.4 GB upload scored only the
  99.4th percentile. Behavioural rules carry exfiltration (DNS tunnelling, beaconing).
- Prompt injection is mitigated, not solved, for narrative manipulation. Command
  injection is impossible by construction: the model can only pick from an enum.
- The dashboard's password gate is the minimum. Production needs SSO/RBAC, and it
  should never be exposed on a shared network.
