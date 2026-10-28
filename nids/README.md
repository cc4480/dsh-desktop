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
NIDS_DASHBOARD_PASSWORD=change-me streamlit run dashboard/app.py   # http://127.0.0.1:8501
python -m pytest -q                             # 35 tests, incl. the prompt-injection suite
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
| 7 Storage/UI | `nids/storage.py`, `dashboard/app.py` | SQLite (schema is plain SQL, ready for Postgres/Timescale). Audit tables for rendered commands, command views and LLM egress. Streamlit has a password gate, auto-refresh and no usage telemetry. |

## Results on the synthetic demo capture

The demo capture is 15 minutes, 46,580 flows (~3.2k pps on average, peaking at
12,450 pps). It was generated with a different seed and day than the training
baseline. The first 60 s are benign only (the negative control).

| Ground truth | Incident | Severity | Engines |
|---|---|---|---|
| SYN flood 192.168.1.105 → web-prod-01, 24,900 flows | 1 incident, T1498.001, peak 12,450 pps | critical | rule + anomaly |
| Vertical scan 192.168.1.77 → db-prod-01, 1,024 ports | 1 incident, T1046 | critical | rule + anomaly |
| DNS tunnelling from hr-laptop-12 | 1 incident, T1048 | medium | rule |
| 60 s C2 beacon from dev-laptop-07 | 1 incident, T1071 | medium | rule + anomaly |
| Allowlisted scanner 192.168.1.250 | 1 incident, `no_action` | informational | rule + anomaly |
| 2.4 GB upload from build-runner-03 (no rule) | 1 incident | low | anomaly only |
| Poisoned User-Agent | did not reach the prompt; the obedient-model variants were rejected | — | — |

- **26,279 alerts became 6 incidents.** No benign host raised an incident.
- **231 lone anomalous benign flows went to the watchlist.** That is the expected ~1% at a 0.99 percentile threshold.
- Pipeline time is about 4 s for the whole capture, mostly JSON parsing.

These numbers show that the plumbing works. They don't show detection quality: the
traffic is synthetic and the rules were written with these attacks in mind. Real
numbers need M0 (a real lab capture) and M2 (CIC-IDS2017).

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
6. **The supervised task is binary.** Friday's attack classes (PortScan, DDoS, Bot) never
   appear Monday–Wednesday, so an honest temporal split can't test a multi-class model.
   Per-class recall on Friday is still reported.

## Roadmap status

| Milestone | Status |
|---|---|
| M0 Lab & ground truth | **Stand-in.** `nids/lab/generate.py` makes Zeek-format logs with labelled ground truth. Replace with a real capture (`scripts/zeek_from_pcap.sh`); see "Next steps". |
| M1 Baseline detector | **Done.** Rules, correlation, severity, template narrative, policy engine, store, dashboard. |
| M2 Honest ML | **Script ready, not run.** `ml/train_supervised.py`: dedupe → Mon–Wed/Thu/Fri split → drop identifiers → deployable (no payload-byte) features → isotonic calibration on Thursday → naive-vs-honest gap. Needs the CIC-IDS2017 CSVs. Not wired into the live path until a Zeek→CIC feature adapter exists. |
| M3 LLM tier | **Done; needs a real model run.** Ollama/OpenAI clients, grounding validator, fallback, cache, redaction. Tested with scripted fake models only. |
| M4 Dashboard & response | **Done** with SQLite. TimescaleDB is optional. |
| M5 Evaluation | **Partly done.** Adversarial suite done. The analyst ablation (raw / template / LLM) is not done. |

## Next steps

1. **M0 for real:** set up two containers on an isolated Docker network. Run `hping3 -S --flood`
   and `nmap -sS` from one at the other while `tcpdump` records. Convert the capture
   with `scripts/zeek_from_pcap.sh` and re-run the pipeline. Tune the rule thresholds
   on *this* data, then freeze them.
2. **M2:** download CIC-IDS2017 (MachineLearningCVE CSVs) and run
   `python ml/train_supervised.py --data <dir>`. Publish `models/supervised_report.json`
   (baseline table and naive-vs-honest gap).
3. **M3:** `ollama pull llama3.1:8b`, run with `--backend ollama`, and record the
   narrative validation pass rate and p99 latency.
4. **Streaming:** the pipeline is batch over a log directory today. Next, tail Zeek's
   rotating logs and keep correlator state between runs.

## Honest limitations

- Synthetic traffic proves the plumbing, not the detectors.
- Point-wise Isolation Forest is weak at exfiltration: the 2.4 GB upload scored only the
  99.4th percentile. Behavioural rules carry exfiltration (DNS tunnelling, beaconing).
- Prompt injection is mitigated, not solved, for narrative manipulation. Command
  injection is impossible by construction: the model can only pick from an enum.
- The dashboard's password gate is the minimum. Production needs SSO/RBAC, and it
  should never be exposed on a shared network.
