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
python -m nids lab                         # synthetic Zeek logs with ground truth
python -m nids train data/lab/baseline     # anomaly model (IF + autoencoder) + behavioural profile
python -m nids run data/lab/demo --fresh   # detect -> correlate -> explain -> render -> store
python -m nids evaluate data/lab/demo      # each engine and the ensemble, against ground truth
python -m nids add-user alice --role approver   # dashboard login (analyst | approver)
streamlit run dashboard/app.py             # http://127.0.0.1:8501
python -m pytest -q                        # 62 tests, incl. the prompt-injection suite
```

`NIDS_DASHBOARD_PASSWORD=change-me scripts/demo.sh` runs the whole demo with a shared
password. Without `add-user` there is no per-person accountability, and the dashboard
says so on screen.

### Live mode

```bash
python -m nids watch /opt/zeek/logs/current --interval 10
```

Each pass (default every 10 s):

1. **Ingest.** Read what Zeek appended, safely across log rotation.
2. **Score.** Run the per-flow engines on new flows only.
3. **Detect.** Run rules and correlation over a one-hour buffer.
4. **Update incidents.**
   - An incident whose attack continues keeps its id and is updated in place.
   - A new incident is explained and gets its response command.
   - The narrative is regenerated only if severity rises.
   - An incident an analyst closed while the attack continued is reopened.
5. **Close.** Incidents close once their correlation window passes with no activity.

"Now" is log time, so replaying a capture behaves exactly like live traffic.
`tests/test_watch.py` replays the demo in five-minute chunks and checks the result
matches the batch run, incident for incident.

### LLM backends

```bash
ollama pull llama3.1:8b
python -m nids run data/lab/demo --fresh --backend ollama --model llama3.1:8b
```

The model receives a strict JSON schema (Ollama ≥ 0.5 constrains decoding to it), plus:
- a trusted `<CONTEXT>` block: the ATT&CK summary from `config/attack.yaml` and our runbook;
- the authoritative `<CLASSIFICATION>`;
- typed `<EVIDENCE>` only.

**Model choice is open.** `llama3.1:8b` (July 2024) is only the default tag. Newer small
open models exist (the Qwen3 and Gemma families are the usual suggestions for schema-
constrained JSON). The tie-breaker for this project is the validator's pass rate, so
run `run --backend ollama --model <tag>` with two or three candidates and keep the one
with the highest pass rate at acceptable p99 latency. Model availability couldn't be
checked from here (ollama.com was unreachable).

`--backend openai` works with any OpenAI-compatible endpoint (`OPENAI_API_KEY`,
`OPENAI_BASE_URL`). If you use OpenAI itself, check its deprecations page first.
Secondary sources report that `gpt-4o-mini` leaves the API on 2027-01-14; the official
page couldn't be reached from here. Before anything is sent, internal IPs and asset names become stable
placeholders, and every payload sent is logged in `egress_log`. Narratives are cached by
fingerprint for 7 days, and round-trip latency is recorded (p50/p99 in the dashboard).

### Supervised model (CIC-IDS2017)

```bash
python ml/train_supervised.py --data /path/to/MachineLearningCVE --out models/
```

The script dedupes before splitting and uses a Mon–Wed / Thu / Fri temporal split. It
drops identifier columns and calibrates on Thursday only. It reports three feature sets
plus the naive random split, so the leak is quantified.

`models/supervised.joblib` is trained on exactly the CIC features `nids/supervised.py`
can compute from Zeek's conn.log (11 of 78). The pipeline loads it automatically and
refuses a model trained on anything else.

**Dataset quality.** The original CIC-IDS2017 release has documented errors. Engelen et
al. (2021) and Liu et al. (2022) found more than 20% of flows were artefacts, and about
10% were mislabelled. They regenerated and relabelled the dataset from the original pcaps
and published the corrected version. Prefer that version. The trainer has only been tested
against the original CSV layout, so check its column names and labels (the corrected
version marks failed attacks as "Attempted") before training. Either way, report which
version you used.

### Docker lab (M0)

`lab/` is an isolated lab with real TCP/IP stacks. The attack scripts write their own
ground truth as they run. The compose network is `internal`, so nothing reaches the
internet.

| Container | Address | Role |
|---|---|---|
| target | 172.28.0.10 | nginx :80, :443 (self-signed), sshd :22, dnsmasq :53, upload sink :9000 |
| sensor | (target's namespace) | `zeek -i eth0` with the **JA4** package and Community IDs (`lab/sensor/Dockerfile`), JSON logs to `data/lab-docker/<mode>/` |
| recorder | (target's namespace) | `tcpdump -s 128` → `capture.pcap`, for `nids pcap` |
| client | 172.28.0.100 | always-on benign web and DNS traffic |
| attacker | 172.28.0.66 | poisoned UA, `hping3` SYN flood (upstream inactive since 2005, still packaged by Debian), `nmap -sS`, 40 SSH password guesses, gobuster-style wordlist scan |
| implant | 172.28.0.60 | 60 s HTTPS beacon, DNS tunnel, 3 × 200 MB upload |

```bash
lab/run_lab.sh baseline 1200     # 20 min benign only
lab/run_lab.sh attack            # 60 s negative control, then the scenario (~20 min)
python -m nids train data/lab-docker/baseline --out models/anomaly-lab.joblib --profile-out models/profile-lab.json
LAB="--assets config/assets.lab.yaml --anomaly-model models/anomaly-lab.joblib --profile models/profile-lab.json"
python -m nids run data/lab-docker/attack --fresh $LAB
python -m nids evaluate data/lab-docker/attack $LAB
python -m nids pcap <INCIDENT-ID> --pcap data/lab-docker/attack/capture.pcap
```

#### TLS fingerprints (JA4)

`lab/sensor/Dockerfile` builds the sensor from **`zeek/zeek:9.0.1`** plus **`zeek/foxio/ja4`**.
The image is pinned to an exact release, not the floating `lts` tag, because the JA4 plugin
is compiled against Zeek and `lts` moved from 8.0 to 9.0 on 2026-09-17. JA4's own CI tests
Zeek 8.0; reading its source turned up nothing Zeek 9.0 removed. If the plugin fails on
9.0, build with `--build-arg ZEEK_IMAGE=zeek/zeek:8.0.11`, the previous LTS, which is
supported until Zeek 9.1 ships.
That compiled plugin is actively maintained by FoxIO and adds `ja4` (and the JA4+
variants) to ssl.log. It is pinned to the commit this project was checked against. The
image also loads Community ID logging and Zeek's SSH brute-force detector, and fails the
build if the scripts don't load. `scripts/zeek_from_pcap.sh` uses the same image.

**Why JA4 and not JA3:**
- JA3's Zeek package (`salesforce/ja3`) has been archived upstream since May 2025.
- Chrome randomises TLS extension order on every connection, so its JA3 changes each
  time and "never-seen fingerprint" would fire on ordinary browsing. JA4 sorts the
  extensions first and stays stable.

So JA3 is not installed or used anywhere. If the baseline was captured without JA4, the
rule says "can't tell" instead of "everything is new".

Licensing: the JA4 client fingerprint is BSD-3. The JA4+ fields the package also writes
(`ja4s`, `ja4h`, `ja4x`, …) are under the FoxIO License 1.1. That's fine for academic and
internal use; selling a product built on them needs an OEM licence.

**Base images:** the lab's own containers use Debian 13 (`trixie-slim`). Debian 12 left
regular security support in June 2026. Package names were picked to exist in both
releases (`nginx`, `bind9-dnsutils`), but the Debian archive wasn't reachable from where
this was written, so the trixie package list is unverified. If a package is missing, build
with `--build-arg DEBIAN_TAG=bookworm-slim`.

**The Docker lab has not been run yet:** there was no Docker daemon where it was written.
The compose file and scripts were syntax-checked, and the ground-truth format is tested.
Expect to tune rule thresholds on the first real capture, then freeze them.

## Where each plane lives

| Plane | Code | Notes |
|---|---|---|
| 0 Context | `config/assets.yaml`, `nids/assets.py`, `runbooks/`, `config/attack.yaml` | criticality, internet-facing, known scanners, protected IPs, critical ports; ATT&CK and runbook text for the LLM's trusted context |
| 1 Sensing | `nids/sensing/` | Zeek conn, dns, http, ssl, notice, weird, capture_loss and stats logs (JSON or TSV). **Untrusted text is reduced at the edge.** User-Agent becomes an enum (browser, cli, scanner…), a URI becomes a length and hash, and SNI is charset-filtered. Community IDs are taken from Zeek or computed; Wireshark computes the same value. |
| 2 Features | `nids/features.py`, `nids/profile.py` | Versioned `FEATURE_REGISTRY`. A **behavioural profile** learned from the baseline holds known destinations per host, peak hourly outbound bytes per host, and seen JA4 fingerprints. Rules use it as window features (`new_dst_ratio`, `bytes_out_vs_baseline`, `new_fingerprint_ratio`). |
| 3a Rules | `config/rules.yaml`, `nids/rules.py` | 12 rules over conn, dns, http, tls and notice records. Conditions are structured `(feature, op, value)` with an optional pre-filter, and no `eval`. Windows overlap by half (hopping). **Detection time is the first moment the condition holds**, found by replaying records in the order Zeek logs them. |
| 3b Supervised | `nids/supervised.py`, `ml/train_supervised.py` | Zeek→CIC adapter with 11 honest features. Per-flow probability, isotonic-calibrated. |
| 3c Unsupervised | `nids/anomaly.py` | **Isolation Forest + autoencoder**, each scored against a frozen benign ECDF. The ECDF is per hour of day where the baseline allows. A flow is anomalous if both detectors exceed 0.99 or either exceeds 0.999. The baseline is cleaned by majority vote: rule hits and either detector's top 1% are dropped, then both are refitted. |
| 4 Correlation | `nids/correlation.py` | One incident per `(src, dst, attack_type)` episode. Destination-less alerts (Zeek notices) merge into the matching incident. A per-flow engine needs 3 agreeing flows on a pair, or 10 if the profile already knows the pair. **Campaigns** link one source's incidents of different types within an hour. Deterministic severity table and modifiers. Forensics: BPF, display filter, time range and Community IDs. |
| 5 Explanation | `nids/explain/`, `prompts/system_prompt.txt` | `prompt.py` is the trust boundary. The validator checks schema, intent enum, field **and value** of each citation, CVEs and command-like text, then overrides the fields we own. The template is always produced too: it is the fallback and arm B of the study. |
| 6 Response | `nids/response/policy.py`, `config/policy.yaml` | intent → allowlisted template for **iptables/ip6tables or nftables**. nft rules carry a `nids-<incident>` comment, so rollback deletes exactly that rule by handle. Arguments are re-validated. Guards for protected IPs, registered assets and critical ports. Never executes. |
| 7 Storage/UI | `nids/storage.py`, `dashboard/app.py`, `nids/auth.py` | SQLite with additive migrations. Audit of command views, approve/reject decisions and status changes. LLM egress log. Per-user logins (PBKDF2, 310k iterations), with roles **analyst** (triage) and **approver** (may approve a command). |
| Watch | `nids/watch.py` | Live mode (above). |
| Forensics | `nids/forensics.py` | `python -m nids pcap INCIDENT --pcap FILE` (tshark with a time bound, else tcpdump with BPF only). |
| Evaluation | `nids/evaluate.py` | rules / anomaly / supervised / ensemble against ground truth, at incident and flow level, with detection latency. |
| Study (§6.4) | `nids/study.py`, dashboard **Study** tab | Blinded, timed raw / template / LLM comparison. `python -m nids study-report` prints the results. |

### Dashboard

- **Banner**
  - traffic chart with a line at each incident's detection time
  - open critical/high count and the anomaly watchlist
  - sensor **capture loss**
  - LLM pass rate and latency
  - warnings: capture loss above 1%, rules that can't fire because no profile is trained
- **Incidents**
  - filters: severity, status (open, acknowledged, closed), attack type, search (including campaign id)
  - a **campaign** summary above the feed
  - each card:
    - **Acknowledge / Close / Reopen**
    - its own packets/s chart
    - the grounded narrative, why it got its severity, and runbooks
    - a copy-only command with rollback and dry-run; Approve / Reject is shown to **approvers only**
    - a **Forensics** popover: BPF filter, tshark commands, Community IDs
- **Model health**
  - engine status
  - anomaly model: version, cleaning, per-hour calibration, combination rule
  - profile size; supervised test metrics
  - drift (PSI) on traffic outside incidents, with all-traffic PSI shown separately
  - sensor counters and alert rate
- **Evaluation:** baselines table, per-episode results, per-engine recall heatmap.
- **Study:** the blinded analyst study (below).
- **Audit:** every view, decision and status change; downloadable as CSV.

### The analyst study (§6.4)

Each analyst sees each incident once, in one version, assigned by a stable hash so
versions balance across analysts. The three versions:
- **A**, the raw alert: signature name plus flow stats, as an IDS console shows it.
- **B**, the template.
- **C**, the validated LLM narrative.

The order is shuffled. Two multiple-choice questions are timed ("what happened?", "what
should be done first?"), then actionability and confidence are rated 1–5.

Version A keeps the signature name because every real alert has one. So "what happened"
accuracy should be near the ceiling everywhere. **Time to answer and choosing the right
action are the measures that tell the versions apart.** Version C needs an LLM backend;
without one the study runs A against B.

## Results on the synthetic demo capture

The demo capture is 15 minutes: 46,882 flows (~3.4k pps average, 12,450 pps peak), plus
2,519 HTTP requests and 7,471 TLS sessions. It was generated with a different seed and
day than the baseline. The first 60 s and an admin's long legitimate SSH session are
negative controls. From `python -m nids evaluate data/lab/demo`:

| Config | Episodes detected | False incidents | ATT&CK correct | Latency p50 / max (s) | Flow P / R | PR-AUC |
|---|---|---|---|---|---|---|
| rules + profile | 8/8 | 0 | 8/8 | 16 / 660 | 1.00 / 1.00 | — |
| anomaly (IF + AE) | 4/8 | 0 | 0/4 | 0.2 / 889 | 0.99 / 0.98 | 0.995 |
| supervised | not run: no CIC-IDS2017 model trained here | | | | | |
| **ensemble** | **8/8** | **0** | **8/8** | 16 / 660 | 1.00 / 1.00 | — |

| Episode | Incidents | Severity | Latency | Note |
|---|---|---|---|---|
| SYN flood | 1 | critical | 0.0 s | |
| Port scan | 1 | critical | 0.1 s | |
| Allowlisted scanner | 1 | informational | 0.2 s | gets `no_action` |
| Web wordlist scan | 2 | critical | 0.5 s | wordlist + scanner-UA, linked as one campaign |
| SSH brute force | 1 | critical | 31 s | conn rule + Zeek notice, merged |
| DNS tunnel | 1 | medium | 58 s | |
| HTTPS beacon | 3 | medium, low | 245 s | beacon + self-signed TLS + unseen JA4, linked as one campaign |
| Bulk upload, new destination | 1 | medium | 660 s | Zeek logs a connection only when it ends |

What the tables show:
- **The anomaly engine alone misses DNS tunnelling, brute force, the wordlist scan and
  the beacon**, because each of their flows looks ordinary. It never names an attack.
- **Without a profile, the rules miss the upload** and only the anomaly engine sees it.
  `test_without_a_profile_…` pins this.
- **The ensemble is the only setup that gets everything.**

Other measurements:
- **About 0.7% of benign flows score above the 0.99 percentile (139 here),** less than
  the 1% one detector alone gives, because the two detectors must agree. Incident
  formation keeps all of them out of the feed.
- **Background PSI stays below 0.003, while all-traffic PSI reaches 3.05** because of the
  attacks. That's why the dashboard plots background PSI.

These numbers show the plumbing works. They don't show detection quality: the traffic is
synthetic and the rules were written with these attacks in mind. Real numbers need the
Docker lab (M0) and CIC-IDS2017 (M2).

## Where this deliberately departs from the blueprint text

1. **The ECDF sign.** §3.4 writes `score = 1 - ECDF(raw)` with `raw = -score_samples`.
   Higher `raw` already means more anomalous, so `ECDF(raw)` *is* the score.
2. **A lone anomalous flow is not an incident.** At a 0.99 threshold, ~1% of benign flows
   exceed it by construction; the first run gave 233 incidents. A standalone anomaly
   incident needs ≥ 3 agreeing flows on a pair, and ≥ 10 if the profile knows the pair.
   That second threshold was added after a **real false positive** in testing: an admin's
   long SSH session. Majority-vote cleaning had dropped those rare-but-legitimate sessions
   from training, so they looked anomalous.
3. **The validator checks values, not only field names** (1% tolerance).
4. **Intents are constrained per attack type** (`allowed_intents`). Informational
   incidents only get `no_action`.
5. **`block_source_ip` drops all traffic from the source**, not just `--syn`. The engine
   refuses to block a registered internal asset and points to `isolate_host`.
6. **Overlapping (hopping) windows.** `test_scan_straddling_a_window_boundary_is_still_caught`
   fails with fixed windows. Flows are counted by unique Zeek uid; notices are not flows.
7. **`SYN_FLOOD` doesn't require `conn_state == S0`.** A real target answers SYN-ACK and
   the attacker's kernel sends RST, so Zeek's state varies. "The originator never
   completed the handshake" holds in every case.
8. **The supervised task is binary.** Friday's attacks never appear Monday–Wednesday.
9. **The autoencoder is scikit-learn's MLP, not PyTorch.** It's the same 16-4-16
   reconstruction model without a ~2 GB dependency.
10. **"RAG" is a deterministic lookup.** The classification is already known, so the
    context block is the ATT&CK entry and runbook for that technique and rule. A lookup
    can't be steered by attacker-controlled text; a vector search could.
11. **SQLite, not TimescaleDB.** The blueprint allows SQLite as the fallback, and the
    schema is plain SQL.

## Roadmap status

| Milestone | Status |
|---|---|
| M0 Lab & ground truth | **Built, not yet run.** Docker lab with all scenarios, a header-only recorder, and ground truth written by the attack scripts. The synthetic generator is the offline fallback and what the tests use. |
| M1 Baseline detector | **Done.** |
| M2 Honest ML | **Built, not run on the real dataset.** Leakage-aware trainer, Zeek→CIC adapter, and the supervised engine in the pipeline and evaluator. Tested end to end on a synthetic CIC-shaped frame. Needs the CIC-IDS2017 CSVs. |
| M3 LLM tier | **Done; needs a real model run.** Schema-constrained Ollama/OpenAI clients, trusted context, validator, fallback, cache expiry, latency, redaction. Tested with scripted fake models only. |
| M4 Dashboard & response | **Done.** Live mode, campaigns, incident lifecycle, roles, forensics, nftables, sensor health. |
| M5 Evaluation | **Built, needs people.** Evaluation harness, baselines table, adversarial suite, and the blinded timed study are done. The study needs ≥ 8 analysts and an LLM backend. |

## What's left: testing in real environments

1. **M0:** `lab/run_lab.sh baseline` and `lab/run_lab.sh attack` on a machine with Docker.
   Then `train`, `evaluate`, and `pcap` an incident. Tune thresholds there, freeze them,
   and re-run on a fresh capture.
2. **M2:** `python ml/train_supervised.py --data <CIC-IDS2017 dir>`, then re-run
   `evaluate` so the supervised row and the naive-vs-honest gap are real.
3. **M3:** `--backend ollama`. Compare two or three current small models on validation
   pass rate and p99 latency (see "Model choice is open" above).
4. **M5:** run the study with ≥ 8 analysts, then `python -m nids study-report`.
5. **JA4:** the sensor image installs the JA4 package, but it has not been built here.
   Zeek isn't available in this environment, and compiling it from source was not
   permitted. Check that ssl.log carries `ja4` after the first lab run.
6. **Demo safety net:** record a backup video of the demo (blueprint §8).

## Honest limitations

- Synthetic traffic proves the plumbing, not the detectors.
- Per-flow detectors are weak at exfiltration and at low-and-slow attacks. Behavioural
  rules and the profile carry those.
- The profile and baselines are only as good as the baseline capture. A short baseline
  makes everything look "new".
- In the Docker lab, any client using the target's self-signed HTTPS would also trip
  `SELF_SIGNED_TLS_REPEATED`. That rule is weak alone by design: it is low severity and
  matters next to beaconing.
- Prompt injection is mitigated, not solved, for narrative manipulation. Command injection
  is impossible by construction: the model can only pick from an enum.
- The dashboard should stay on localhost or behind SSO. Its logins are the minimum for
  accountability, not an identity system.
