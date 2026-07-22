# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack

Elasticsearch 9.3.0 / Kibana 9.3.0 / Logstash 9.3.0 running as Docker Swarm services on a single node. All three are deployed via `elastic.sh`, which generates SSL certs, writes compose files to `~/elastic/`, and brings up the stack. Single-node, so scenario indexes are yellow (replica shard unassigned — expected).

- Elasticsearch: `https://<host-ip>:9200` (host IP is dynamic — was `192.168.86.55`, currently `192.168.86.31`; `https://localhost:9200` always works from the host). Scripts default the endpoint via `ES_URL`/`KB_URL` env vars — export `ES_URL=https://localhost:9200 KB_URL=https://localhost:5601` when re-seeding.
- Kibana: `https://<host-ip>:5601`
- Default user: `elastic` — password in `.env` as `ES_PASS`

**License:** the cluster runs on a permanent **Basic** license. A self-generated *trial* expires after 30 days; when it lapses you get `current license is non-compliant for [security]`. Fix without a rebuild: `curl -sk -u elastic:$ES_PASS -XPOST "$ES/_license/start_basic?acknowledge=true"`. Every feature used here (security, enrich policies, ingest pipelines, runtime fields, Lens, index-threshold alerting) is Basic-tier.

**Kibana can be down** after a stack restart even when ES is up. Bring it back with `docker compose -f ~/elastic/kibana.yml up -d` and poll `GET /api/status` until 200 (~30–120s).

## Credentials

```bash
source .env   # sets ES_PASS (NOT exported — add `export ES_PASS` before python subprocesses)
```

All curl to the cluster uses `-sk -u elastic:$ES_PASS` (self-signed cert). All Kibana calls need `-H "kbn-xsrf: true"`.

## The Praxis v7 experiment

The repository implements a **two-condition (baseline vs enriched) evaluation** of a PII Context Framework across five PII-targeting attack scenarios, producing a statistical report validating hypotheses H1–H3. Driven by `setup_scenarios.sh` then `indexes/report/gen_report.py`.

### Dual-index control

Each scenario is generated **once** (`indexes/<key>/events.ndjson`) and indexed **twice**. The only difference is the ingest pipeline:

| Condition | Index | Pipeline | Output |
|---|---|---|---|
| Baseline | `<key>_baseline` | `baseline-detection-pipeline` | `baseline.risk_score` + `baseline.priority` — signature + threshold rules only, **no** `pii.context` |
| Enriched | `<key>_enriched` | `pii-context-enrich-pipeline` | populated `pii.context.*` namespace |

Every event has ground-truth `labels.is_malicious` and is mixed with benign noise (some tuned to trip standard rules → realistic baseline false positives). Scenarios: `s1_rat`, `s2_ato`, `s3_insider`, `s4_sqli`, `s5_ransomware` (see README for MITRE chains). `s1_rat` is the primary/PoC scenario and supersedes the legacy `rat_scored`.

### Enriched scoring — v7 PII promotion model (`indexes/lib/scoring.py`)

**The PII context is a bounded, weighted promotion layer** (Praxis v7 revision, §3.6). `pii.context.base_alert_severity` is scored **0–100 by the same standard-detection formula as the baseline** (`S_BASE` ≡ `S_BASELINE`) and owns the base tier (high ≥60 · medium 40–59 · low <40 — **never critical on its own**). Three **bounded, individually-stored contributions** are then **added** to it, giving a decomposed, defensible escalation:

> `composite_risk_score = base + contrib_pii(0–25) + contrib_asset(0–20) + contrib_complexity(0–15)`. Impact caps (PII 25 + asset 20 = 45) dominate the likelihood cap (complexity 15), so a confirmed attack on Tier-1/2 PII reaches **critical** while a sophisticated attack on non-sensitive data is capped at **high** (NIST SP 800-30r1: Risk = f(Impact, Likelihood)). The **critical tier is gated on a confirmed PII attack**: a ≥80 score promotes to `critical` **only if `pii_tier_rank ∈ {1,2}` AND (explicit `metadata.pii_type` present OR `technique_count ≥ 1`)** — i.e. Tier-1/2 PII target *plus* real evidence of an active attack (observed PII exposure or ≥1 correlated MITRE technique). Ambient traffic on a PII-holding asset (inferred PII, `technique_count 0`) caps at high — this keeps quiet asset-adjacent noise out of the critical tier (§3.6). Benign traffic that genuinely carries the confirmatory signals still promotes: authorized bulk PII exports (Tier-1 `pii_type` + correlated techniques + large volume, injected by `scatter_benign`) are the model's realistic false positives, so pooled enriched TPR@high is **0.773**, not 1.0. Weights cited to NIST SP 800-122 / FIPS 199 / IBM–Ponemon 2025.

| `pii.context.*` field | Meaning |
|---|---|
| `base_alert_severity` (0–100) | standard-detection score; identical formula to `baseline.risk_score` |
| `base_priority` | tier from base score alone: high ≥60 · medium 40–59 · low <40 (never critical) |
| `asset_criticality` (0–25) | `max(src,dst)` criticality via `asset-criticality-policy` enrich, halved (raw input) |
| `pii_exposure_tier` (0–25) / `pii_tier_rank` (1–4) | 4-tier taxonomy (T1/T2/T3/T4) + volume bonus; rank gates critical |
| `attack_complexity` (5–20) | from `metadata.technique_count` (raw input) |
| `contrib_pii` (0–25) / `contrib_asset` (0–20) / `contrib_complexity` (0–15) | the three bounded contributions added to base; `contrib_complexity = attack_complexity − 5`, `contrib_asset = round(20·asset_criticality/25)` |
| `promoted` (bool) | did the alert reach the PII-gated critical tier (`priority == 'critical'`) |
| `priority` | tier of `composite_risk_score`, with critical gated on `pii_tier_rank ∈ {1,2}` |
| `composite_risk_score` | enriched risk = `base + contrib_pii + contrib_asset + contrib_complexity` (≤100); stacked "why critical" breakdown sums exactly to it |

PII tier is from explicit `metadata.pii_type`, else **inferred** from `pii.context.data_classification`. The **baseline keeps its own critical tier** (loud raw signals ≥80) — enrichment *adds* the stealthy PII criticals baseline under-rates as high/medium. **Actionable high-priority queue:** baseline = high+critical (≥60); enriched = the promoted **critical** tier.

The enrich policy `asset-criticality-policy` reads `asset_inventory` (28 hosts: IP → `asset_criticality` 0–50, `asset_type`, `data_classification`) and **must expose all three enrich_fields** including `data_classification` — otherwise PII inference silently returns 0. An enrich policy cannot be deleted while an ingest pipeline references it, so `setup_scenarios.sh` drops the pipelines *before* recreating the policy.

### Validation report (§3.8.4)

`indexes/report/gen_report.py` (uses `metrics.py` + `stats.py`):
- Metrics: high-priority volume, TPR@high, FPR@high, recall; secondary: alert-distribution shift, PII-exposure coverage, risk-score precision, early-detection rate. Under v7 the enriched high-priority set is the **promoted critical tier** (`_e_hp` in `metrics.py`), vs baseline high+critical (`_b_hp`, score ≥60) — this is where the promotion model's noise reduction (210→44 alerts pooled, 79% cut) and TPR gain (0.195→0.773, z=7.64, p<0.001) are realized.
- Tests (pure Python, no scipy): **paired t-test + Cohen's d** (simulated triage time, H1), **two-proportion z-test** (TPR@high, H2; early-detection, H3), **independent t-test + Levene** (composite of TP vs FP).
- Triage time is a documented deterministic **model** (no human analysts) — see the model constants at the top of `metrics.py`.
- Outputs: `praxis_validation_report.{docx,md}` + `metrics_raw.csv`; also seeds `praxis_results` and imports the Kibana "Validation Results" dashboard.

## Re-seeding after a stack rebuild

```bash
source .env; export ES_PASS
ES_PASS=$ES_PASS bash setup_scenarios.sh          # 5 scenarios × 2 conditions + dashboards
ES_PASS=$ES_PASS python3 indexes/report/gen_report.py   # metrics + stats + report
# legacy single-index prototypes (optional):
ES_PASS=$ES_PASS bash indexes/forensics/setup.sh
```

## Shared library (`indexes/lib/`)

| Module | Purpose |
|---|---|
| `topology.py` | per-scenario IPs, sensors, correlation windows, BASE timestamps, and the `ASSETS` inventory (single source of truth) |
| `mitre.py` | ATT&CK technique table |
| `events.py` | `event()` ECS builder, `scatter_benign()` noise (+ `hard` authorized-bulk edge cases), `annotate_technique_counts()`, dual-index `write_events()` |
| `scoring.py` | builds both ingest pipelines + index mappings + asset-inventory ndjson (CLI: `assets`, `enrich-pipeline`, `baseline-pipeline`, `enriched-mapping`, `baseline-mapping`) |
| `lens_dsl.py` | Kibana 9.3 Lens saved-object DSL (4-band palette) + `build_scenario_dashboard()` |
| `stats.py` | pure-Python paired/independent t-test, Levene, two-proportion z, Cohen's d, t/F/normal p-values |

Each `indexes/<key>/gen_events.py` imports the lib and emits `events.ndjson`; `gen_dashboard.py` is a thin wrapper over `build_scenario_dashboard()`.

## Data Schema (ECS + extensions)

Key fields: `source.ip`/`destination.ip`/`destination.port`, `network.transport`, `threat.name`, `event.severity`, `event.norm_risk_level`, `metadata.former_category` (TROJAN/MALWARE/EXFIL/RANSOMWARE/WEBATTACK/C2/INSIDER/SCAN/AUTH/POLICY/RECON/LATERAL), `metadata.flowbits`, `metadata.pii_type`, `metadata.correlation_id`, `metadata.mitre_technique`, `metadata.technique_count`, `custom.str1` (attack phase), `labels.is_malicious`, `observer.hostname`.

Custom namespaces: **`pii.context.*`** (enriched scores, present only in enriched indices) and **`baseline.*`** (baseline scores). Standard-rule signals used by the baseline pipeline: `metadata.ps_encoded`, `metadata.auth_result`, `metadata.geo_anomaly`, `metadata.db_rows`, plus large-transfer from `source/destination.bytes`.

### Legacy indexes

`forensics` (5 real Suricata alerts) and the prototypes `test_rat` / `rat_scored` use an older single-index model — `forensics`/`test_rat` a `risk_score` runtime field, `rat_scored` the old `score.*` ingest pipeline (base 0–45 / pii 2–20 / complexity 4–10). These are superseded by the v6 dual-index scenarios but remain for reference. Note the historical field-name gotcha: `forensics` uses `doc['metadata.former_category.keyword']` in Painless (text+keyword) while `test_rat` uses `doc['metadata.former_category']` (native keyword).

## Kibana API Notes

All Kibana API calls require `-H "kbn-xsrf: true"`.

Import saved objects:

```bash
curl -sk -u elastic:$ES_PASS -XPOST "$KB/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" -F "file=@dashboard.ndjson;type=application/ndjson"
```

**Lens objects must set `coreMigrationVersion: "8.8.0"` and `typeMigrationVersion: "10.1.0"`.** An earlier `typeMigrationVersion` makes Kibana strip `datasourceStates.formBased.layers`, producing empty "could not find datasource" panels. The `lens_dsl.py` helpers set these automatically. Each lens object's `references` array needs one `indexpattern-datasource-layer-<layerId>` entry per layer pointing at the data view id.

## Logstash Pipelines

`logstash-pipeline.tar.gz` extracts to `~/.persistent/logstash/pipeline/` and defines 9 pipelines (inputs → per-source filters → validator → outputs). Valid events route to `forensics`; parse failures go to `failed-logs`. Sources: suricata, paloalto-suite, mcafee, windows, wazuh.
