# praxis

ELK deployment and validation harness for the **PII Context Framework** — a
context-aware SOC triage model evaluated against five PII-targeting attack
scenarios (Praxis Draft v6). The core artifact is a controlled, two-condition
experiment (baseline vs enriched) whose output is a statistical report validating
research hypotheses **H1–H3**.

## Stack

Elasticsearch / Kibana / Logstash 9.3.0 as Docker Swarm services on a single node.

| Service | URL |
|---------|-----|
| Kibana | https://192.168.86.55:5601 |
| Elasticsearch | https://192.168.86.55:9200 |

The cluster runs on a permanent **Basic** license (all features used here — security,
enrich policies, ingest pipelines, Lens — are Basic-tier). If a request returns
`current license is non-compliant`, run `POST /_license/start_basic?acknowledge=true`.

## Setup

```bash
# 1. credentials (.env, not committed)
echo 'ES_PASS=your_password' > .env
source .env

# 2. (first time only) bring the stack up
./elastic.sh

# 3. build the whole experiment: pipelines, 10 indices, data views, dashboards
ES_PASS=$ES_PASS bash setup_scenarios.sh

# 4. compute metrics + run the §3.8.4 statistics + write the report
ES_PASS=$ES_PASS python3 indexes/report/gen_report.py
```

`setup_scenarios.sh` is idempotent. It seeds `asset_inventory`, creates the enrich
policy and both ingest pipelines, then for each scenario builds the `*_baseline`
and `*_enriched` indices, data views, and dashboard.

## The experiment (dual-index control)

Each scenario is generated **once** and indexed **twice**. The only difference is
which ingest pipeline runs:

| Condition | Index | Pipeline | Scoring |
|---|---|---|---|
| Baseline | `<scenario>_baseline` | `baseline-detection-pipeline` | Signature + standard threshold rules only. No PII context. → `baseline.risk_score` |
| Enriched | `<scenario>_enriched` | `pii-context-enrich-pipeline` | Asset + PII context. → populated `pii.context.*` |

Every event carries a ground-truth `labels.is_malicious` flag and is mixed with
benign business-activity noise (a documented subset trips standard rules to create
realistic false positives). This makes true/false-positive rates measurable.

### Five scenarios (§3.6)

| Key | Scenario | MITRE chain | PII target |
|---|---|---|---|
| `s1_rat` | RAT with PII exfiltration (primary/PoC) | T1566.001→T1547.001→T1083/T1005→T1074.001/T1041 | SSN + bank account |
| `s2_ato` | Credential harvesting → online-banking ATO | T1566.002→T1539/T1185→T1078→T1041 | Banking credentials |
| `s3_insider` | Privileged-insider (DBA) bulk export | T1078.002→T1530→T1048/T1567 | Full customer records |
| `s4_sqli` | SQL injection → web shell → card exfil | T1190→T1505→T1074/T1041 | Cardholder data (PCI) |
| `s5_ransomware` | RaaS double-extortion, pre-encryption exfil | T1133→T1570→T1560/T1537→T1486 | HR + customer PII |

### Composite scoring (enriched, v8 §3.5 / §3.7.4)

`pii.context.composite_risk_score` = sum of four bounded contributions whose maxima
total **exactly 100** (range 5–100):

| Contribution | Range | Computed from |
|---|---|---|
| `contrib_base` | 0–30 | `base_alert_severity` (0–100 standard-detection score) normalized: `round(30·base/100)` |
| `contrib_pii` | 0–25 | discrete 4-tier PII taxonomy (T1 25 / T2 18 / T3 8 / T4 0) |
| `contrib_asset` | 0–25 | higher-criticality endpoint (src/dst) via `asset_inventory` enrich |
| `contrib_complexity` | 5–20 | # distinct MITRE techniques in the correlation window |

**Priority tiers:** critical ≥80 (gated) · high 60–79 · medium 40–59 · low <40.
Because base contributes ≤30, an alert on a non-PII asset maxes at 75 (high) — impact
(25+25) outweighs likelihood (20). Critical is **gated**: composite ≥80 AND Tier-1/2 PII
AND active-attack evidence. Dashboard gauge bands: green <40 · yellow 40–60 · orange
60–80 · red 80+.

The PII tier is taken from an explicit `metadata.pii_type` when present, otherwise
**inferred** from the asset's `data_classification`. So a benign authorized bulk
transfer to a Tier-1 database is elevated by context, while a low-signature
malicious lateral move toward that database — invisible to signature-only
baseline detection — is surfaced as high priority.

## Validation report (§3.8.4)

`indexes/report/gen_report.py` queries both index sets, computes the primary and
secondary metrics, runs the inferential tests in pure Python (no scipy needed) —
**paired t-test + Cohen's d** (triage time), **two-proportion z-test** (TPR@high),
**independent t-test + Levene** (risk-score precision) — and writes:

- `indexes/report/praxis_validation_report.docx` — thesis-ready
- `indexes/report/praxis_validation_report.md` — same content, Markdown
- `indexes/report/metrics_raw.csv` — per-scenario raw numbers

It also seeds the `praxis_results` index and imports the Kibana **Validation
Results** dashboard (the exportable/visual counterpart, since Kibana cannot run
inferential statistics).

## Layout

```
setup_scenarios.sh              orchestration (idempotent)
indexes/lib/                    shared library
  topology.py                     network + asset inventory + PII classification
  mitre.py                        ATT&CK technique tables
  events.py                       ECS event builder + benign noise + dual bulk writer
  scoring.py                      both ingest pipelines + mappings + asset inventory (CLI)
  lens_dsl.py                     Kibana 9.3 Lens dashboard DSL
  stats.py                        paired/independent t, Levene, two-proportion z, Cohen's d
indexes/<scenario>/             gen_events.py, gen_dashboard.py, events.ndjson, dashboard.ndjson
indexes/report/                 metrics.py, gen_report.py, gen_results_dashboard.py + outputs
indexes/forensics/              legacy: 5 real Suricata IDS alerts (runtime risk_score)
```

`test_rat` and `rat_scored` are the earlier single-index prototypes, superseded by
the dual-index scenarios (`s1_rat` supersedes `rat_scored`). They remain on disk for
reference but are not wired into `setup_scenarios.sh`.

## Logstash Pipelines

`logstash-pipeline.tar.gz` extracts to `~/.persistent/` and covers Suricata, Palo
Alto, McAfee ePO, Windows Security Events, and Wazuh — all routing valid events to
the `forensics` index.
