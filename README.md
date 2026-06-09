# praxis

ELK stack deployment and forensics index tooling for Suricata IDS analysis and threat simulation.

## Stack

Elasticsearch / Kibana / Logstash 9.3.0 running as Docker Swarm services.

| Service | URL |
|---------|-----|
| Kibana | https://192.168.86.39:5601 |
| Elasticsearch | https://192.168.86.39:9200 |

## Setup

### 1. Start the stack

```bash
./elastic.sh
```

Pulls images, generates SSL certs, writes compose files to `~/elastic/`, and brings up all three services.

### 2. Configure credentials

Create `.env` (not committed):

```bash
ES_PASS=your_password
```

### 3. Seed indexes

```bash
source .env
ES_PASS=$ES_PASS bash indexes/forensics/setup.sh
ES_PASS=$ES_PASS bash indexes/test_rat/setup.sh
ES_PASS=$ES_PASS bash indexes/rat_scored/setup.sh
```

Each script creates the index, inserts events, creates a Kibana data view, and imports the dashboard. Safe to re-run.

## Indexes

| Index | Events | Dashboard |
|-------|--------|-----------|
| `forensics` | 5 Suricata IDS alerts | `/app/dashboards#/view/forensics-dashboard` |
| `test_rat` | 36 financial RAT simulation events | `/app/dashboards#/view/rat-dashboard` |
| `rat_scored` | 31 MediBank RAT campaign events | `/app/dashboards#/view/rat-scored-dashboard` |

`forensics` and `test_rat` include a `risk_score` runtime field (0–100) computed from severity, risk level, threat category, flowbits, and destination port.

`rat_scored` uses a four-component additive scoring model. Scores are **computed at index time** by the `rat-scoring-pipeline` ES ingest pipeline — they are not hardcoded in the event data.

| Field | Range | Computed from |
|-------|-------|---------------|
| `score.base_alert_severity` | 0–45 | `norm_risk_level` + `former_category` + `flowbits` (Painless) |
| `score.asset_criticality` | 0–25 | `max(source.ip, destination.ip)` → `asset_inventory` enrich lookup |
| `score.asset_type` | keyword | Asset type of the higher-criticality endpoint (source or destination) |
| `score.pii_exposure_tier` | 2–20 | `type_tier (0–15) + volume_bonus (0–5)`: explicit financial PII→15, medical/mixed→10; inferred from asset_type: payment_server→12, database_server→9, domain_controller→8, finance_workstation→6, exec_workstation→4; volume bonus from `max(source.bytes, destination.bytes)` |
| `score.pii_label` | keyword | Explicit `pii_type` value, or `inferred: <asset_type>`, or `none` |
| `score.attack_complexity` | 4–10 | Attack phase + technique category bonus (EXPLOIT/EXFIL +3, TROJAN/MALWARE +2, SCAN +1) |
| `score.composite` | 8–100 | Additive sum of all four (Painless) |

Asset criticality is sourced from the `asset_inventory` index (7 internal hosts, IP → criticality score), consumed via the `asset-criticality-policy` enrich policy. Both the source and destination IP are looked up; the higher-criticality endpoint wins. This ensures that events _targeting_ a high-value server (e.g., recon probing the payment server) score as highly as events _originating_ from one.

PII scoring uses an additive `type_tier + volume_bonus` model. Type tier is set from `metadata.pii_type` when present; otherwise inferred from `score.asset_type`. Volume bonus (0–5) comes from `max(source.bytes, destination.bytes)` and only applies when type_tier>0 — a 256-byte recon probe to the payment server scores 12 while a 100MB bulk exfiltration scores 20.

The dashboard shows five arc gauges on a unified 0–100 scale. The top gauge displays the average composite score across all matching events; the bottom row shows cumulative step-up gauges (① base → ② +asset → ③ +PII → ④ +complexity). Four legend tables below the step-up gauges show the specific criteria that matched each component. Color bands: green 0–40 · yellow 40–68 · red 68–100.

## Logstash Pipelines

`logstash-pipeline.tar.gz` contains the full Logstash pipeline configuration (extracts to `~/.persistent/`). Pipelines cover Suricata, Palo Alto, McAfee ePO, Windows Security Events, and Wazuh — all routing valid events to the `forensics` index.
