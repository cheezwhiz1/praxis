# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack

Elasticsearch 9.3.0 / Kibana 9.3.0 / Logstash 9.3.0 running as Docker Swarm services on a single node. All three are deployed via `elastic.sh`, which generates SSL certs, writes compose files to `~/elastic/`, and brings up the stack. The cluster is single-node so `forensics` and `test_rat` indexes will always be yellow (replica shard unassigned — expected).

- Elasticsearch: `https://192.168.86.39:9200`
- Kibana: `https://192.168.86.39:5601`
- Default user: `elastic` — password in `.env` as `ES_PASS`

## Credentials

Load from `.env` before running any scripts:

```bash
source .env   # exports ES_PASS
```

All curl commands to the cluster use `-sk -u elastic:$ES_PASS` (self-signed cert, no verify).

## Indexes

Three indexes live in `indexes/`:

| Index | Events | Purpose |
|-------|--------|---------|
| `forensics` | 5 | Real Suricata IDS alerts (ECS format via Logstash) |
| `test_rat` | 36 | Synthetic financial RAT simulation, 6 attack phases |
| `rat_scored` | 31 | MediBank RAT campaign with additive composite risk scoring (0–100), 7 attack phases |

Each index directory contains:
- `events.ndjson` — Elasticsearch `_bulk` format, ready to POST directly
- `dashboard.ndjson` — Kibana saved objects (16 panels + dashboard), ready to import
- `setup.sh` — idempotent: drops and recreates the index, inserts events, creates data view, imports dashboard
- `gen_dashboard.py` — Python script that regenerates `dashboard.ndjson`
- `gen_events.py` (test_rat and rat_scored) — Python script that regenerates `events.ndjson`

`rat_scored` also contains:
- `asset_inventory.ndjson` — bulk seed data for the `asset_inventory` index (IP → criticality lookup)

### Re-seeding after a stack rebuild

```bash
source .env
ES_PASS=$ES_PASS bash indexes/forensics/setup.sh
ES_PASS=$ES_PASS bash indexes/test_rat/setup.sh
ES_PASS=$ES_PASS bash indexes/rat_scored/setup.sh
```

### Updating a dashboard

Edit `gen_dashboard.py`, then regenerate and apply:

```bash
python3 indexes/test_rat/gen_dashboard.py   # writes to /tmp/rat_dashboard.ndjson
# then copy output back and re-run setup.sh, or import directly via API
```

## Logstash Pipelines

`logstash-pipeline.tar.gz` extracts to `~/.persistent/logstash/pipeline/` and defines 9 pipelines (inputs → per-source filters → validator → outputs). All valid events route to the `forensics` index; parse failures go to `failed-logs`. Each source (suricata, paloalto-suite, mcafee, windows, wazuh) follows the pattern:

```
<source>/
  *.conf           # numbered filter stages
  resources/       # test injection scripts and sample log files
  dashboard/       # Kibana saved objects NDJSON
  catalogs/        # forensic schema ZIPs
```

## Data Schema

All indexes use [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) field naming. Key fields:

- `source.ip` / `destination.ip` / `destination.port`
- `network.transport`
- `threat.name` — Suricata signature string
- `event.severity` (1=highest), `event.norm_risk_level` (Critical/High/Medium/Low)
- `metadata.former_category` — threat category (TROJAN, MALWARE, EXFIL, COMPROMISED, Dshield…)
- `metadata.flowbits` — ET flowbit tags (ET.Evil, ET.RAT, ET.BotCC…)
- `observer.hostname` — NIDS sensor name
- `custom.str1` — attack phase (test_rat and rat_scored: initial_access, c2_establishment, etc.)
- `metadata.pii_type` — type of PII targeted (test_rat and rat_scored)
- `metadata.correlation_id` — 4-hour window grouping key (rat_scored only)

### risk_score runtime field (forensics and test_rat)

`forensics` and `test_rat` have a `risk_score` Painless runtime field (0–100) computed at query time from severity, norm_risk_level, former_category, flowbits, and destination port. No reindex needed when the script changes — update via `PUT /<index>/_mapping`.

**Critical field name difference between indexes:**
- `forensics`: `metadata.former_category` is `text+keyword`, so Painless must use `doc['metadata.former_category.keyword']`
- `test_rat`: `metadata.former_category` is mapped as native `keyword`, so Painless uses `doc['metadata.former_category']` (no `.keyword`)

### rat_scored ingest pipeline

`rat_scored` uses `rat-scoring-pipeline` (an ES ingest pipeline) instead of a runtime field. Scores are written to stored `score.*` integer fields at bulk-ingest time. Pipeline processors in order:

| Processor | Type | Input → Output |
|---|---|---|
| Asset lookup (dst) | Enrich (`asset-criticality-policy`) | `destination.ip` → `_dst_asset` temp field |
| Asset lookup (src) | Enrich (`asset-criticality-policy`) | `source.ip` → `_asset` temp field |
| Asset score | Painless script | `max(src, dst)` criticality → `score.asset_criticality` (0–25), `score.asset_type` |
| Base alert severity | Painless script | `norm_risk_level` + `former_category` + `flowbits` → `score.base_alert_severity` (0–45) |
| PII exposure tier | Painless script | `type_tier (0–15) + volume_bonus (0–5)` → `score.pii_exposure_tier` (2–20), `score.pii_label` |
| Attack complexity | Painless script | `custom.str1` phase + `former_category` technique bonus → `score.attack_complexity` (4–10) |
| Composite | Painless script | Additive sum of all four → `score.composite` (8–100) |

**Asset scoring** uses the higher-criticality endpoint (source or destination) so that events targeting a high-value server (e.g., recon probing the payment server) reflect the target's risk, not just the attacker's compromised host.

**PII scoring** uses an additive model: `type_tier (0–15) + volume_bonus (0–5, capped at 20)`. Type tiers: explicit financial PII→15, medical/mixed→10; inferred from asset_type: payment_server→12, database_server→9, domain_controller→8, finance_workstation→6, exec_workstation→4, none→0 (floor at 2). Volume bonus is derived from `max(source.bytes, destination.bytes)`: ≥100MB→5, ≥10MB→4, ≥1MB→3, ≥100KB→2, ≥1KB→1. Volume bonus only applies when type_tier>0. This means a 256-byte recon probe to the payment server scores 12 while a 100MB payment_card_full_track exfil scores 20 — volume of data movement directly influences severity.

**Color bands** (all five gauges): Green 0–40 · Yellow 40–68 · Red 68–100.

The enrich policy (`asset-criticality-policy`) reads from the `asset_inventory` index (seeded by `asset_inventory.ndjson`). Both the policy and index are created by `setup.sh` before the bulk ingest. The pipeline must be passed explicitly: `POST /rat_scored/_bulk?pipeline=rat-scoring-pipeline`.

## Kibana API Notes

All Kibana API calls require the `kbn-xsrf: true` header.

### Importing saved objects

```bash
curl -sk -u elastic:$ES_PASS -XPOST "https://192.168.86.39:5601/api/saved_objects/_import?overwrite=true" \
  -H "kbn-xsrf: true" \
  -F "file=@dashboard.ndjson;type=application/ndjson"
```

**`typeMigrationVersion` must be `"10.1.0"`** for Lens objects. Using any earlier version (e.g. `8.3.0`) causes Kibana's migration pipeline to strip `datasourceStates.formBased.layers`, producing empty "could not find datasource" panels. Always include both:

```json
"coreMigrationVersion": "8.8.0",
"typeMigrationVersion": "10.1.0"
```

### Lens visualization format

Generator scripts in this repo use a thin Python DSL (`lens_obj`, `layer`, `count`, `terms`, `avg_agg`, etc.) that produces the correct Kibana 9.3 Lens saved object structure. Each `lens` object's `references` array must contain one entry per layer with `"name": "indexpattern-datasource-layer-<layerId>"` pointing to the data view ID.
