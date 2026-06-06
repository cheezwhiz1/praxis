# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Stack

Elasticsearch 9.3.0 / Kibana 9.3.0 / Logstash 9.3.0 running as Docker Swarm services on a single node. All three are deployed via `elastic.sh`, which generates SSL certs, writes compose files to `~/elastic/`, and brings up the stack. The cluster is single-node so `forensics` and `test_rat` indexes will always be yellow (replica shard unassigned — expected).

- Elasticsearch: `https://192.168.86.45:9200`
- Kibana: `https://192.168.86.45:5601`
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
| `rat_scored` | 31 | MediBank RAT campaign with additive composite risk scoring (0–200), 7 attack phases |

Each index directory contains:
- `events.ndjson` — Elasticsearch `_bulk` format, ready to POST directly
- `dashboard.ndjson` — Kibana saved objects (16 panels + dashboard), ready to import
- `setup.sh` — idempotent: drops and recreates the index, inserts events, creates data view, imports dashboard
- `gen_dashboard.py` — Python script that regenerates `dashboard.ndjson`
- `gen_events.py` (test_rat only) — Python script that regenerates `events.ndjson`

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

Both indexes use [ECS](https://www.elastic.co/guide/en/ecs/current/index.html) field naming. Key fields:

- `source.ip` / `destination.ip` / `destination.port`
- `network.transport`
- `threat.name` — Suricata signature string
- `event.severity` (1=highest), `event.norm_risk_level` (Critical/High/Medium/Low)
- `metadata.former_category` — threat category (TROJAN, MALWARE, EXFIL, COMPROMISED, Dshield…)
- `metadata.flowbits` — ET flowbit tags (ET.Evil, ET.RAT, ET.BotCC…)
- `observer.hostname` — NIDS sensor name
- `custom.str1` — attack phase (test_rat only: initial_access, c2_establishment, etc.)
- `metadata.pii_type` — type of PII targeted (test_rat only)

### risk_score runtime field

Both indexes have a `risk_score` Painless runtime field (0–100) computed at query time from severity, norm_risk_level, former_category, flowbits, and destination port. No reindex needed when the script changes — update via `PUT /<index>/_mapping`.

**Critical field name difference between indexes:**
- `forensics`: `metadata.former_category` is `text+keyword`, so Painless must use `doc['metadata.former_category.keyword']`
- `test_rat`: `metadata.former_category` is mapped as native `keyword`, so Painless uses `doc['metadata.former_category']` (no `.keyword`)

## Kibana API Notes

All Kibana API calls require the `kbn-xsrf: true` header.

### Importing saved objects

```bash
curl -sk -u elastic:$ES_PASS -XPOST "https://192.168.86.45:5601/api/saved_objects/_import?overwrite=true" \
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
