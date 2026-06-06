# praxis

ELK stack deployment and forensics index tooling for Suricata IDS analysis and threat simulation.

## Stack

Elasticsearch / Kibana / Logstash 9.3.0 running as Docker Swarm services.

| Service | URL |
|---------|-----|
| Kibana | https://192.168.86.45:5601 |
| Elasticsearch | https://192.168.86.45:9200 |

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
```

Each script creates the index, inserts events, creates a Kibana data view, and imports the dashboard. Safe to re-run.

## Indexes

| Index | Events | Dashboard |
|-------|--------|-----------|
| `forensics` | 5 Suricata IDS alerts | `/app/dashboards#/view/forensics-dashboard` |
| `test_rat` | 36 financial RAT simulation events | `/app/dashboards#/view/rat-dashboard` |

Both indexes include a `risk_score` runtime field (0–100) computed from severity, risk level, threat category, flowbits, and destination port.

## Logstash Pipelines

`logstash-pipeline.tar.gz` contains the full Logstash pipeline configuration (extracts to `~/.persistent/`). Pipelines cover Suricata, Palo Alto, McAfee ePO, Windows Security Events, and Wazuh — all routing valid events to the `forensics` index.
