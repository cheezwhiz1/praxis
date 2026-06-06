#!/bin/bash
# Sets up the rat_scored index (composite risk-scored RAT campaign), data view, and Kibana dashboard.
# Safe to re-run: existing index and saved objects are overwritten.
set -euo pipefail

ES_URL="${ES_URL:-https://192.168.86.45:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-}"
[[ -z "$ES_PASS" ]] && { printf 'Set ES_PASS env var before running.\n' >&2; exit 1; }
KB_URL="${KB_URL:-https://192.168.86.45:5601}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ok()  { printf '\033[32m✓\033[0m %s\n' "$*"; }
err() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

CURL="curl -sk -u ${ES_USER}:${ES_PASS}"

# ── 1. Create index with explicit mapping (score fields as integer) ───────────
printf 'Creating rat_scored index...\n'
${CURL} -XDELETE "${ES_URL}/rat_scored" > /dev/null 2>&1 || true
${CURL} -XPUT "${ES_URL}/rat_scored" \
  -H 'Content-Type: application/json' -d '{
  "mappings": {
    "properties": {
      "@timestamp":    {"type": "date"},
      "source":        {"properties": {"ip": {"type": "keyword"}, "port": {"type": "integer"}, "bytes": {"type": "long"}, "packets": {"type": "integer"}}},
      "destination":   {"properties": {"ip": {"type": "keyword"}, "port": {"type": "integer"}, "bytes": {"type": "long"}, "packets": {"type": "integer"}}},
      "network":       {"properties": {"transport": {"type": "keyword"}}},
      "threat":        {"properties": {"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}},
      "event":         {"properties": {"type": {"type": "keyword"}, "severity": {"type": "integer"}, "norm_risk_level": {"type": "keyword"}, "response": {"type": "keyword"}, "action": {"type": "keyword"}}},
      "log":           {"properties": {"level": {"type": "keyword"}}},
      "rule":          {"properties": {"category": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}},
      "observer":      {"properties": {"hostname": {"type": "keyword"}, "product": {"type": "keyword"}, "vendor": {"type": "keyword"}, "type": {"type": "keyword"}, "ingress": {"properties": {"interface": {"properties": {"name": {"type": "keyword"}}}, "vlan": {"properties": {"id": {"type": "integer"}}}}}}},
      "metadata":      {"properties": {"former_category": {"type": "keyword"}, "flowbits": {"type": "keyword"}, "affected_product": {"type": "keyword"}, "attack_target": {"type": "keyword"}, "pii_type": {"type": "keyword"}, "correlation_id": {"type": "keyword"}}},
      "custom":        {"properties": {"str1": {"type": "keyword"}}},
      "score": {
        "properties": {
          "base_alert_severity": {"type": "integer"},
          "asset_criticality":   {"type": "integer"},
          "pii_exposure_tier":   {"type": "integer"},
          "attack_complexity":   {"type": "integer"},
          "composite":           {"type": "integer"}
        }
      }
    }
  }
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('acknowledged' if d.get('acknowledged') else d)" \
  && ok "rat_scored index created" || err "Failed to create index"

# ── 2. Bulk insert events ─────────────────────────────────────────────────────
printf 'Inserting events...\n'
result=$(${CURL} -XPOST "${ES_URL}/rat_scored/_bulk" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary "@${DIR}/events.ndjson")
errors=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(1 for i in d['items'] if 'error' in i.get('index',{})))")
count=$(echo  "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['items']))")
[[ "$errors" == "0" ]] && ok "Inserted ${count} events" || err "${errors} bulk errors"

# ── 3. Create Kibana data view ────────────────────────────────────────────────
printf 'Creating data view...\n'
${CURL} -XDELETE "${KB_URL}/api/data_views/data_view/rat-scored-dataview" \
  -H 'kbn-xsrf: true' > /dev/null 2>&1 || true
${CURL} -XPOST "${KB_URL}/api/data_views/data_view" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
  "data_view": {
    "id": "rat-scored-dataview",
    "title": "rat_scored",
    "timeFieldName": "@timestamp",
    "name": "RAT_SCORED (Composite Risk Score Campaign)"
  }
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if 'data_view' in d else d)" \
  && ok "Data view created" || err "Failed to create data view"

# ── 4. Import Kibana dashboard ────────────────────────────────────────────────
printf 'Importing dashboard...\n'
result=$(${CURL} -XPOST "${KB_URL}/api/saved_objects/_import?overwrite=true" \
  -H 'kbn-xsrf: true' \
  -F "file=@${DIR}/dashboard.ndjson;type=application/ndjson")
success=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('successCount',0))")
ok "Imported ${success} saved objects"

printf '\nDone. Dashboard: %s/app/dashboards#/view/rat-scored-dashboard\n' "${KB_URL}"
printf 'Time range: 2026-06-15 to 2026-06-19 (7-phase attack simulation)\n'
printf '\nScore model ranges:\n'
printf '  Base Alert Severity : 0-60   (avg ~52)\n'
printf '  Asset Criticality   : 0-50   (avg ~33)\n'
printf '  PII Exposure Tier   : 0-50   (avg ~25)\n'
printf '  Attack Complexity   : 10-40  (avg ~30)\n'
printf '  Composite Score     : 10-200 (avg ~140, max 200)\n'
