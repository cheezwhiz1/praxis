#!/bin/bash
# Sets up the test_rat index (financial RAT simulation), data view, and Kibana dashboard.
# Safe to re-run: existing index and saved objects are overwritten.
set -euo pipefail

ES_URL="${ES_URL:-https://192.168.86.39:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-}"
[[ -z "$ES_PASS" ]] && { printf 'Set ES_PASS env var before running.\n' >&2; exit 1; }
KB_URL="${KB_URL:-https://192.168.86.39:5601}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ok()  { printf '\033[32m✓\033[0m %s\n' "$*"; }
err() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

CURL="curl -sk -u ${ES_USER}:${ES_PASS}"

# ── 1. Create index with mapping and risk_score runtime field ─────────────────
printf 'Creating test_rat index...\n'
${CURL} -XDELETE "${ES_URL}/test_rat" > /dev/null 2>&1 || true
${CURL} -XPUT "${ES_URL}/test_rat" \
  -H 'Content-Type: application/json' -d '{
  "mappings": {
    "runtime": {
      "risk_score": {
        "type": "long",
        "script": {
          "source": "int score = 0; if (doc.containsKey(\"event.severity\") && doc[\"event.severity\"].size() > 0) { long sev = doc[\"event.severity\"].value; if (sev == 1) score += 30; else if (sev == 2) score += 20; else if (sev == 3) score += 10; else score += 5; } if (doc.containsKey(\"event.norm_risk_level\") && doc[\"event.norm_risk_level\"].size() > 0) { String lvl = doc[\"event.norm_risk_level\"].value; if (lvl == \"Critical\") score += 30; else if (lvl == \"High\") score += 25; else if (lvl == \"Medium\") score += 15; else if (lvl == \"Low\") score += 5; } if (doc.containsKey(\"metadata.former_category\") && doc[\"metadata.former_category\"].size() > 0) { String cat = doc[\"metadata.former_category\"].value; if (cat == \"TROJAN\") score += 25; else if (cat == \"MALWARE\") score += 25; else if (cat == \"EXFIL\") score += 25; else if (cat == \"EXPLOIT\") score += 22; else if (cat == \"SCAN\") score += 10; else if (cat == \"POLICY\") score += 8; } if (doc.containsKey(\"metadata.flowbits\")) { for (String bit : doc[\"metadata.flowbits\"]) { if (bit == \"ET.Evil\") score += 3; else if (bit == \"ET.Malware\") score += 3; else if (bit == \"ET.BotCC\") score += 3; else if (bit == \"ET.ThreatIntel\") score += 2; else if (bit == \"ET.RAT\") score += 3; else if (bit == \"ET.Exploit\") score += 3; else if (bit == \"ET.DNSTunnel\") score += 2; } } if (doc.containsKey(\"destination.port\") && doc[\"destination.port\"].size() > 0) { long port = doc[\"destination.port\"].value; if (port == 3389 || port == 445 || port == 1433) score += 5; else if (port == 8080 || port == 8443) score += 3; } emit((long) Math.min(score, 100));"
        }
      }
    },
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
      "metadata":      {"properties": {"former_category": {"type": "keyword"}, "flowbits": {"type": "keyword"}, "affected_product": {"type": "keyword"}, "attack_target": {"type": "keyword"}, "pii_type": {"type": "keyword"}}},
      "custom":        {"properties": {"str1": {"type": "keyword"}}}
    }
  }
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('acknowledged' if d.get('acknowledged') else d)" \
  && ok "test_rat index created" || err "Failed to create index"

# ── 2. Bulk insert events ─────────────────────────────────────────────────────
printf 'Inserting events...\n'
result=$(${CURL} -XPOST "${ES_URL}/test_rat/_bulk" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary "@${DIR}/events.ndjson")
errors=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(1 for i in d['items'] if 'error' in i.get('index',{})))")
count=$(echo "$result"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['items']))")
[[ "$errors" == "0" ]] && ok "Inserted ${count} events" || err "${errors} bulk errors"

# ── 3. Create Kibana data view ────────────────────────────────────────────────
printf 'Creating data view...\n'
${CURL} -XDELETE "${KB_URL}/api/data_views/data_view/test-rat-dataview" \
  -H 'kbn-xsrf: true' > /dev/null 2>&1 || true
${CURL} -XPOST "${KB_URL}/api/data_views/data_view" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
  "data_view": {
    "id": "test-rat-dataview",
    "title": "test_rat",
    "timeFieldName": "@timestamp",
    "name": "TEST_RAT (Financial RAT Simulation)"
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

printf '\nDone. Dashboard: %s/app/dashboards#/view/rat-dashboard\n' "${KB_URL}"
printf 'Time range: 2026-05-20 to 2026-05-27 (attack simulation window)\n'
