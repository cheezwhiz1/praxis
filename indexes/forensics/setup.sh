#!/bin/bash
# Sets up the forensics index, data view, and Kibana dashboard.
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

# ── 1. Create index with mapping and risk_score runtime field ─────────────────
printf 'Creating forensics index...\n'
status=$(${CURL} -o /dev/null -w '%{http_code}' -XDELETE "${ES_URL}/forensics" 2>/dev/null || true)
${CURL} -XPUT "${ES_URL}/forensics" \
  -H 'Content-Type: application/json' -d '{
  "mappings": {
    "runtime": {
      "risk_score": {
        "type": "long",
        "script": {
          "source": "int score = 0; if (doc.containsKey(\"event.severity\") && doc[\"event.severity\"].size() > 0) { long sev = doc[\"event.severity\"].value; if (sev == 1) score += 30; else if (sev == 2) score += 20; else if (sev == 3) score += 10; else score += 5; } if (doc.containsKey(\"event.norm_risk_level.keyword\") && doc[\"event.norm_risk_level.keyword\"].size() > 0) { String lvl = doc[\"event.norm_risk_level.keyword\"].value; if (lvl == \"High\") score += 25; else if (lvl == \"Medium\") score += 15; else if (lvl == \"Low\") score += 5; } if (doc.containsKey(\"metadata.former_category.keyword\") && doc[\"metadata.former_category.keyword\"].size() > 0) { String cat = doc[\"metadata.former_category.keyword\"].value; if (cat == \"COMPROMISED\") score += 25; else if (cat == \"Dshield\") score += 20; else if (cat == \"POLICY\") score += 10; } if (doc.containsKey(\"metadata.flowbits.keyword\")) { for (String bit : doc[\"metadata.flowbits.keyword\"]) { if (bit == \"ET.Evil\") score += 10; else if (bit == \"ET.DshieldIP\") score += 5; } } if (doc.containsKey(\"destination.port\") && doc[\"destination.port\"].size() > 0) { long port = doc[\"destination.port\"].value; if (port == 3389 || port == 445) score += 15; else if (port == 22 || port == 389 || port == 636) score += 10; else if (port == 80 || port == 443) score += 5; else score += 2; } emit((long) Math.min(score, 100));"
        }
      }
    }
  }
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('acknowledged' if d.get('acknowledged') else d)" \
  && ok "forensics index created" || err "Failed to create index"

# ── 2. Bulk insert events ─────────────────────────────────────────────────────
printf 'Inserting events...\n'
result=$(${CURL} -XPOST "${ES_URL}/forensics/_bulk" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary "@${DIR}/events.ndjson")
errors=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(1 for i in d['items'] if 'error' in i.get('index',{})))")
count=$(echo "$result"  | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['items']))")
[[ "$errors" == "0" ]] && ok "Inserted ${count} events" || err "${errors} bulk errors"

# ── 3. Create Kibana data view ────────────────────────────────────────────────
printf 'Creating data view...\n'
${CURL} -XDELETE "${KB_URL}/api/data_views/data_view/forensics-dataview" \
  -H 'kbn-xsrf: true' > /dev/null 2>&1 || true
${CURL} -XPOST "${KB_URL}/api/data_views/data_view" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{
  "data_view": {
    "id": "forensics-dataview",
    "title": "forensics",
    "timeFieldName": "@timestamp",
    "name": "Forensics (Suricata)"
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

printf '\nDone. Dashboard: %s/app/dashboards#/view/forensics-dashboard\n' "${KB_URL}"
