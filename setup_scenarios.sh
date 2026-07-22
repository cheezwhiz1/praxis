#!/bin/bash
# Praxis v6 — build the full dual-condition experiment in Elasticsearch/Kibana.
#
# For each of the five scenarios this creates two parallel indices that differ
# ONLY in which ingest pipeline runs (the experimental control of §3.4):
#   <scenario>_baseline  <- baseline-detection-pipeline   (signature + threshold rules only)
#   <scenario>_enriched  <- pii-context-enrich-pipeline    (populated pii.context.*)
#
# Idempotent: every resource is dropped and recreated. Safe to re-run.
#   source .env && ES_PASS=$ES_PASS bash setup_scenarios.sh
set -euo pipefail

ES_URL="${ES_URL:-https://192.168.86.55:9200}"
KB_URL="${KB_URL:-https://192.168.86.55:5601}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-}"
[[ -z "$ES_PASS" ]] && { printf 'Set ES_PASS env var before running.\n' >&2; exit 1; }
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB="${DIR}/indexes/lib"
SCENARIOS=(s1_rat s2_ato s3_insider s4_sqli s5_ransomware)

CURL="curl -sk -u ${ES_USER}:${ES_PASS}"
ok()  { printf '\033[32m✓\033[0m %s\n' "$*"; }
err() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }
ack() { python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if d.get('acknowledged') or d.get('successCount') is not None or 'data_view' in d or 'fields' in d else d)"; }

# ── 0. Ensure a valid (basic) license ─────────────────────────────────────────
printf '\n== 0. License ==\n'
lic=$(${CURL} "${ES_URL}/_license" | python3 -c "import sys,json; print(json.load(sys.stdin).get('license',{}).get('status','unknown'))")
if [[ "$lic" != "active" ]]; then
  ${CURL} -XPOST "${ES_URL}/_license/start_basic?acknowledge=true" >/dev/null && ok "Started basic license" || err "License activation failed"
else
  ok "License active ($lic)"
fi

# ── 1. Asset inventory ────────────────────────────────────────────────────────
printf '\n== 1. Asset inventory ==\n'
${CURL} -XDELETE "${ES_URL}/asset_inventory" >/dev/null 2>&1 || true
${CURL} -XPUT "${ES_URL}/asset_inventory" -H 'Content-Type: application/json' -d '{
  "mappings": {"properties": {
    "ip": {"type": "keyword"}, "asset_criticality": {"type": "integer"},
    "asset_type": {"type": "keyword"}, "data_classification": {"type": "keyword"},
    "pii_categories": {"type": "text"}}}}' | ack >/dev/null && ok "asset_inventory index created" || err "asset_inventory create failed"
python3 "${LIB}/scoring.py" assets | ${CURL} -XPOST "${ES_URL}/asset_inventory/_bulk" \
  -H 'Content-Type: application/x-ndjson' --data-binary @- \
  | python3 -c "import sys,json; d=json.load(sys.stdin); e=sum('error' in i.get('index',{}) for i in d['items']); print('bulk errors:',e) if e else print('seeded',len(d['items']),'assets')" \
  && ok "asset_inventory seeded" || err "asset_inventory seed failed"
${CURL} -XPOST "${ES_URL}/asset_inventory/_refresh" >/dev/null

# ── 2. Enrich policy ──────────────────────────────────────────────────────────
printf '\n== 2. Enrich policy ==\n'
# An enrich policy cannot be deleted/updated while an ingest pipeline references it,
# so drop the referencing pipelines first (incl. the legacy rat-scoring-pipeline).
for p in pii-context-enrich-pipeline rat-scoring-pipeline; do
  ${CURL} -XDELETE "${ES_URL}/_ingest/pipeline/${p}" >/dev/null 2>&1 || true
done
${CURL} -XDELETE "${ES_URL}/_enrich/policy/asset-criticality-policy" >/dev/null 2>&1 || true
${CURL} -XPUT "${ES_URL}/_enrich/policy/asset-criticality-policy" -H 'Content-Type: application/json' -d '{
  "match": {"indices": "asset_inventory", "match_field": "ip",
            "enrich_fields": ["asset_criticality", "asset_type", "data_classification"]}}' \
  | ack >/dev/null && ok "enrich policy created" || err "enrich policy failed"
${CURL} -XPOST "${ES_URL}/_enrich/policy/asset-criticality-policy/_execute" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('completed' if d.get('status',{}).get('phase')=='COMPLETE' else d)" >/dev/null \
  && ok "enrich policy executed" || err "enrich execute failed"

# ── 3. Ingest pipelines ───────────────────────────────────────────────────────
printf '\n== 3. Ingest pipelines ==\n'
python3 "${LIB}/scoring.py" enrich-pipeline | ${CURL} -XPUT "${ES_URL}/_ingest/pipeline/pii-context-enrich-pipeline" \
  -H 'Content-Type: application/json' -d @- | ack >/dev/null && ok "pii-context-enrich-pipeline created" || err "enrich pipeline failed"
python3 "${LIB}/scoring.py" baseline-pipeline | ${CURL} -XPUT "${ES_URL}/_ingest/pipeline/baseline-detection-pipeline" \
  -H 'Content-Type: application/json' -d @- | ack >/dev/null && ok "baseline-detection-pipeline created" || err "baseline pipeline failed"

# reusable mapping bodies
ENR_MAP=$(python3 "${LIB}/scoring.py" enriched-mapping)
BAS_MAP=$(python3 "${LIB}/scoring.py" baseline-mapping)

create_index () {  # $1=index  $2=mapping-json  $3=pipeline  $4=events.ndjson
  ${CURL} -XDELETE "${ES_URL}/$1" >/dev/null 2>&1 || true
  echo "$2" | ${CURL} -XPUT "${ES_URL}/$1" -H 'Content-Type: application/json' -d @- | ack >/dev/null \
    || err "index $1 create failed"
  ${CURL} -XPOST "${ES_URL}/$1/_bulk?pipeline=$3&refresh=true" -H 'Content-Type: application/x-ndjson' \
    --data-binary "@$4" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); e=sum('error' in i.get('index',{}) for i in d['items']); sys.exit(1) if e else print('  '+'$1'+':',len(d['items']),'docs')" \
    || { ${CURL} -XPOST "${ES_URL}/$1/_bulk?pipeline=$3" -H 'Content-Type: application/x-ndjson' --data-binary "@$4" | python3 -c "import sys,json; d=json.load(sys.stdin); [print(i['index']['error']) for i in d['items'] if 'error' in i.get('index',{})][:3]"; err "bulk into $1 failed"; }
}

create_data_view () {  # $1=id/title
  ${CURL} -XDELETE "${KB_URL}/api/data_views/data_view/$1" -H 'kbn-xsrf: true' >/dev/null 2>&1 || true
  ${CURL} -XPOST "${KB_URL}/api/data_views/data_view" -H 'kbn-xsrf: true' -H 'Content-Type: application/json' \
    -d "{\"data_view\": {\"id\": \"$1\", \"title\": \"$1\", \"timeFieldName\": \"@timestamp\", \"name\": \"$1\"}}" \
    | ack >/dev/null || err "data view $1 failed"
}

# ── 4. Per-scenario indices, data views, dashboards ───────────────────────────
for s in "${SCENARIOS[@]}"; do
  printf '\n== 4. Scenario %s ==\n' "$s"
  EV="${DIR}/indexes/${s}/events.ndjson"
  [[ -f "$EV" ]] || err "missing ${EV} (run indexes/${s}/gen_events.py)"
  create_index "${s}_baseline" "$BAS_MAP" "baseline-detection-pipeline" "$EV"
  create_index "${s}_enriched" "$ENR_MAP" "pii-context-enrich-pipeline" "$EV"
  create_data_view "${s}_baseline"
  create_data_view "${s}_enriched"
  ${CURL} -XPOST "${KB_URL}/api/data_views/data_view/${s}_enriched/fields/refresh" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{"fieldAttrs":{}}' >/dev/null 2>&1 || true
  ${CURL} -XPOST "${KB_URL}/api/data_views/data_view/${s}_baseline/fields/refresh" \
    -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{"fieldAttrs":{}}' >/dev/null 2>&1 || true
  imp=$(${CURL} -XPOST "${KB_URL}/api/saved_objects/_import?overwrite=true" -H 'kbn-xsrf: true' \
    -F "file=@${DIR}/indexes/${s}/dashboard.ndjson;type=application/ndjson")
  echo "$imp" | python3 -c "import sys,json; d=json.load(sys.stdin); print('  dashboard imported:',d.get('successCount'),'objects','OK' if d.get('success') else d.get('errors'))"
  ok "${s} complete"
done

# ── 5. Sample verification ────────────────────────────────────────────────────
printf '\n== 5. Sample scored events ==\n'
${CURL} "${ES_URL}/s1_rat_enriched/_search?size=1&q=labels.is_malicious:true&sort=%40timestamp:desc" | python3 -c "
import sys,json; h=json.load(sys.stdin)['hits']['hits'][0]['_source']; c=h.get('pii',{}).get('context',{})
print('  enriched sample:', h['threat']['name'][:40], '=> composite', c.get('composite_risk_score'), c.get('priority'),
      '| base',c.get('base_alert_severity'),'asset',c.get('asset_criticality'),'pii',c.get('pii_exposure_tier'),'cmplx',c.get('attack_complexity'))"
${CURL} "${ES_URL}/s1_rat_baseline/_search?size=1&q=labels.is_malicious:true&sort=%40timestamp:desc" | python3 -c "
import sys,json; h=json.load(sys.stdin)['hits']['hits'][0]['_source']; b=h.get('baseline',{})
print('  baseline sample:', h['threat']['name'][:40], '=> risk', b.get('risk_score'), b.get('priority'), '| pii.context present:', 'pii' in h)"

printf '\n\033[32mDone.\033[0m Dashboards: %s/app/dashboards  (search \"—\" or scenario key)\n' "$KB_URL"
