#!/bin/bash
# Sets up the rat_scored index, scoring pipeline, data view, and Kibana dashboard.
# Safe to re-run: all resources are dropped and recreated.
#
# Scoring pipeline (rat-scoring-pipeline) computes four components at index time:
#   score.base_alert_severity — Painless: former_category + flowbits + norm_risk_level (0-45)
#   score.asset_criticality   — Enrich:   max(source.ip, destination.ip) lookup in asset_inventory (0-25)
#   score.pii_exposure_tier   — Painless: type_tier (explicit/inferred, 0-15) + volume_bonus (0-5) (2-20)
#   score.attack_complexity   — Painless: attack phase + technique category bonus (4-10)
#   score.composite           — Painless: additive sum of all four components (8-100)
set -euo pipefail

ES_URL="${ES_URL:-https://192.168.86.55:9200}"
ES_USER="${ES_USER:-elastic}"
ES_PASS="${ES_PASS:-}"
[[ -z "$ES_PASS" ]] && { printf 'Set ES_PASS env var before running.\n' >&2; exit 1; }
KB_URL="${KB_URL:-https://192.168.86.55:5601}"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

ok()  { printf '\033[32m✓\033[0m %s\n' "$*"; }
err() { printf '\033[31m✗\033[0m %s\n' "$*" >&2; exit 1; }

CURL="curl -sk -u ${ES_USER}:${ES_PASS}"

# ── 1. Asset inventory index ──────────────────────────────────────────────────
printf 'Creating asset_inventory index...\n'
${CURL} -XDELETE "${ES_URL}/asset_inventory" > /dev/null 2>&1 || true
${CURL} -XPUT "${ES_URL}/asset_inventory" \
  -H 'Content-Type: application/json' -d '{
  "mappings": {
    "properties": {
      "ip":                {"type": "keyword"},
      "asset_criticality": {"type": "integer"},
      "asset_type":        {"type": "keyword"},
      "description":       {"type": "text"}
    }
  }
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('acknowledged' if d.get('acknowledged') else d)" \
  && ok "asset_inventory index created" || err "Failed to create asset_inventory"

printf 'Seeding asset inventory...\n'
result=$(${CURL} -XPOST "${ES_URL}/asset_inventory/_bulk" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary "@${DIR}/asset_inventory.ndjson")
errors=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(1 for i in d['items'] if 'error' in i.get('index',{})))")
count=$(echo  "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['items']))")
[[ "$errors" == "0" ]] && ok "Seeded ${count} assets" || err "${errors} bulk errors in asset_inventory"

# ── 2. Enrich policy ──────────────────────────────────────────────────────────
printf 'Creating enrich policy...\n'
${CURL} -XDELETE "${ES_URL}/_enrich/policy/asset-criticality-policy" > /dev/null 2>&1 || true
${CURL} -XPUT "${ES_URL}/_enrich/policy/asset-criticality-policy" \
  -H 'Content-Type: application/json' -d '{
  "match": {
    "indices": "asset_inventory",
    "match_field": "ip",
    "enrich_fields": ["asset_criticality", "asset_type"]
  }
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('acknowledged' if d.get('acknowledged') else d)" \
  && ok "Enrich policy created" || err "Failed to create enrich policy"

printf 'Refreshing asset_inventory before enrich execute...\n'
${CURL} -XPOST "${ES_URL}/asset_inventory/_refresh" > /dev/null

printf 'Executing enrich policy (builds lookup index)...\n'
${CURL} -XPOST "${ES_URL}/_enrich/policy/asset-criticality-policy/_execute" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('completed' if d.get('status',{}).get('phase') == 'COMPLETE' else d)" \
  && ok "Enrich policy executed" || err "Failed to execute enrich policy"

# ── 3. Ingest pipeline ────────────────────────────────────────────────────────
# Pipeline JSON is built by Python so Painless source strings are properly escaped.
printf 'Creating rat-scoring-pipeline...\n'
pipeline_json=$(python3 - <<'PYEOF'
import json

S_ASSET = (
    "int crit = 0; String atype = 'unknown';"
    " if (ctx.containsKey('_asset') && ctx['_asset'] != null) {"
    "   if (ctx['_asset'].containsKey('asset_criticality')) {"
    "     crit = (int) ctx['_asset']['asset_criticality'];"
    "   }"
    "   if (ctx['_asset'].containsKey('asset_type')) {"
    "     atype = ctx['_asset']['asset_type'];"
    "   }"
    " }"
    " if (ctx.containsKey('_dst_asset') && ctx['_dst_asset'] != null) {"
    "   int dstCrit = ctx['_dst_asset'].containsKey('asset_criticality')"
    "     ? (int) ctx['_dst_asset']['asset_criticality'] : 0;"
    "   if (dstCrit > crit) {"
    "     crit = dstCrit;"
    "     if (ctx['_dst_asset'].containsKey('asset_type')) {"
    "       atype = ctx['_dst_asset']['asset_type'];"
    "     }"
    "   }"
    " }"
    " if (!ctx.containsKey('score')) { ctx['score'] = [:]; }"
    " ctx['score']['asset_criticality'] = (int) Math.round(crit / 2.0);"
    " ctx['score']['asset_type'] = atype;"
    " ctx.remove('_asset');"
    " ctx.remove('_dst_asset');"
)

S_BASE = (
    "int score = 0;"
    " if (ctx.containsKey('event') && ctx['event'].containsKey('norm_risk_level')) {"
    "   String lvl = ctx['event']['norm_risk_level'];"
    "   if (lvl == 'Critical') score += 20;"
    "   else if (lvl == 'High') score += 12;"
    "   else if (lvl == 'Medium') score += 6;"
    "   else score += 2;"
    " }"
    " if (ctx.containsKey('metadata') && ctx['metadata'].containsKey('former_category')) {"
    "   String cat = ctx['metadata']['former_category'];"
    "   if (cat == 'EXFIL') score += 22;"
    "   else if (cat == 'TROJAN') score += 20;"
    "   else if (cat == 'MALWARE') score += 20;"
    "   else if (cat == 'EXPLOIT') score += 18;"
    "   else if (cat == 'SCAN') score += 8;"
    "   else if (cat == 'POLICY') score += 5;"
    " }"
    " if (ctx.containsKey('metadata') && ctx['metadata'].containsKey('flowbits')) {"
    "   for (String bit : ctx['metadata']['flowbits']) {"
    "     if (bit == 'ET.Evil') score += 5;"
    "     else if (bit == 'ET.RAT') score += 5;"
    "     else if (bit == 'ET.Exploit') score += 4;"
    "     else if (bit == 'ET.BotCC') score += 4;"
    "     else if (bit == 'ET.Malware') score += 3;"
    "     else if (bit == 'ET.ThreatIntel') score += 3;"
    "     else if (bit == 'ET.DNSTunnel') score += 3;"
    "     else if (bit == 'ET.Scan') score += 1;"
    "   }"
    " }"
    " if (!ctx.containsKey('score')) { ctx['score'] = [:]; }"
    " ctx['score']['base_alert_severity'] = (int) Math.round(Math.min(score, 60) / 60.0 * 45);"
)

S_PII = (
    "int type_tier = 0; String pii_label = 'none';"
    " if (ctx.containsKey('metadata') && ctx['metadata'].containsKey('pii_type')) {"
    "   String pt = ctx['metadata']['pii_type'];"
    "   if (pt == 'payment_card_full_track' || pt == 'credit_card'"
    "       || pt == 'banking_credentials' || pt == 'ssn_dob_full_identity'"
    "       || pt == 'account_number' || pt == 'financial_records'"
    "       || pt == 'payment_card') { type_tier = 15; pii_label = pt; }"
    "   else if (pt == 'medical_financial_records' || pt == 'mixed_pii') { type_tier = 10; pii_label = pt; }"
    " }"
    " if (type_tier == 0 && ctx.containsKey('score') && ctx['score'].containsKey('asset_type')) {"
    "   String at = ctx['score']['asset_type'];"
    "   if (at == 'payment_server')          { type_tier = 12; pii_label = 'inferred: ' + at; }"
    "   else if (at == 'database_server')    { type_tier = 9;  pii_label = 'inferred: ' + at; }"
    "   else if (at == 'domain_controller')  { type_tier = 8;  pii_label = 'inferred: ' + at; }"
    "   else if (at == 'finance_workstation'){ type_tier = 6;  pii_label = 'inferred: ' + at; }"
    "   else if (at == 'exec_workstation')   { type_tier = 4;  pii_label = 'inferred: ' + at; }"
    " }"
    " int vol_bonus = 0;"
    " if (type_tier > 0) {"
    "   long src_b = ctx.containsKey('source') && ctx['source'].containsKey('bytes') ? (long)ctx['source']['bytes'] : 0L;"
    "   long dst_b = ctx.containsKey('destination') && ctx['destination'].containsKey('bytes') ? (long)ctx['destination']['bytes'] : 0L;"
    "   long max_b = src_b > dst_b ? src_b : dst_b;"
    "   if (max_b >= 104857600L) vol_bonus = 5;"
    "   else if (max_b >= 10485760L) vol_bonus = 4;"
    "   else if (max_b >= 1048576L) vol_bonus = 3;"
    "   else if (max_b >= 102400L) vol_bonus = 2;"
    "   else if (max_b >= 1024L) vol_bonus = 1;"
    " }"
    " int tier = (int) Math.min(20, Math.max(2, type_tier + vol_bonus));"
    " if (!ctx.containsKey('score')) { ctx['score'] = [:]; }"
    " ctx['score']['pii_exposure_tier'] = tier;"
    " ctx['score']['pii_label'] = pii_label;"
)

S_CMPLX = (
    "int phase_cmplx = 3;"
    " if (ctx.containsKey('custom') && ctx['custom'].containsKey('str1')) {"
    "   String phase = ctx['custom']['str1'];"
    "   if (phase == 'initial_access')        phase_cmplx = 2;"
    "   else if (phase == 'c2_establishment') phase_cmplx = 3;"
    "   else if (phase == 'reconnaissance')   phase_cmplx = 5;"
    "   else if (phase == 'lateral_movement') phase_cmplx = 5;"
    "   else if (phase == 'privilege_escalation') phase_cmplx = 6;"
    "   else if (phase == 'data_discovery')   phase_cmplx = 7;"
    "   else if (phase == 'exfiltration')     phase_cmplx = 7;"
    " }"
    " int cat_bonus = 0;"
    " if (ctx.containsKey('metadata') && ctx['metadata'].containsKey('former_category')) {"
    "   String cat = ctx['metadata']['former_category'];"
    "   if (cat == 'EXPLOIT') cat_bonus = 3;"
    "   else if (cat == 'EXFIL') cat_bonus = 3;"
    "   else if (cat == 'TROJAN') cat_bonus = 2;"
    "   else if (cat == 'MALWARE') cat_bonus = 2;"
    "   else if (cat == 'SCAN') cat_bonus = 1;"
    " }"
    " if (!ctx.containsKey('score')) { ctx['score'] = [:]; }"
    " ctx['score']['attack_complexity'] = phase_cmplx + cat_bonus;"
)

S_COMP = (
    "int base  = ctx['score'].containsKey('base_alert_severity') ? (int)ctx['score']['base_alert_severity'] : 0;"
    " int asset = ctx['score'].containsKey('asset_criticality')   ? (int)ctx['score']['asset_criticality']   : 0;"
    " int pii   = ctx['score'].containsKey('pii_exposure_tier')   ? (int)ctx['score']['pii_exposure_tier']   : 0;"
    " int cmplx = ctx['score'].containsKey('attack_complexity')   ? (int)ctx['score']['attack_complexity']   : 3;"
    " ctx['score']['composite'] = base + asset + pii + cmplx;"
)

pipeline = {
    "description": "Computes composite risk score components from event fields at index time",
    "processors": [
        {"enrich": {
            "description": "Asset criticality: look up destination.ip in asset_inventory",
            "policy_name": "asset-criticality-policy",
            "field": "destination.ip",
            "target_field": "_dst_asset",
            "ignore_missing": True,
            "ignore_failure": True
        }},
        {"enrich": {
            "description": "Asset criticality: look up source.ip in asset_inventory",
            "policy_name": "asset-criticality-policy",
            "field": "source.ip",
            "target_field": "_asset",
            "ignore_missing": True,
            "ignore_failure": True
        }},
        {"script": {"description": "Move enriched asset_criticality into score object",
                    "lang": "painless", "source": S_ASSET}},
        {"script": {"description": "Base alert severity (0-45): category + flowbits + risk level",
                    "lang": "painless", "source": S_BASE}},
        {"script": {"description": "PII exposure tier (2-20): type_tier (0-15) + volume_bonus (0-5, from max bytes)",
                    "lang": "painless", "source": S_PII}},
        {"script": {"description": "Attack complexity (3-10): MITRE tactic breadth from attack phase",
                    "lang": "painless", "source": S_CMPLX}},
        {"script": {"description": "Composite: additive sum of all four components (8-100)",
                    "lang": "painless", "source": S_COMP}},
    ]
}
print(json.dumps(pipeline))
PYEOF
)
echo "$pipeline_json" | ${CURL} -XPUT "${ES_URL}/_ingest/pipeline/rat-scoring-pipeline" \
  -H 'Content-Type: application/json' -d @- \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('acknowledged' if d.get('acknowledged') else d)" \
  && ok "rat-scoring-pipeline created" || err "Failed to create ingest pipeline"

# ── 4. Create rat_scored index with explicit mapping ──────────────────────────
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
          "asset_type":          {"type": "keyword"},
          "pii_label":           {"type": "keyword"},
          "pii_exposure_tier":   {"type": "integer"},
          "attack_complexity":   {"type": "integer"},
          "composite":           {"type": "integer"}
        }
      }
    }
  }
}' | python3 -c "import sys,json; d=json.load(sys.stdin); print('acknowledged' if d.get('acknowledged') else d)" \
  && ok "rat_scored index created" || err "Failed to create index"

# ── 5. Bulk insert events (pipeline scores each document) ─────────────────────
printf 'Inserting events through scoring pipeline...\n'
result=$(${CURL} -XPOST "${ES_URL}/rat_scored/_bulk?pipeline=rat-scoring-pipeline" \
  -H 'Content-Type: application/x-ndjson' \
  --data-binary "@${DIR}/events.ndjson")
errors=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(sum(1 for i in d['items'] if 'error' in i.get('index',{})))")
count=$(echo  "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d['items']))")
[[ "$errors" == "0" ]] && ok "Inserted ${count} events (pipeline scored)" || err "${errors} bulk errors"

# ── 6. Verify pipeline scores on a sample event ───────────────────────────────
printf 'Verifying pipeline scores...\n'
sleep 1
sample=$(${CURL} "${ES_URL}/rat_scored/_search?size=1&sort=@timestamp:asc" \
  | python3 -c "
import sys, json
d = json.load(sys.stdin)
hit = d['hits']['hits'][0]['_source']
s = hit.get('score', {})
phase = hit.get('custom', {}).get('str1', '?')
print(f'phase={phase}  base={s.get(\"base_alert_severity\")}  asset={s.get(\"asset_criticality\")}  pii={s.get(\"pii_exposure_tier\")}  complexity={s.get(\"attack_complexity\")}  composite={s.get(\"composite\")}')
")
ok "Sample: ${sample}"

# ── 7. Create Kibana data view ────────────────────────────────────────────────
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

printf 'Refreshing data view field list...\n'
${CURL} -XPOST "${KB_URL}/api/data_views/data_view/rat-scored-dataview/fields/refresh" \
  -H 'kbn-xsrf: true' -H 'Content-Type: application/json' -d '{"fieldAttrs": {}}' \
  | python3 -c "import sys,json; d=json.load(sys.stdin); print('ok' if 'fields' in d else d)" \
  && ok "Data view fields refreshed" || err "Failed to refresh data view fields"

# ── 8. Import Kibana dashboard ────────────────────────────────────────────────
printf 'Importing dashboard...\n'
result=$(${CURL} -XPOST "${KB_URL}/api/saved_objects/_import?overwrite=true" \
  -H 'kbn-xsrf: true' \
  -F "file=@${DIR}/dashboard.ndjson;type=application/ndjson")
success=$(echo "$result" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('successCount',0))")
ok "Imported ${success} saved objects"

printf '\nDone. Dashboard: %s/app/dashboards#/view/rat-scored-dashboard\n' "${KB_URL}"
printf 'Time range: 2026-06-15 to 2026-06-19 (7-phase attack simulation)\n'
