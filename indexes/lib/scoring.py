#!/usr/bin/env python3
"""
Scoring engine: builds the two Elasticsearch ingest pipelines, the index
mappings, and the asset_inventory bulk payload for the Praxis v8 experiment.

Two conditions, one control:
  * ENRICHED  -> `pii-context-enrich-pipeline`  writes pii.context.* (asset lookup,
                 4-tier PII exposure, complexity from MITRE breadth, and a base 0-100
                 severity that is *promoted* to critical for confirmed PII attacks).
  * BASELINE  -> `baseline-detection-pipeline`   writes baseline.* from signature +
                 standard threshold rules ONLY. No asset/PII context, no pii.context.

v8 scoring model (§3.5, §3.7.4, Tables 3.2-3.3): the PII context is a *bounded, weighted
promotion layer* whose four contribution maxima total EXACTLY 100, so no post-hoc cap is
needed and every escalation decomposes into an auditable rationale that sums to the composite.
`base_alert_severity` is scored 0-100 by the SAME standard-detection formula as the baseline
and owns the base tier (high >=60 | medium 40-59 | low <40) -- it never reaches critical on
its own, and it contributes only a NORMALIZED 0-30 to the composite:
  contrib_base       0-30  standard-detection severity, normalized  round(30*base/100)
  contrib_pii        0-25  Impact, primary    (pii_exposure_tier: T1 25|T2 18|T3 8|T4 0)  [NIST SP 800-122]
  contrib_asset      0-25  Impact, secondary  (asset_criticality, 0-25 direct)            [FIPS 199/800-60]
  contrib_complexity 5-20  Likelihood/threat  (attack_complexity, 5-20 direct)            [MITRE ATT&CK]
giving composite_risk_score = contrib_base + contrib_pii + contrib_asset + contrib_complexity.
Because base contributes at most 30, an alert on an asset with NO PII exposure maxes at
30+0+25+20 = 75 (inside high, below the critical threshold 80), so attack sophistication alone
cannot promote a non-PII alert -- impact (25+25) dominates likelihood (20), per NIST SP 800-30r1
Risk = f(Impact, Likelihood). The critical tier is GATED on a CONFIRMED attack targeting PII:
an alert reaches critical only when composite >= 80 AND the target holds Tier-1/2 PII
(pii_tier_rank in {1,2}) AND there is real evidence of an active attack -- observed PII exposure
in the event (explicit metadata.pii_type) OR >=1 correlated MITRE technique. Otherwise a >=80
score is capped to high, so ambient traffic on a PII-holding asset never qualifies (§3.5).
The baseline retains its own critical tier from loud raw signals; enrichment ADDS the missed
PII criticals. High-priority = critical+high (>=60) baseline; promoted-critical enriched.

Run as CLI to emit JSON for setup_scenarios.sh:
  python3 scoring.py assets           # asset_inventory _bulk ndjson
  python3 scoring.py enrich-pipeline   # enriched ingest pipeline JSON
  python3 scoring.py baseline-pipeline # baseline ingest pipeline JSON
  python3 scoring.py enriched-mapping  # enriched index mapping JSON
  python3 scoring.py baseline-mapping  # baseline index mapping JSON
"""
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from topology import ASSETS  # noqa: E402

ENRICH_POLICY = "asset-criticality-policy"
ENRICH_PIPELINE = "pii-context-enrich-pipeline"
BASELINE_PIPELINE = "baseline-detection-pipeline"

# ── Painless: enriched pipeline ───────────────────────────────────────────────
S_ASSET = r"""
if (ctx.pii == null) { ctx.pii = new HashMap(); }
if (ctx.pii.context == null) { ctx.pii.context = new HashMap(); }
int crit = 0; String atype = 'none'; String dclass = 'none';
if (ctx._asset != null) {
  if (ctx._asset.asset_criticality != null) crit = (int) ctx._asset.asset_criticality;
  if (ctx._asset.asset_type != null) atype = (String) ctx._asset.asset_type;
  if (ctx._asset.data_classification != null) dclass = (String) ctx._asset.data_classification;
}
if (ctx._dst_asset != null) {
  int dcrit = ctx._dst_asset.asset_criticality != null ? (int) ctx._dst_asset.asset_criticality : 0;
  if (dcrit > crit) {
    crit = dcrit;
    if (ctx._dst_asset.asset_type != null) atype = (String) ctx._dst_asset.asset_type;
    if (ctx._dst_asset.data_classification != null) dclass = (String) ctx._dst_asset.data_classification;
  }
}
ctx.pii.context.asset_criticality = (int) Math.round(crit / 2.0);
ctx.pii.context.asset_type = atype;
ctx.pii.context.data_classification = dclass;
ctx.remove('_asset'); ctx.remove('_dst_asset');
"""

# base_alert_severity is scored 0-100 by the SAME standard-detection formula the
# baseline pipeline uses (S_BASELINE). This is the "base anomaly risk score ... that
# remains intact" (§3.4); the promotion layer (S_PROMOTE) sits on top of it, so a base
# HIGH alert can escalate to CRITICAL purely from PII context.
S_BASE = r"""
int s = 0;
if (ctx.event != null && ctx.event.norm_risk_level != null) {
  String lvl = ctx.event.norm_risk_level;
  if (lvl == 'Critical') s += 55;
  else if (lvl == 'High') s += 40;
  else if (lvl == 'Medium') s += 25;
  else s += 10;
}
if (ctx.metadata != null && ctx.metadata.former_category != null) {
  String cat = ctx.metadata.former_category;
  if (cat == 'EXFIL' || cat == 'RANSOMWARE') s += 25;
  else if (cat == 'TROJAN' || cat == 'MALWARE' || cat == 'EXPLOIT' || cat == 'WEBATTACK' || cat == 'C2') s += 20;
  else if (cat == 'SCAN' || cat == 'AUTH') s += 8;
  else if (cat == 'POLICY') s += 4;
}
if (ctx.metadata != null && ctx.metadata.flowbits != null) {
  for (def bit : ctx.metadata.flowbits) {
    if (bit == 'ET.Evil' || bit == 'ET.RAT' || bit == 'ET.BotCC' || bit == 'ET.Exploit') { s += 5; break; }
  }
}
long sb = (ctx.source != null && ctx.source.bytes != null) ? ((Number) ctx.source.bytes).longValue() : 0L;
long db = (ctx.destination != null && ctx.destination.bytes != null) ? ((Number) ctx.destination.bytes).longValue() : 0L;
long mx = sb > db ? sb : db;
if (mx >= 52428800L) s += 55;
if (ctx.metadata != null && ctx.metadata.ps_encoded == true) s += 50;
if (ctx.metadata != null && ctx.metadata.auth_result != null && ctx.metadata.auth_result == 'failure') s += 50;
if (ctx.metadata != null && ctx.metadata.geo_anomaly == true) s += 50;
if (ctx.metadata != null && ctx.metadata.db_rows != null && ((Number) ctx.metadata.db_rows).intValue() >= 50000) s += 50;
if (s > 100) s = 100;
ctx.pii.context.base_alert_severity = s;
"""

S_PII = r"""
int tier_pts = 0; int rank = 0; String label = 'none';
String pt = (ctx.metadata != null) ? ctx.metadata.pii_type : null;
if (pt != null) {
  if (pt == 'ssn' || pt == 'ssn_dob_full_identity' || pt == 'payment_card_full_track'
      || pt == 'credit_card' || pt == 'bank_account' || pt == 'account_number'
      || pt == 'banking_credentials' || pt == 'routing_number' || pt == 'financial_records') { tier_pts = 25; rank = 1; label = pt; }
  else if (pt == 'name_dob' || pt == 'account_credentials' || pt == 'session_token' || pt == 'mixed_pii') { tier_pts = 18; rank = 2; label = pt; }
  else if (pt == 'email' || pt == 'phone' || pt == 'address') { tier_pts = 8; rank = 3; label = pt; }
  else { tier_pts = 0; rank = 4; label = pt; }
}
if (tier_pts == 0 && rank == 0) {
  String dc = ctx.pii.context.data_classification;
  if (dc == 'tier1') { tier_pts = 25; rank = 1; label = 'inferred:tier1'; }
  else if (dc == 'tier2') { tier_pts = 18; rank = 2; label = 'inferred:tier2'; }
  else if (dc == 'tier3') { tier_pts = 8; rank = 3; label = 'inferred:tier3'; }
  else if (dc == 'tier4') { tier_pts = 0; rank = 4; label = 'inferred:tier4'; }
}
ctx.pii.context.pii_tier_rank = rank;
// v8 Table 3.2: PII exposure is a discrete per-tier contribution (T1 25 | T2 18 | T3 8 | T4 0),
// no volume bonus — volume/frequency signal is carried by the base score (large-transfer,
// db_rows) and by attack_complexity, keeping the four contributions' maxima summing to exactly 100.
int tier = tier_pts; if (tier > 25) tier = 25;
ctx.pii.context.pii_exposure_tier = tier;
ctx.pii.context.pii_label = label;
"""

S_CMPLX = r"""
int tc = (ctx.metadata != null && ctx.metadata.technique_count != null) ? (int) ctx.metadata.technique_count : 0;
int c = 5;
if (tc >= 2) c = 5 + 3 * (tc - 1);
if (c > 20) c = 20;
ctx.pii.context.attack_complexity = c;
"""

# v8 PROMOTION layer (§3.5, §3.7.4, Tables 3.2-3.3) — a BOUNDED, WEIGHTED promotion in which
# the four contributions' maxima total EXACTLY 100, so no post-hoc cap is required and every
# escalation carries a decomposed, auditable rationale that sums to the composite:
#   contrib_base       0-30  standard-detection severity NORMALIZED  (round(30*base/100))
#   contrib_pii        0-25  Impact, primary    (from pii_exposure_tier: T1 25|T2 18|T3 8|T4 0)
#   contrib_asset      0-25  Impact, secondary  (from asset_criticality, 0-25 direct)
#   contrib_complexity 5-20  Likelihood/threat  (from attack_complexity, 5-20 direct)
# The native 0-100 base severity still owns the BASE tier (low<40 | medium 40-59 | high>=60) and
# never reaches critical on its own. Because base contributes at most 30, an alert against an
# asset carrying NO PII exposure maxes at 30+0+25+20 = 75 — inside the high band, below the
# critical threshold of 80 — so attack sophistication alone cannot promote a non-PII alert
# (NIST SP 800-30r1: Risk = f(Impact, Likelihood); impact 25+25 dominates likelihood 20).
# The CRITICAL tier is additionally GATED: composite >= 80 AND the target holds Tier-1/2 PII
# (rank in {1,2}) AND there is real evidence of an active attack — observed PII exposure in the
# event (explicit metadata.pii_type) OR >=1 correlated MITRE technique. The gate is required
# because asset_criticality is scored independently of PII, so a high composite alone is not
# proof that regulated data is at risk (§3.5). `priority` is authoritative and applies the gate.
S_PROMOTE = r"""
int base = (int) ctx.pii.context.base_alert_severity;
// native 0-100 base severity owns low/medium/high only — critical is context-driven (§3.5)
String bp;
if (base >= 60) bp = 'high';
else if (base >= 40) bp = 'medium';
else bp = 'low';
ctx.pii.context.base_priority = bp;

int pii_t = (ctx.pii.context.pii_exposure_tier != null) ? (int) ctx.pii.context.pii_exposure_tier : 0;
int asset = (ctx.pii.context.asset_criticality != null) ? (int) ctx.pii.context.asset_criticality : 0;
int ac    = (ctx.pii.context.attack_complexity != null) ? (int) ctx.pii.context.attack_complexity : 0;
int rank  = (ctx.pii.context.pii_tier_rank != null) ? (int) ctx.pii.context.pii_tier_rank : 0;

// four bounded contributions — caps 30 / 25 / 25 / 20 (total 100)
int c_base  = (int) Math.round(30.0 * base / 100.0); if (c_base > 30) c_base = 30; if (c_base < 0) c_base = 0;
int c_pii   = pii_t; if (c_pii > 25) c_pii = 25; if (c_pii < 0) c_pii = 0;
int c_asset = asset; if (c_asset > 25) c_asset = 25; if (c_asset < 0) c_asset = 0;
int c_cmplx = ac; if (c_cmplx > 20) c_cmplx = 20; if (c_cmplx < 5) c_cmplx = 5;
ctx.pii.context.contrib_base = c_base;
ctx.pii.context.contrib_pii = c_pii;
ctx.pii.context.contrib_asset = c_asset;
ctx.pii.context.contrib_complexity = c_cmplx;

int enriched = c_base + c_pii + c_asset + c_cmplx;
if (enriched > 100) enriched = 100;
ctx.pii.context.composite_risk_score = enriched;

// tier from the composite; CRITICAL is gated on a CONFIRMED attack targeting PII:
// the target must hold Tier-1/2 PII (rank in {1,2}) AND there must be real evidence of an
// active attack -- observed PII exposure in the event (explicit metadata.pii_type) OR at
// least one correlated MITRE technique. Ambient traffic on a PII-holding asset (inferred
// PII, technique_count 0) therefore does NOT promote -- this keeps the critical tier
// concentrated on confirmed PII attacks rather than asset-adjacent noise (§3.5).
String prio;
if (enriched >= 80) prio = 'critical';
else if (enriched >= 60) prio = 'high';
else if (enriched >= 40) prio = 'medium';
else prio = 'low';
boolean explicit_pii = (ctx.metadata != null && ctx.metadata.pii_type != null);
int tc = (ctx.metadata != null && ctx.metadata.technique_count != null) ? (int) ctx.metadata.technique_count : 0;
boolean confirmed_attack = explicit_pii || tc >= 1;
boolean pii_gate = (rank == 1 || rank == 2) && confirmed_attack;
if (prio == 'critical' && !pii_gate) prio = 'high';   // not a confirmed PII attack -> cap at high

boolean promoted = (prio == 'critical');
ctx.pii.context.promoted = promoted;
ctx.pii.context.priority = prio;
"""

# ── Painless: baseline pipeline (standard SOC, NO PII context) ────────────────
S_BASELINE = r"""
if (ctx.baseline == null) { ctx.baseline = new HashMap(); }
int s = 0;
if (ctx.event != null && ctx.event.norm_risk_level != null) {
  String lvl = ctx.event.norm_risk_level;
  if (lvl == 'Critical') s += 55;
  else if (lvl == 'High') s += 40;
  else if (lvl == 'Medium') s += 25;
  else s += 10;
}
if (ctx.metadata != null && ctx.metadata.former_category != null) {
  String cat = ctx.metadata.former_category;
  if (cat == 'EXFIL' || cat == 'RANSOMWARE') s += 25;
  else if (cat == 'TROJAN' || cat == 'MALWARE' || cat == 'EXPLOIT' || cat == 'WEBATTACK' || cat == 'C2') s += 20;
  else if (cat == 'SCAN' || cat == 'AUTH') s += 8;
  else if (cat == 'POLICY') s += 4;
}
if (ctx.metadata != null && ctx.metadata.flowbits != null) {
  for (def bit : ctx.metadata.flowbits) {
    if (bit == 'ET.Evil' || bit == 'ET.RAT' || bit == 'ET.BotCC' || bit == 'ET.Exploit') { s += 5; break; }
  }
}
long sb = (ctx.source != null && ctx.source.bytes != null) ? ((Number) ctx.source.bytes).longValue() : 0L;
long db = (ctx.destination != null && ctx.destination.bytes != null) ? ((Number) ctx.destination.bytes).longValue() : 0L;
long mx = sb > db ? sb : db;
if (mx >= 52428800L) s += 55;
if (ctx.metadata != null && ctx.metadata.ps_encoded == true) s += 50;
if (ctx.metadata != null && ctx.metadata.auth_result != null && ctx.metadata.auth_result == 'failure') s += 50;
if (ctx.metadata != null && ctx.metadata.geo_anomaly == true) s += 50;
if (ctx.metadata != null && ctx.metadata.db_rows != null && ((Number) ctx.metadata.db_rows).intValue() >= 50000) s += 50;
if (s > 100) s = 100;
ctx.baseline.risk_score = s;
String prio;
if (s >= 80) prio = 'critical';
else if (s >= 60) prio = 'high';
else if (s >= 40) prio = 'medium';
else prio = 'low';
ctx.baseline.priority = prio;
"""


def enrich_pipeline():
    return {
        "description": "v8 PII Context Framework: enrich asset + base severity + PII promotion layer",
        "processors": [
            {"enrich": {"policy_name": ENRICH_POLICY, "field": "destination.ip",
                        "target_field": "_dst_asset", "ignore_missing": True, "ignore_failure": True}},
            {"enrich": {"policy_name": ENRICH_POLICY, "field": "source.ip",
                        "target_field": "_asset", "ignore_missing": True, "ignore_failure": True}},
            {"script": {"lang": "painless", "source": S_ASSET,
                        "description": "asset_criticality (0-25) + data_classification from higher endpoint"}},
            {"script": {"lang": "painless", "source": S_BASE,
                        "description": "base_alert_severity (0-100), same formula as baseline"}},
            {"script": {"lang": "painless", "source": S_PII,
                        "description": "pii_exposure_tier (T1 25|T2 18|T3 8|T4 0) + pii_tier_rank (1-4): 4-tier taxonomy"}},
            {"script": {"lang": "painless", "source": S_CMPLX,
                        "description": "attack_complexity (5-20) from MITRE technique breadth"}},
            {"script": {"lang": "painless", "source": S_PROMOTE,
                        "description": "four bounded contributions (base30/pii25/asset25/complexity20, sum==100) + composite_risk_score + PII-gated critical promotion"}},
        ],
    }


def baseline_pipeline():
    return {
        "description": "Standard SOC detection: signature + threshold rules only, no PII context",
        "processors": [
            {"script": {"lang": "painless", "source": S_BASELINE,
                        "description": "baseline.risk_score (0-100) + priority"}},
        ],
    }


# ── Index mappings ────────────────────────────────────────────────────────────
_COMMON_PROPS = {
    "@timestamp":  {"type": "date"},
    "source":      {"properties": {"ip": {"type": "keyword"}, "port": {"type": "integer"}, "bytes": {"type": "long"}, "packets": {"type": "integer"}}},
    "destination": {"properties": {"ip": {"type": "keyword"}, "port": {"type": "integer"}, "bytes": {"type": "long"}, "packets": {"type": "integer"}}},
    "network":     {"properties": {"transport": {"type": "keyword"}}},
    "threat":      {"properties": {"name": {"type": "text", "fields": {"keyword": {"type": "keyword"}}}}},
    "event":       {"properties": {"type": {"type": "keyword"}, "severity": {"type": "integer"}, "norm_risk_level": {"type": "keyword"}, "category": {"type": "keyword"}, "action": {"type": "keyword"}, "response": {"type": "keyword"}}},
    "log":         {"properties": {"level": {"type": "keyword"}}},
    "rule":        {"properties": {"category": {"type": "keyword"}, "name": {"type": "keyword"}}},
    "observer":    {"properties": {"hostname": {"type": "keyword"}, "product": {"type": "keyword"}, "vendor": {"type": "keyword"}, "type": {"type": "keyword"}, "ingress": {"properties": {"interface": {"properties": {"name": {"type": "keyword"}}}, "vlan": {"properties": {"id": {"type": "integer"}}}}}}},
    "metadata":    {"properties": {
        "former_category": {"type": "keyword"}, "flowbits": {"type": "keyword"},
        "pii_type": {"type": "keyword"}, "correlation_id": {"type": "keyword"},
        "attack_phase": {"type": "keyword"}, "mitre_technique": {"type": "keyword"},
        "technique_count": {"type": "integer"}, "ps_encoded": {"type": "boolean"},
        "auth_result": {"type": "keyword"}, "geo_anomaly": {"type": "boolean"}, "db_rows": {"type": "integer"}}},
    "custom":      {"properties": {"str1": {"type": "keyword"}}},
    "labels":      {"properties": {"is_malicious": {"type": "boolean"}, "scenario": {"type": "keyword"}}},
}

_PII_CONTEXT = {"properties": {"context": {"properties": {
    "asset_criticality":    {"type": "integer"},
    "asset_type":           {"type": "keyword"},
    "data_classification":  {"type": "keyword"},
    "base_alert_severity":  {"type": "integer"},
    "base_priority":        {"type": "keyword"},
    "pii_exposure_tier":    {"type": "integer"},
    "pii_tier_rank":        {"type": "integer"},
    "pii_label":            {"type": "keyword"},
    "attack_complexity":    {"type": "integer"},
    "contrib_base":         {"type": "integer"},
    "contrib_pii":          {"type": "integer"},
    "contrib_asset":        {"type": "integer"},
    "contrib_complexity":   {"type": "integer"},
    "promoted":             {"type": "boolean"},
    "composite_risk_score": {"type": "integer"},
    "priority":             {"type": "keyword"},
}}}}

_BASELINE = {"properties": {"risk_score": {"type": "integer"}, "priority": {"type": "keyword"}}}


def enriched_mapping():
    props = dict(_COMMON_PROPS); props["pii"] = _PII_CONTEXT
    return {"mappings": {"properties": props}}


def baseline_mapping():
    props = dict(_COMMON_PROPS); props["baseline"] = _BASELINE
    return {"mappings": {"properties": props}}


def assets_ndjson():
    lines = []
    for a in ASSETS:
        lines.append(json.dumps({"index": {"_index": "asset_inventory", "_id": a["ip"]}}))
        lines.append(json.dumps(a))
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "assets":             sys.stdout.write(assets_ndjson())
    elif cmd == "enrich-pipeline":   print(json.dumps(enrich_pipeline()))
    elif cmd == "baseline-pipeline": print(json.dumps(baseline_pipeline()))
    elif cmd == "enriched-mapping":  print(json.dumps(enriched_mapping()))
    elif cmd == "baseline-mapping":  print(json.dumps(baseline_mapping()))
    else:
        sys.stderr.write(__doc__); sys.exit(1)
