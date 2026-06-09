#!/usr/bin/env python3
"""
Generate the RAT_SCORED composite-risk-score dashboard.
Five arc gauges on a 0–100 additive scale (composite = sum of four components),
plus four legend tables below the component gauges showing what matched each score.

  Sub-score contributions (max values sum to 100):
    base_alert_severity : 0–45  (category + flowbits + risk level)
    asset_criticality   : 0–25  (max(source IP, destination IP) lookup in asset_inventory)
    pii_exposure_tier   : 2–20  (4-tier PII taxonomy)
    attack_complexity   : 3–10  (MITRE attack phase proxy)

  Row 1 (full-width): Composite Risk Score — avg(composite)  [0–100]
  Row 2, gauge ①:  Base Alert Severity     — avg(base)                        additive step 1
  Row 2, gauge ②: +Asset Criticality       — avg(base + asset)                additive step 2
  Row 2, gauge ③: +PII Exposure Tier       — avg(base + asset + pii)          additive step 3
  Row 2, gauge ④: +Attack Complexity       — avg(base + asset + pii + cmplx)  additive step 4 = composite

  Row 3, legend ①: event.norm_risk_level | count
  Row 3, legend ②: source.ip | score.asset_type | score.asset_criticality
  Row 3, legend ③: metadata.pii_type | count
  Row 3, legend ④: custom.str1 (phase) | threat.name | count

Color banding (all gauges, number-based on the 0–100 scale):
  Green  :   0 –  40  (low risk)
  Yellow :  40 –  70  (elevated risk)
  Red    :  70 – 100  (critical risk)
"""
import json

DV = "rat-scored-dataview"


def dv_ref(layer_id):
    return {"type": "index-pattern", "id": DV,
            "name": f"indexpattern-datasource-layer-{layer_id}"}


def layer(columns, col_order):
    return {"columns": columns, "columnOrder": col_order,
            "incompleteColumns": {}, "sampling": 1}


def avg_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "average",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}


def max_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "max",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}


def count_agg(label="Count"):
    return {"label": label, "dataType": "number", "operationType": "count",
            "isBucketed": False, "scale": "ratio",
            "sourceField": "___records___", "params": {}}


def terms_agg(field, label, order_col=None, size=10):
    """Terms bucket column. order_col: column key to order by, or None for alphabetical."""
    order = ({"type": "column", "columnId": order_col}
             if order_col else {"type": "alphabetical"})
    return {"label": label, "dataType": "string", "operationType": "terms",
            "isBucketed": True, "scale": "ordinal",
            "sourceField": field,
            "params": {"size": size, "orderBy": order, "orderDirection": "desc",
                       "otherBucket": False, "missingBucket": True}}


def formula_agg(formula_str, label):
    """Lens formula column — combines multiple aggregations at query time."""
    return {"label": label, "dataType": "number", "operationType": "formula",
            "isBucketed": False, "scale": "ratio",
            "params": {"formula": formula_str, "isFormulaBroken": False},
            "references": []}


def static_val(val, label):
    return {"label": label, "dataType": "number", "operationType": "static_value",
            "isStaticValue": True, "isBucketed": False, "scale": "ratio",
            "params": {"value": str(val)}, "references": []}


def color_palette():
    """Green 0-40 / Yellow 40-70 / Red 70-100 on the 0–100 scale."""
    return {
        "name": "custom",
        "type": "palette",
        "params": {
            "name": "custom",
            "rangeType": "number",
            "colorStops": [
                {"color": "#54B399", "stop": 0},
                {"color": "#D6BF57", "stop": 40},
                {"color": "#E7664C", "stop": 70}
            ],
            "stops": [
                {"color": "#54B399", "stop": 40},
                {"color": "#D6BF57", "stop": 70},
                {"color": "#E7664C", "stop": 100}
            ],
            "continuity": "all",
            "reverse": False
        }
    }


def lens_obj(pid, title, layers_dict, vis_state, vis_type="lnsGauge"):
    return {
        "type": "lens", "id": pid,
        "coreMigrationVersion": "8.8.0",
        "typeMigrationVersion": "10.1.0",
        "attributes": {
            "title": title,
            "visualizationType": vis_type,
            "state": {
                "datasourceStates": {"formBased": {
                    "currentIndexPatternId": DV,
                    "layers": layers_dict
                }},
                "filters": [], "query": {"language": "kuery", "query": ""},
                "visualization": vis_state
            }
        },
        "references": [dv_ref(lid) for lid in layers_dict.keys()]
    }


def gauge_vis():
    """Arc gauge visualization state — all gauges share max=100, green/yellow/red."""
    return {
        "shape": "arc",
        "layerId": "l1",
        "layerType": "data",
        "metricAccessor": "metric",
        "minAccessor": "vmin",
        "maxAccessor": "vmax",
        "ticksPosition": "auto",
        "labelMajorMode": "auto",
        "colorMode": "palette",
        "palette": color_palette()
    }


def gauge(pid, title, metric_col):
    """Build a gauge lens object. metric_col is an avg_agg() or formula_agg() dict."""
    cols = {
        "metric": metric_col,
        "vmin":   static_val(0,   "Min"),
        "vmax":   static_val(100, "Max"),
    }
    return lens_obj(
        pid, title,
        {"l1": layer(cols, ["metric", "vmin", "vmax"])},
        gauge_vis()
    )


def table_vis(col_ids):
    """Data table visualization state."""
    return {
        "layerId": "l1",
        "layerType": "data",
        "columns": [{"columnId": cid, "isTransposed": False} for cid in col_ids]
    }


def legend_table(pid, title, cols_dict, col_order):
    """Build a data table lens object for score legends."""
    return lens_obj(
        pid, title,
        {"l1": layer(cols_dict, col_order)},
        table_vis(col_order),
        vis_type="lnsDatatable"
    )


objects = []

# ── Gauge 1: Composite Risk Score (top, full-width) ───────────────────────────
objects.append(gauge(
    "rsc-composite",
    "Composite Risk Score  [0–100]",
    avg_agg("score.composite", "Avg Composite Score")
))

# ── Gauge 2: Base Alert Severity — additive step 1 ───────────────────────────
objects.append(gauge(
    "rsc-base-severity",
    "① Base Alert Severity",
    avg_agg("score.base_alert_severity", "Avg Base Alert Severity")
))

# ── Gauge 3: + Asset Criticality — additive step 2 ───────────────────────────
objects.append(gauge(
    "rsc-asset-criticality",
    "② + Asset Criticality",
    formula_agg(
        "average(score.base_alert_severity) + average(score.asset_criticality)",
        "Base + Asset Criticality"
    )
))

# ── Gauge 4: + PII Exposure Tier — additive step 3 ───────────────────────────
objects.append(gauge(
    "rsc-pii-exposure",
    "③ + PII Exposure Tier",
    formula_agg(
        "average(score.base_alert_severity) + average(score.asset_criticality)"
        " + average(score.pii_exposure_tier)",
        "Base + Asset + PII"
    )
))

# ── Gauge 5: + Attack Complexity — additive step 4 (= full composite) ────────
objects.append(gauge(
    "rsc-attack-complexity",
    "④ + Attack Complexity  [= Composite]",
    formula_agg(
        "average(score.base_alert_severity) + average(score.asset_criticality)"
        " + average(score.pii_exposure_tier) + average(score.attack_complexity)",
        "Full Composite (formula)"
    )
))

# ── Legend A: Risk level breakdown (under gauge ①) ────────────────────────────
objects.append(legend_table(
    "rsc-legend-base",
    "① Risk Level Breakdown",
    {
        "c1": terms_agg("event.norm_risk_level", "Risk Level", order_col="c2"),
        "c2": count_agg("Events"),
    },
    ["c1", "c2"]
))

# ── Legend B: Asset inventory match (under gauge ②) ──────────────────────────
objects.append(legend_table(
    "rsc-legend-asset",
    "② Asset Inventory Match  (src or dst, higher criticality)",
    {
        "c1": terms_agg("source.ip",          "Source IP",        order_col="c3"),
        "c2": terms_agg("score.asset_type",   "Asset Type"),
        "c3": max_agg("score.asset_criticality", "Criticality Score"),
    },
    ["c1", "c2", "c3"]
))

# ── Legend C: PII exposure detail (under gauge ③) ────────────────────────────
objects.append(legend_table(
    "rsc-legend-pii",
    "③ PII Exposure Detail",
    {
        "c1": terms_agg("metadata.pii_type", "PII Type", order_col="c2"),
        "c2": count_agg("Events"),
    },
    ["c1", "c2"]
))

# ── Legend D: Attack phase + technique (under gauge ④) ───────────────────────
objects.append(legend_table(
    "rsc-legend-complexity",
    "④ Attack Phase & Technique",
    {
        "c1": terms_agg("custom.str1",          "Attack Phase",    order_col="c3", size=10),
        "c2": terms_agg("threat.name.keyword",  "Technique (Suricata Sig)", size=20),
        "c3": count_agg("Events"),
    },
    ["c1", "c2", "c3"]
))

# ── Dashboard ─────────────────────────────────────────────────────────────────
# Row 1 (y=0,  h=18): Composite gauge — full width, headline KPI
# Row 2 (y=18, h=18): Four additive build-up gauges — step-by-step accumulation
# Row 3 (y=36, h=15): Four legend tables — score criteria that matched
grid = [
    {"i": "rsc-composite",          "x":  0, "y":  0, "w": 48, "h": 18},
    {"i": "rsc-base-severity",      "x":  0, "y": 18, "w": 12, "h": 18},
    {"i": "rsc-asset-criticality",  "x": 12, "y": 18, "w": 12, "h": 18},
    {"i": "rsc-pii-exposure",       "x": 24, "y": 18, "w": 12, "h": 18},
    {"i": "rsc-attack-complexity",  "x": 36, "y": 18, "w": 12, "h": 18},
    {"i": "rsc-legend-base",        "x":  0, "y": 36, "w": 12, "h": 15},
    {"i": "rsc-legend-asset",       "x": 12, "y": 36, "w": 12, "h": 15},
    {"i": "rsc-legend-pii",         "x": 24, "y": 36, "w": 12, "h": 15},
    {"i": "rsc-legend-complexity",  "x": 36, "y": 36, "w": 12, "h": 15},
]

panels_json = []
dashboard_refs = []
for idx, g in enumerate(grid):
    ref_name = f"panel_{idx}"
    panels_json.append({
        "type": "lens",
        "gridData": g,
        "panelIndex": g["i"],
        "embeddableConfig": {"enhancements": {}},
        "panelRefName": ref_name
    })
    dashboard_refs.append({"type": "lens", "id": g["i"], "name": ref_name})

objects.append({
    "type": "dashboard",
    "id": "rat-scored-dashboard",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "10.1.0",
    "attributes": {
        "title": "RAT_SCORED — Composite Risk Score Components",
        "description": (
            "Five arc gauges on a unified 0–100 additive scale (max = 30+25+25+20). "
            "Bottom row shows cumulative score build-up: "
            "① Base Alert Severity → ② +Asset Criticality → "
            "③ +PII Exposure Tier → ④ +Attack Complexity (= composite). "
            "Legend tables show the specific criteria that matched each component. "
            "Color bands: Green 0–40 · Yellow 40–70 · Red 70–100."
        ),
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({
            "useMargins": True, "syncColors": True, "hidePanelTitles": False
        }),
        "version": 1,
        "timeRestore": True,
        "timeFrom": "2026-06-15T00:00:00.000Z",
        "timeTo":   "2026-06-19T23:59:59.999Z",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({
                "query": {"language": "kuery", "query": ""}, "filter": []
            })
        }
    },
    "references": dashboard_refs
})

out = "/tmp/rat_scored_dashboard.ndjson"
with open(out, "w") as f:
    for obj in objects:
        f.write(json.dumps(obj) + "\n")

print(f"Written {len(objects)} objects to {out}")
for o in objects:
    print(f"  {o['type']:12s}  {o['id']}")
