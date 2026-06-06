#!/usr/bin/env python3
"""
Generate the RAT_SCORED composite-risk-score dashboard.
Five arc gauges, all on a 0–200 scale with goal at 160.

  Row 1 (full-width): Composite Risk Score — avg(composite)
  Row 2, gauge ①:  Base Alert Severity     — avg(base)                         cumulative step 1
  Row 2, gauge ②: +Asset Criticality       — avg(base + asset)                 cumulative step 2
  Row 2, gauge ③: +PII Exposure Tier       — avg(base + asset + pii)           cumulative step 3
  Row 2, gauge ④: +Attack Complexity       — avg(base + asset + pii + cmplx)   cumulative step 4 = composite

Color banding (all gauges, number-based on the 0–200 scale):
  Green  :   0 –  80  (low risk)
  Yellow :  80 – 140  (elevated risk)
  Red    : 140 – 200  (critical risk)
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
    """Green 0-80 / Yellow 80-140 / Red 140-200 on the 0–200 composite scale."""
    return {
        "name": "custom",
        "type": "palette",
        "params": {
            "name": "custom",
            "rangeType": "number",
            "colorStops": [
                {"color": "#54B399", "stop": 0},
                {"color": "#D6BF57", "stop": 80},
                {"color": "#E7664C", "stop": 140}
            ],
            "stops": [
                {"color": "#54B399", "stop": 80},
                {"color": "#D6BF57", "stop": 140},
                {"color": "#E7664C", "stop": 200}
            ],
            "continuity": "all",
            "reverse": False
        }
    }


def lens_obj(pid, title, layers_dict, vis_state):
    return {
        "type": "lens", "id": pid,
        "coreMigrationVersion": "8.8.0",
        "typeMigrationVersion": "10.1.0",
        "attributes": {
            "title": title,
            "visualizationType": "lnsGauge",
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
    """Arc gauge visualization state — all gauges share max=200, goal=160, green/yellow/red."""
    return {
        "shape": "arc",
        "layerId": "l1",
        "layerType": "data",
        "metricAccessor": "metric",
        "minAccessor": "vmin",
        "maxAccessor": "vmax",
        "goalAccessor": "vgoal",
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
        "vmax":   static_val(200, "Max"),
        "vgoal":  static_val(160, "Critical Threshold"),
    }
    return lens_obj(
        pid, title,
        {"l1": layer(cols, ["metric", "vmin", "vmax", "vgoal"])},
        gauge_vis()
    )


objects = []

# ── Gauge 1: Composite Risk Score (top, full-width) ───────────────────────────
objects.append(gauge(
    "rsc-composite",
    "Composite Risk Score  [0–200]",
    avg_agg("score.composite", "Avg Composite Score")
))

# ── Gauge 2: Base Alert Severity — cumulative step 1 ─────────────────────────
objects.append(gauge(
    "rsc-base-severity",
    "① Base Alert Severity",
    avg_agg("score.base_alert_severity", "Avg Base Alert Severity")
))

# ── Gauge 3: + Asset Criticality — cumulative step 2 ─────────────────────────
objects.append(gauge(
    "rsc-asset-criticality",
    "② + Asset Criticality",
    formula_agg(
        "average(score.base_alert_severity) + average(score.asset_criticality)",
        "Base + Asset Criticality"
    )
))

# ── Gauge 4: + PII Exposure Tier — cumulative step 3 ─────────────────────────
objects.append(gauge(
    "rsc-pii-exposure",
    "③ + PII Exposure Tier",
    formula_agg(
        "average(score.base_alert_severity) + average(score.asset_criticality)"
        " + average(score.pii_exposure_tier)",
        "Base + Asset + PII"
    )
))

# ── Gauge 5: + Attack Complexity — cumulative step 4 (= full composite) ──────
objects.append(gauge(
    "rsc-attack-complexity",
    "④ + Attack Complexity  [= Composite]",
    formula_agg(
        "average(score.base_alert_severity) + average(score.asset_criticality)"
        " + average(score.pii_exposure_tier) + average(score.attack_complexity)",
        "Full Composite (formula)"
    )
))

# ── Dashboard ─────────────────────────────────────────────────────────────────
# Row 1 (y=0,  h=18): Composite gauge — full width, headline KPI
# Row 2 (y=18, h=18): Four cumulative component gauges — step-by-step buildup
grid = [
    {"i": "rsc-composite",         "x":  0, "y":  0, "w": 48, "h": 18},
    {"i": "rsc-base-severity",     "x":  0, "y": 18, "w": 12, "h": 18},
    {"i": "rsc-asset-criticality", "x": 12, "y": 18, "w": 12, "h": 18},
    {"i": "rsc-pii-exposure",      "x": 24, "y": 18, "w": 12, "h": 18},
    {"i": "rsc-attack-complexity", "x": 36, "y": 18, "w": 12, "h": 18},
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
            "Five arc gauges on a unified 0–200 scale. "
            "Bottom row shows cumulative score build-up: "
            "① Base Alert Severity → ② +Asset Criticality → "
            "③ +PII Exposure Tier → ④ +Attack Complexity (= composite). "
            "Color bands: Green 0–80 · Yellow 80–140 · Red 140–200. "
            "Goal line at 160 (critical threshold)."
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
