#!/usr/bin/env python3
import json

DV = "forensics-dataview"

def dv_ref(layer):
    return {"type": "index-pattern", "id": DV, "name": f"indexpattern-datasource-layer-{layer}"}

def layer(columns, col_order):
    return {"columns": columns, "columnOrder": col_order, "incompleteColumns": {}, "sampling": 1}

def count():
    return {"label": "Count", "dataType": "number", "operationType": "count",
            "isBucketed": False, "scale": "ratio", "sourceField": "___records___", "params": {}}

def unique_count(field, label):
    return {"label": label, "dataType": "number", "operationType": "unique_count",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}

def max_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "max",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}

def avg_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "average",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}

def static_val(val, label):
    return {"label": label, "dataType": "number", "operationType": "static_value",
            "isStaticValue": True, "isBucketed": False, "scale": "ratio",
            "params": {"value": str(val)}, "references": []}

def terms(field, label, order_col, size=10, data_type="string"):
    return {"label": label, "dataType": data_type, "operationType": "terms",
            "isBucketed": True, "scale": "ordinal", "sourceField": field,
            "params": {"size": size,
                       "orderBy": {"type": "column", "columnId": order_col},
                       "orderDirection": "desc", "otherBucket": False, "missingBucket": False}}

def date_hist():
    return {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
            "isBucketed": True, "scale": "interval", "sourceField": "@timestamp",
            "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False}}

def lens_obj(pid, title, vis_type, layers_dict, vis_state):
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

objects = []

# ── Row 1: KPI metrics ──────────────────────────────────────────────────────
objects.append(lens_obj(
    "panel-total-alerts", "Total Alerts", "lnsMetric",
    {"l1": layer({"c1": count()}, ["c1"])},
    {"layerId": "l1", "layerType": "data", "metricAccessor": "c1", "color": "#006BB4"}
))

objects.append(lens_obj(
    "panel-unique-src", "Unique Source IPs", "lnsMetric",
    {"l1": layer({"c1": unique_count("source.ip.keyword", "Unique Source IPs")}, ["c1"])},
    {"layerId": "l1", "layerType": "data", "metricAccessor": "c1", "color": "#017D73"}
))

objects.append(lens_obj(
    "panel-max-risk", "Max Risk Score", "lnsMetric",
    {"l1": layer({"c1": max_agg("risk_score", "Max Risk Score")}, ["c1"])},
    {"layerId": "l1", "layerType": "data", "metricAccessor": "c1", "color": "#BD271E"}
))

objects.append(lens_obj(
    "panel-avg-risk", "Avg Risk Score", "lnsMetric",
    {"l1": layer({"c1": avg_agg("risk_score", "Avg Risk Score")}, ["c1"])},
    {"layerId": "l1", "layerType": "data", "metricAccessor": "c1", "color": "#F5A700"}
))

# ── Row 2: Timeline ─────────────────────────────────────────────────────────
objects.append(lens_obj(
    "panel-timeline", "Alert Volume Over Time", "lnsXY",
    {"l1": layer({"x": date_hist(), "y": count()}, ["x", "y"])},
    {
        "legend": {"isVisible": True, "position": "right"},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

# ── Row 3: Risk score panels ────────────────────────────────────────────────
objects.append(lens_obj(
    "panel-risk-gauge", "Risk Score Gauge (Avg)", "lnsGauge",
    {"l1": layer({
        "metric": avg_agg("risk_score", "Avg Risk Score"),
        "vmin":   static_val(0, "Min"),
        "vmax":   static_val(100, "Max"),
        "vgoal":  static_val(70, "High Risk Threshold"),
    }, ["metric", "vmin", "vmax", "vgoal"])},
    {
        "shape": "arc",
        "layerId": "l1", "layerType": "data",
        "metricAccessor": "metric",
        "minAccessor": "vmin",
        "maxAccessor": "vmax",
        "goalAccessor": "vgoal",
        "ticksPosition": "auto",
        "labelMajorMode": "auto",
        "colorMode": "palette"
    }
))

objects.append(lens_obj(
    "panel-risk-by-threat", "Risk Score by Threat Signature", "lnsDatatable",
    {"l1": layer({
        "g":        terms("threat.name.keyword", "Threat Signature", "cnt", 10),
        "cnt":      count(),
        "avg_risk": avg_agg("risk_score", "Avg Risk Score"),
        "max_risk": max_agg("risk_score", "Max Risk Score"),
    }, ["g", "cnt", "avg_risk", "max_risk"])},
    {
        "layerId": "l1", "layerType": "data",
        "columns": [
            {"columnId": "g",        "isTransposed": False},
            {"columnId": "cnt",      "isTransposed": False},
            {"columnId": "avg_risk", "isTransposed": False},
            {"columnId": "max_risk", "isTransposed": False},
        ],
        "sorting": {"columnId": "max_risk", "direction": "desc"}
    }
))

# ── Row 4: Sources & targets ────────────────────────────────────────────────
objects.append(lens_obj(
    "panel-top-src", "Top Source IPs", "lnsXY",
    {"l1": layer({"x": terms("source.ip.keyword", "Source IP", "y", 10), "y": count()}, ["x", "y"])},
    {
        "legend": {"isVisible": False, "position": "right"},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_horizontal",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

objects.append(lens_obj(
    "panel-top-dest-ports", "Top Targeted Ports", "lnsXY",
    {"l1": layer({
        "x": terms("destination.port", "Destination Port", "y", 10, data_type="number"),
        "y": count()
    }, ["x", "y"])},
    {
        "legend": {"isVisible": False, "position": "right"},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_horizontal",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

objects.append(lens_obj(
    "panel-protocol", "Protocol Breakdown", "lnsPie",
    {"l1": layer({
        "g": terms("network.transport.keyword", "Protocol", "m", 5),
        "m": count()
    }, ["g", "m"])},
    {
        "shape": "donut",
        "layers": [{"layerId": "l1", "layerType": "data",
                    "primaryGroups": ["g"], "metrics": ["m"],
                    "numberDisplay": "percent", "categoryDisplay": "default",
                    "legendDisplay": "default", "nestedLegend": False}]
    }
))

# ── Row 5: Threat classification ────────────────────────────────────────────
objects.append(lens_obj(
    "panel-top-threats", "Top Threat Signatures", "lnsDatatable",
    {"l1": layer({
        "g":   terms("threat.name.keyword", "Threat", "cnt", 10),
        "cnt": count()
    }, ["g", "cnt"])},
    {
        "layerId": "l1", "layerType": "data",
        "columns": [
            {"columnId": "g",   "isTransposed": False},
            {"columnId": "cnt", "isTransposed": False},
        ],
        "sorting": {"columnId": "cnt", "direction": "desc"}
    }
))

objects.append(lens_obj(
    "panel-former-cat", "Threat Category", "lnsPie",
    {"l1": layer({
        "g": terms("metadata.former_category.keyword", "Category", "m", 10),
        "m": count()
    }, ["g", "m"])},
    {
        "shape": "donut",
        "layers": [{"layerId": "l1", "layerType": "data",
                    "primaryGroups": ["g"], "metrics": ["m"],
                    "numberDisplay": "percent", "categoryDisplay": "default",
                    "legendDisplay": "default", "nestedLegend": False}]
    }
))

objects.append(lens_obj(
    "panel-risk-level", "Risk Level Distribution", "lnsPie",
    {"l1": layer({
        "g": terms("event.norm_risk_level.keyword", "Risk Level", "m", 5),
        "m": count()
    }, ["g", "m"])},
    {
        "shape": "donut",
        "layers": [{"layerId": "l1", "layerType": "data",
                    "primaryGroups": ["g"], "metrics": ["m"],
                    "numberDisplay": "percent", "categoryDisplay": "default",
                    "legendDisplay": "default", "nestedLegend": False}]
    }
))

# ── Row 6: Sensor view ──────────────────────────────────────────────────────
objects.append(lens_obj(
    "panel-by-sensor", "Alerts by Sensor", "lnsXY",
    {"l1": layer({
        "x": terms("observer.hostname.keyword", "Sensor", "y", 10),
        "y": count()
    }, ["x", "y"])},
    {
        "legend": {"isVisible": False, "position": "right"},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_horizontal",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

objects.append(lens_obj(
    "panel-by-vlan", "Alerts by VLAN", "lnsXY",
    {"l1": layer({
        "x": terms("observer.ingress.vlan.id", "VLAN", "y", 10, data_type="number"),
        "y": count()
    }, ["x", "y"])},
    {
        "legend": {"isVisible": False, "position": "right"},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_horizontal",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

# ── Dashboard ───────────────────────────────────────────────────────────────
grid = [
    # Row 1: KPIs
    {"i": "panel-total-alerts",   "x": 0,  "y": 0,  "w": 12, "h": 6},
    {"i": "panel-unique-src",     "x": 12, "y": 0,  "w": 12, "h": 6},
    {"i": "panel-max-risk",       "x": 24, "y": 0,  "w": 12, "h": 6},
    {"i": "panel-avg-risk",       "x": 36, "y": 0,  "w": 12, "h": 6},
    # Row 2: Timeline
    {"i": "panel-timeline",       "x": 0,  "y": 6,  "w": 48, "h": 10},
    # Row 3: Risk score
    {"i": "panel-risk-gauge",     "x": 0,  "y": 16, "w": 14, "h": 12},
    {"i": "panel-risk-by-threat", "x": 14, "y": 16, "w": 34, "h": 12},
    # Row 4: Sources & targets
    {"i": "panel-top-src",        "x": 0,  "y": 28, "w": 16, "h": 12},
    {"i": "panel-top-dest-ports", "x": 16, "y": 28, "w": 16, "h": 12},
    {"i": "panel-protocol",       "x": 32, "y": 28, "w": 16, "h": 12},
    # Row 5: Threat classification
    {"i": "panel-top-threats",    "x": 0,  "y": 40, "w": 24, "h": 12},
    {"i": "panel-former-cat",     "x": 24, "y": 40, "w": 12, "h": 12},
    {"i": "panel-risk-level",     "x": 36, "y": 40, "w": 12, "h": 12},
    # Row 6: Sensor view
    {"i": "panel-by-sensor",      "x": 0,  "y": 52, "w": 24, "h": 10},
    {"i": "panel-by-vlan",        "x": 24, "y": 52, "w": 24, "h": 10},
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
    "id": "forensics-dashboard",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "10.1.0",
    "attributes": {
        "title": "Forensics - Suricata IDS Alerts",
        "description": "Suricata IDS alert analysis with composite risk scoring (0-100)",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": False,
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})
        }
    },
    "references": dashboard_refs
})

out = "/tmp/forensics_dashboard.ndjson"
with open(out, "w") as f:
    for obj in objects:
        f.write(json.dumps(obj) + "\n")

print(f"Written {len(objects)} objects to {out}")
for o in objects:
    print(f"  {o['type']:12s}  {o['id']}")
