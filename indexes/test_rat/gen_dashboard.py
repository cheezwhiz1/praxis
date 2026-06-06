#!/usr/bin/env python3
import json

DV = "test-rat-dataview"

def dv_ref(layer):
    return {"type": "index-pattern", "id": DV, "name": f"indexpattern-datasource-layer-{layer}"}

def layer(columns, col_order):
    return {"columns": columns, "columnOrder": col_order, "incompleteColumns": {}, "sampling": 1}

def count():
    return {"label": "Count", "dataType": "number", "operationType": "count",
            "isBucketed": False, "scale": "ratio", "sourceField": "___records___", "params": {}}

def max_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "max",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}

def avg_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "average",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}

def sum_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "sum",
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
    "rat-total-alerts", "Total RAT Alerts", "lnsMetric",
    {"l1": layer({"c1": count()}, ["c1"])},
    {"layerId": "l1", "layerType": "data", "metricAccessor": "c1", "color": "#BD271E"}
))

objects.append(lens_obj(
    "rat-compromised-hosts", "Compromised Hosts", "lnsMetric",
    {"l1": layer({"c1": {"label": "Unique Source IPs", "dataType": "number",
                         "operationType": "unique_count", "isBucketed": False,
                         "scale": "ratio", "sourceField": "source.ip", "params": {}}}, ["c1"])},
    {"layerId": "l1", "layerType": "data", "metricAccessor": "c1", "color": "#CC5642"}
))

objects.append(lens_obj(
    "rat-max-risk", "Max Risk Score", "lnsMetric",
    {"l1": layer({"c1": max_agg("risk_score", "Max Risk Score")}, ["c1"])},
    {"layerId": "l1", "layerType": "data", "metricAccessor": "c1", "color": "#7B0000"}
))

objects.append(lens_obj(
    "rat-total-exfil", "Total Data Exfiltrated (bytes)", "lnsMetric",
    {"l1": layer({"c1": sum_agg("source.bytes", "Total Bytes Out")}, ["c1"])},
    {"layerId": "l1", "layerType": "data", "metricAccessor": "c1", "color": "#920000"}
))

# ── Row 2: Attack timeline ──────────────────────────────────────────────────
objects.append(lens_obj(
    "rat-timeline", "Attack Timeline", "lnsXY",
    {"l1": layer({
        "x": date_hist(),
        "y": count(),
        "brk": terms("custom.str1", "Attack Phase", "y", 10)
    }, ["brk", "x", "y"])},
    {
        "legend": {"isVisible": True, "position": "right"},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_stacked",
                    "xAccessor": "x", "accessors": ["y"], "splitAccessor": "brk"}]
    }
))

# ── Row 3: Risk score panels ────────────────────────────────────────────────
objects.append(lens_obj(
    "rat-risk-gauge", "Risk Score Gauge (Avg)", "lnsGauge",
    {"l1": layer({
        "metric": avg_agg("risk_score", "Avg Risk Score"),
        "vmin":   static_val(0, "Min"),
        "vmax":   static_val(100, "Max"),
        "vgoal":  static_val(80, "Critical Threshold"),
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
    "rat-risk-by-phase", "Risk Score by Attack Phase", "lnsDatatable",
    {"l1": layer({
        "g":        terms("custom.str1", "Attack Phase", "cnt", 10),
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
        "sorting": {"columnId": "avg_risk", "direction": "desc"}
    }
))

# ── Row 4: Infected hosts & C2 ─────────────────────────────────────────────
objects.append(lens_obj(
    "rat-infected-hosts", "Alerts by Infected Host", "lnsXY",
    {"l1": layer({
        "x": terms("source.ip", "Source IP", "y", 10),
        "y": count()
    }, ["x", "y"])},
    {
        "legend": {"isVisible": False},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_horizontal",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

objects.append(lens_obj(
    "rat-c2-servers", "C2 / Exfil Destination IPs", "lnsXY",
    {"l1": layer({
        "x": terms("destination.ip", "Destination IP", "y", 10),
        "y": count()
    }, ["x", "y"])},
    {
        "legend": {"isVisible": False},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_horizontal",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

objects.append(lens_obj(
    "rat-attack-phase-donut", "Events by Attack Phase", "lnsPie",
    {"l1": layer({
        "g": terms("custom.str1", "Phase", "m", 10),
        "m": count()
    }, ["g", "m"])},
    {
        "shape": "donut",
        "layers": [{"layerId": "l1", "layerType": "data",
                    "primaryGroups": ["g"], "metrics": ["m"],
                    "numberDisplay": "value", "categoryDisplay": "default",
                    "legendDisplay": "default", "nestedLegend": False}]
    }
))

# ── Row 5: PII & exfiltration ──────────────────────────────────────────────
objects.append(lens_obj(
    "rat-pii-types", "PII Types Targeted", "lnsPie",
    {"l1": layer({
        "g": terms("metadata.pii_type", "PII Type", "m", 10),
        "m": count()
    }, ["g", "m"])},
    {
        "shape": "donut",
        "layers": [{"layerId": "l1", "layerType": "data",
                    "primaryGroups": ["g"], "metrics": ["m"],
                    "numberDisplay": "value", "categoryDisplay": "default",
                    "legendDisplay": "default", "nestedLegend": False}]
    }
))

objects.append(lens_obj(
    "rat-exfil-bytes", "Data Exfiltrated by Host (bytes)", "lnsXY",
    {"l1": layer({
        "x": terms("source.ip", "Source IP", "y", 10),
        "y": sum_agg("source.bytes", "Bytes Out")
    }, ["x", "y"])},
    {
        "legend": {"isVisible": False},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_horizontal",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

objects.append(lens_obj(
    "rat-threat-table", "Threat Signatures Detected", "lnsDatatable",
    {"l1": layer({
        "g":   terms("threat.name.keyword", "Threat Signature", "cnt", 15),
        "cnt": count(),
        "max_risk": max_agg("risk_score", "Max Risk"),
    }, ["g", "cnt", "max_risk"])},
    {
        "layerId": "l1", "layerType": "data",
        "columns": [
            {"columnId": "g",        "isTransposed": False},
            {"columnId": "cnt",      "isTransposed": False},
            {"columnId": "max_risk", "isTransposed": False},
        ],
        "sorting": {"columnId": "max_risk", "direction": "desc"}
    }
))

# ── Row 6: Category & dest ports ──────────────────────────────────────────
objects.append(lens_obj(
    "rat-category", "Alert Category", "lnsPie",
    {"l1": layer({
        "g": terms("metadata.former_category", "Category", "m", 10),
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
    "rat-dest-ports", "Targeted Ports", "lnsXY",
    {"l1": layer({
        "x": terms("destination.port", "Port", "y", 10, data_type="number"),
        "y": count()
    }, ["x", "y"])},
    {
        "legend": {"isVisible": False},
        "valueLabels": "hide", "fittingFunction": "None",
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_horizontal",
                    "xAccessor": "x", "accessors": ["y"]}]
    }
))

# ── Dashboard ───────────────────────────────────────────────────────────────
grid = [
    # Row 1: KPIs
    {"i": "rat-total-alerts",    "x": 0,  "y": 0,  "w": 12, "h": 6},
    {"i": "rat-compromised-hosts","x": 12, "y": 0,  "w": 12, "h": 6},
    {"i": "rat-max-risk",        "x": 24, "y": 0,  "w": 12, "h": 6},
    {"i": "rat-total-exfil",     "x": 36, "y": 0,  "w": 12, "h": 6},
    # Row 2: Timeline
    {"i": "rat-timeline",        "x": 0,  "y": 6,  "w": 48, "h": 12},
    # Row 3: Risk score
    {"i": "rat-risk-gauge",      "x": 0,  "y": 18, "w": 14, "h": 12},
    {"i": "rat-risk-by-phase",   "x": 14, "y": 18, "w": 34, "h": 12},
    # Row 4: Hosts & C2
    {"i": "rat-infected-hosts",  "x": 0,  "y": 30, "w": 16, "h": 12},
    {"i": "rat-c2-servers",      "x": 16, "y": 30, "w": 16, "h": 12},
    {"i": "rat-attack-phase-donut","x": 32,"y": 30, "w": 16, "h": 12},
    # Row 5: PII & exfil
    {"i": "rat-pii-types",       "x": 0,  "y": 42, "w": 14, "h": 12},
    {"i": "rat-exfil-bytes",     "x": 14, "y": 42, "w": 16, "h": 12},
    {"i": "rat-threat-table",    "x": 30, "y": 42, "w": 18, "h": 12},
    # Row 6: Category & ports
    {"i": "rat-category",        "x": 0,  "y": 54, "w": 16, "h": 10},
    {"i": "rat-dest-ports",      "x": 16, "y": 54, "w": 32, "h": 10},
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
    "id": "rat-dashboard",
    "coreMigrationVersion": "8.8.0",
    "typeMigrationVersion": "10.1.0",
    "attributes": {
        "title": "TEST_RAT - Financial RAT / PII Threat Analysis",
        "description": "Simulated Remote Access Trojan targeting financial PII — 6-phase attack timeline",
        "panelsJSON": json.dumps(panels_json),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True,
        "timeFrom": "2026-05-20T00:00:00.000Z",
        "timeTo":   "2026-05-27T23:59:59.999Z",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"language": "kuery", "query": ""}, "filter": []})
        }
    },
    "references": dashboard_refs
})

out = "/tmp/rat_dashboard.ndjson"
with open(out, "w") as f:
    for obj in objects:
        f.write(json.dumps(obj) + "\n")

print(f"Written {len(objects)} objects to {out}")
for o in objects:
    print(f"  {o['type']:12s}  {o['id']}")
