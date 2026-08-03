#!/usr/bin/env python3
"""
Kibana 9.3 Lens saved-object DSL, generalized from indexes/rat_scored/gen_dashboard.py.

Differences from the original:
  * data view id is a parameter (each lens can point at a different index) so a
    single dashboard can contrast the ENRICHED and BASELINE indices.
  * 4-band palette matching priority tiers: green <40 (low) · yellow 40-60
    (medium) · orange 60-80 (high) · red 80-100 (critical; PII-gated promotion ≥80).

`build_scenario_dashboard()` assembles the standard per-scenario dashboard; the
per-scenario gen_dashboard.py files are thin wrappers around it.
"""
import json

CORE_MIG = "8.8.0"
TYPE_MIG = "10.1.0"


def dv_ref(dv, layer_id):
    return {"type": "index-pattern", "id": dv,
            "name": f"indexpattern-datasource-layer-{layer_id}"}


def layer(columns, col_order):
    return {"columns": columns, "columnOrder": col_order, "incompleteColumns": {}, "sampling": 1}


def avg_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "average",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}


def max_agg(field, label):
    return {"label": label, "dataType": "number", "operationType": "max",
            "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}


def count_agg(label="Count", kql=None):
    col = {"label": label, "dataType": "number", "operationType": "count",
           "isBucketed": False, "scale": "ratio", "sourceField": "___records___", "params": {}}
    if kql is not None:
        col["filter"] = {"language": "kuery", "query": kql}
    return col


def terms_agg(field, label, order_col=None, size=10):
    order = ({"type": "column", "columnId": order_col} if order_col else {"type": "alphabetical"})
    return {"label": label, "dataType": "string", "operationType": "terms",
            "isBucketed": True, "scale": "ordinal", "sourceField": field,
            "params": {"size": size, "orderBy": order, "orderDirection": "desc",
                       "otherBucket": False, "missingBucket": True}}


def formula_agg(formula_str, label):
    return {"label": label, "dataType": "number", "operationType": "formula",
            "isBucketed": False, "scale": "ratio",
            "params": {"formula": formula_str, "isFormulaBroken": False}, "references": []}


def static_val(val, label):
    return {"label": label, "dataType": "number", "operationType": "static_value",
            "isStaticValue": True, "isBucketed": False, "scale": "ratio",
            "params": {"value": str(val)}, "references": []}


def color_palette():
    """4 bands: green <40 · yellow 40-60 · orange 60-80 · red 80-100."""
    return {"name": "custom", "type": "palette", "params": {
        "name": "custom", "rangeType": "number",
        "colorStops": [
            {"color": "#54B399", "stop": 0},
            {"color": "#D6BF57", "stop": 40},
            {"color": "#DA8B45", "stop": 60},
            {"color": "#E7664C", "stop": 80},
        ],
        "stops": [
            {"color": "#54B399", "stop": 40},
            {"color": "#D6BF57", "stop": 60},
            {"color": "#DA8B45", "stop": 80},
            {"color": "#E7664C", "stop": 100},
        ],
        "continuity": "all", "reverse": False}}


def lens_obj(dv, pid, title, layers_dict, vis_state, vis_type="lnsGauge", query=""):
    return {
        "type": "lens", "id": pid,
        "coreMigrationVersion": CORE_MIG, "typeMigrationVersion": TYPE_MIG,
        "attributes": {
            "title": title, "visualizationType": vis_type,
            "state": {
                "datasourceStates": {"formBased": {"currentIndexPatternId": dv, "layers": layers_dict}},
                "filters": [], "query": {"language": "kuery", "query": query},
                "visualization": vis_state,
            },
        },
        "references": [dv_ref(dv, lid) for lid in layers_dict.keys()],
    }


def gauge_vis():
    return {"shape": "arc", "layerId": "l1", "layerType": "data",
            "metricAccessor": "metric", "minAccessor": "vmin", "maxAccessor": "vmax",
            "ticksPosition": "auto", "labelMajorMode": "auto",
            "colorMode": "palette", "palette": color_palette()}


def gauge(dv, pid, title, metric_col):
    cols = {"metric": metric_col, "vmin": static_val(0, "Min"), "vmax": static_val(100, "Max")}
    return lens_obj(dv, pid, title, {"l1": layer(cols, ["metric", "vmin", "vmax"])}, gauge_vis())


def table_vis(col_ids):
    return {"layerId": "l1", "layerType": "data",
            "columns": [{"columnId": cid, "isTransposed": False} for cid in col_ids]}


def legend_table(dv, pid, title, cols_dict, col_order):
    return lens_obj(dv, pid, title, {"l1": layer(cols_dict, col_order)},
                    table_vis(col_order), vis_type="lnsDatatable")


def xy_stacked_vis(x_id, y_ids, y_configs=None):
    return {
        "legend": {"isVisible": True, "position": "right"},
        "valueLabels": "show", "preferredSeriesType": "bar_stacked",
        "fittingFunction": "None",
        "gridlinesVisibilitySettings": {"x": False, "yLeft": True, "yRight": False},
        "tickLabelsVisibilitySettings": {"x": True, "yLeft": True, "yRight": False},
        "axisTitlesVisibilitySettings": {"x": False, "yLeft": True, "yRight": False},
        "layers": [{"layerId": "l1", "layerType": "data", "seriesType": "bar_stacked",
                    "xAccessor": x_id, "accessors": y_ids, "yConfig": y_configs or []}],
    }


def xy_stacked(dv, pid, title, cols_dict, col_order, x_id, y_ids, y_configs=None, query=""):
    """Stacked vertical bar: x = a terms bucket, y = one stacked series per y-id.
    y_configs optionally fixes per-series colours (list of {forAccessor,color});
    query optionally scopes the panel with a KQL filter."""
    return lens_obj(dv, pid, title, {"l1": layer(cols_dict, col_order)},
                    xy_stacked_vis(x_id, y_ids, y_configs), vis_type="lnsXY", query=query)


def dashboard_obj(did, title, description, grid, window, query=""):
    panels_json, refs = [], []
    for idx, g in enumerate(grid):
        ref_name = f"panel_{idx}"
        panels_json.append({"type": "lens", "gridData": g, "panelIndex": g["i"],
                            "embeddableConfig": {"enhancements": {}}, "panelRefName": ref_name})
        refs.append({"type": "lens", "id": g["i"], "name": ref_name})
    return {
        "type": "dashboard", "id": did,
        "coreMigrationVersion": CORE_MIG, "typeMigrationVersion": TYPE_MIG,
        "attributes": {
            "title": title, "description": description,
            "panelsJSON": json.dumps(panels_json),
            "optionsJSON": json.dumps({"useMargins": True, "syncColors": True, "hidePanelTitles": False}),
            "version": 1, "timeRestore": True,
            "timeFrom": window[0], "timeTo": window[1],
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"query": {"language": "kuery", "query": query}, "filter": []})},
        },
        "references": refs,
    }


def write_objects(objects, path):
    with open(path, "w") as f:
        for obj in objects:
            f.write(json.dumps(obj) + "\n")
    print(f"  wrote {len(objects)} saved objects -> {path}")


# ── Standard per-scenario dashboard ───────────────────────────────────────────
def build_scenario_dashboard(key, title, dv_enriched, dv_baseline, window):
    """Composite gauge + 4 additive component gauges + 4 legend tables (enriched),
    plus a baseline-vs-enriched contrast row. Returns (objects, dashboard_id)."""
    E, B = dv_enriched, dv_baseline
    P = "pii.context"
    objects = []

    # Row 1 — enriched-risk headline gauge; composite = base + the three contributions,
    # PII-gated critical sits >=80 (§3.6)
    objects.append(gauge(E, f"{key}-composite", "Enriched Risk Score  [0–100, critical ≥80]",
                         avg_agg(f"{P}.composite_risk_score", "Avg Enriched Risk")))
    # Row 1b — "why critical" decomposition: composite stacked into base + the three bounded
    # contributions, split by priority tier. Critical bars are visibly dominated by the PII +
    # asset (impact) contributions — the defensible evidence for the high→critical promotion.
    objects.append(xy_stacked(
        E, f"{key}-breakdown", "Escalation Contribution by Priority  (base + PII + asset + complexity = enriched risk)",
        {"x":  terms_agg(f"{P}.priority", "Priority", order_col="cord", size=4),
         "yb": avg_agg(f"{P}.contrib_base", "① Base severity (normalized, 0–30)"),
         "yp": avg_agg(f"{P}.contrib_pii", "② PII exposure (impact, 0–25)"),
         "ya": avg_agg(f"{P}.contrib_asset", "③ Asset criticality (impact, 0–25)"),
         "yc": avg_agg(f"{P}.contrib_complexity", "④ Attack complexity (likelihood, 5–20)"),
         "cord": avg_agg(f"{P}.composite_risk_score", "order")},
        ["x", "yb", "yp", "ya", "yc", "cord"], "x", ["yb", "yp", "ya", "yc"]))
    # Row 2 — base severity + the three bounded contributions actually added to it
    objects.append(gauge(E, f"{key}-base", "① Base Alert Severity  [0–100]",
                         avg_agg(f"{P}.base_alert_severity", "Avg Base")))
    objects.append(gauge(E, f"{key}-asset", "③ Asset Contribution  [0–20, impact]",
                         avg_agg(f"{P}.contrib_asset", "Avg Asset Contribution")))
    objects.append(gauge(E, f"{key}-pii", "② PII Contribution  [0–25, impact]",
                         avg_agg(f"{P}.contrib_pii", "Avg PII Contribution")))
    objects.append(gauge(E, f"{key}-cmplx", "④ Complexity Contribution  [0–15, likelihood]",
                         avg_agg(f"{P}.contrib_complexity", "Avg Complexity Contribution")))
    # Row 3 — legend tables (enriched)
    objects.append(legend_table(E, f"{key}-lg-risk", "① Risk Level Breakdown",
                                {"c1": terms_agg("event.norm_risk_level", "Risk Level", order_col="c2"),
                                 "c2": count_agg("Events")}, ["c1", "c2"]))
    objects.append(legend_table(E, f"{key}-lg-asset", "② Asset Inventory Match (higher endpoint)",
                                {"c1": terms_agg("destination.ip", "Destination IP", order_col="c3"),
                                 "c2": terms_agg(f"{P}.asset_type", "Asset Type"),
                                 "c3": max_agg(f"{P}.asset_criticality", "Criticality")}, ["c1", "c2", "c3"]))
    objects.append(legend_table(E, f"{key}-lg-pii", "③ PII Exposure Detail",
                                {"c1": terms_agg(f"{P}.pii_label", "PII Type / Inference", order_col="c3"),
                                 "c2": max_agg(f"{P}.pii_exposure_tier", "Tier"),
                                 "c3": count_agg("Events")}, ["c1", "c2", "c3"]))
    objects.append(legend_table(E, f"{key}-lg-phase", "④ Attack Phase & Technique",
                                {"c1": terms_agg("custom.str1", "Attack Phase", order_col="c3", size=12),
                                 "c2": terms_agg("threat.name.keyword", "Technique (Sig)", size=25),
                                 "c3": count_agg("Events")}, ["c1", "c2", "c3"]))
    # Row 4 — baseline vs enriched contrast
    objects.append(gauge(B, f"{key}-base-risk", "Baseline Avg Risk (no PII context)",
                         avg_agg("baseline.risk_score", "Avg Baseline Risk")))
    objects.append(legend_table(B, f"{key}-base-prio", "Baseline Priority Distribution",
                                {"c1": terms_agg("baseline.priority", "Priority", order_col="c2"),
                                 "c2": count_agg("Alerts")}, ["c1", "c2"]))
    objects.append(legend_table(E, f"{key}-enr-prio", "Enriched Priority Distribution",
                                {"c1": terms_agg(f"{P}.priority", "Priority", order_col="c2"),
                                 "c2": count_agg("Alerts")}, ["c1", "c2"]))
    objects.append(legend_table(E, f"{key}-truth", "Ground Truth (malicious vs benign)",
                                {"c1": terms_agg("labels.is_malicious", "Is Malicious", order_col="c2"),
                                 "c2": count_agg("Events")}, ["c1", "c2"]))
    # Row 5 — dedicated highlight: the enriched CRITICAL tier decomposed into true positives
    # (malicious) vs false positives (benign authorized bulk PII exports that carry the same
    # confirmatory signals). Scoped to the critical tier; FP series forced red.
    objects.append(xy_stacked(
        E, f"{key}-crit-tpfp", "Critical Tier — True vs False Positives",
        {"x":    terms_agg(f"{P}.priority", "Priority", order_col="cord", size=4),
         "ytp":  count_agg("True positives (malicious)", kql="labels.is_malicious: true"),
         "yfp":  count_agg("False positives (benign bulk export)", kql="labels.is_malicious: false"),
         "cord": count_agg("order")},
        ["x", "ytp", "yfp", "cord"], "x", ["ytp", "yfp"],
        y_configs=[{"forAccessor": "ytp", "color": "#54B399"},
                   {"forAccessor": "yfp", "color": "#E7664C"}],
        query=f"{P}.priority: critical"))

    grid = [
        {"i": f"{key}-composite",  "x":  0, "y":  0, "w": 48, "h": 16},
        {"i": f"{key}-breakdown",  "x":  0, "y": 16, "w": 48, "h": 18},
        {"i": f"{key}-base",       "x":  0, "y": 34, "w": 12, "h": 16},
        {"i": f"{key}-pii",        "x": 12, "y": 34, "w": 12, "h": 16},
        {"i": f"{key}-asset",      "x": 24, "y": 34, "w": 12, "h": 16},
        {"i": f"{key}-cmplx",      "x": 36, "y": 34, "w": 12, "h": 16},
        {"i": f"{key}-lg-risk",    "x":  0, "y": 50, "w": 12, "h": 14},
        {"i": f"{key}-lg-asset",   "x": 12, "y": 50, "w": 12, "h": 14},
        {"i": f"{key}-lg-pii",     "x": 24, "y": 50, "w": 12, "h": 14},
        {"i": f"{key}-lg-phase",   "x": 36, "y": 50, "w": 12, "h": 14},
        {"i": f"{key}-base-risk",  "x":  0, "y": 64, "w": 12, "h": 15},
        {"i": f"{key}-base-prio",  "x": 12, "y": 64, "w": 12, "h": 15},
        {"i": f"{key}-enr-prio",   "x": 24, "y": 64, "w": 12, "h": 15},
        {"i": f"{key}-truth",      "x": 36, "y": 64, "w": 12, "h": 15},
        {"i": f"{key}-crit-tpfp",  "x":  0, "y": 79, "w": 48, "h": 18},
    ]
    did = f"{key}-dashboard"
    desc = (f"{title}. v8 promotion model: base alert severity (0–100, same formula as baseline) sets the "
            "base tier but contributes a normalized 0–30 to the composite; the PII context is a bounded, "
            "weighted promotion layer of four contributions whose maxima total exactly 100 — base severity "
            "(0–30), PII exposure (0–25; T1 25/T2 18/T3 8/T4 0, impact), asset criticality (0–25, impact), "
            "attack complexity (5–20, likelihood) — so composite = base + pii + asset + complexity. Because "
            "base contributes ≤30, a non-PII asset maxes at 75: impact (25+25) outweighs likelihood (20), so "
            "a confirmed attack on Tier-1/2 PII is promoted to critical while a sophisticated attack on non-PII "
            "data is capped at high; critical is gated on composite ≥80 AND a Tier-1/2 PII target AND observed "
            "PII exposure or ≥1 correlated technique. The "
            "‘Escalation Contribution by Priority’ chart decomposes each tier's score into these four parts "
            "— the defensible evidence for the high→critical promotion. Bands: green<40 low · yellow 40–60 "
            "medium · orange 60–80 high · red 80+ critical. Bottom rows contrast baseline vs enriched "
            "priority distribution against ground truth, and decompose the enriched critical tier into "
            "true positives (green, malicious) vs false positives (red, benign authorized bulk exports).")
    objects.append(dashboard_obj(did, f"{key.upper()} — {title}", desc, grid, window))
    return objects, did
