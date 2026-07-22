#!/usr/bin/env python3
"""
Build the `praxis_results` index payload + a Kibana "Validation Results" dashboard
that visualises the baseline-vs-enriched comparison across all five scenarios.
Kibana cannot run inferential statistics, so this is the exportable/visual
counterpart to the .docx statistical report.
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from lens_dsl import (gauge, legend_table, dashboard_obj, avg_agg, max_agg,  # noqa: E402
                      terms_agg, count_agg, xy_stacked)

DV = "praxis_results"


def results_ndjson(metrics):
    """One doc per (scenario, condition) with the headline metrics."""
    lines = []
    for m in metrics:
        for cond in ("baseline", "enriched"):
            b = m[cond]
            doc = {"scenario": m["key"], "scenario_title": m["title"], "condition": cond,
                   "high_priority_volume": b["high"], "true_positives": b["tp"],
                   "false_positives": b["fp"], "tpr_at_high": round(b["tpr"], 3),
                   "fpr_at_high": round(b["fpr"], 3), "recall": round(b["recall"], 3),
                   "malicious_total": m["n_mal"], "alerts_total": m["n"]}
            lines.append(json.dumps({"index": {"_index": DV}}))
            lines.append(json.dumps(doc))
    return "\n".join(lines) + "\n"


def results_mapping():
    return {"mappings": {"properties": {
        "scenario": {"type": "keyword"}, "scenario_title": {"type": "keyword"},
        "condition": {"type": "keyword"}, "high_priority_volume": {"type": "integer"},
        "true_positives": {"type": "integer"}, "false_positives": {"type": "integer"},
        "tpr_at_high": {"type": "float"}, "fpr_at_high": {"type": "float"},
        "recall": {"type": "float"}, "malicious_total": {"type": "integer"},
        "alerts_total": {"type": "integer"}}}}


def build_dashboard(window=("2026-06-15T00:00:00.000Z", "2026-07-18T23:59:59.999Z")):
    D = DV
    objects = []
    # baseline query filter via lens formula is awkward; use terms split by condition.
    objects.append(legend_table(
        D, "praxis-res-volume", "High-Priority Alert Volume by Scenario & Condition",
        {"c1": terms_agg("scenario", "Scenario", order_col="c3", size=10),
         "c2": terms_agg("condition", "Condition"),
         "c3": max_agg("high_priority_volume", "High-Priority Alerts")},
        ["c1", "c2", "c3"]))
    objects.append(legend_table(
        D, "praxis-res-tpr", "True-Positive Rate @ High Priority",
        {"c1": terms_agg("scenario", "Scenario", order_col="c3", size=10),
         "c2": terms_agg("condition", "Condition"),
         "c3": max_agg("tpr_at_high", "TPR@high")},
        ["c1", "c2", "c3"]))
    objects.append(legend_table(
        D, "praxis-res-fpr", "False-Positive Rate @ High Priority",
        {"c1": terms_agg("scenario", "Scenario", order_col="c3", size=10),
         "c2": terms_agg("condition", "Condition"),
         "c3": max_agg("fpr_at_high", "FPR@high")},
        ["c1", "c2", "c3"]))
    # pooled headline gauges (avg over docs of each condition — filtered via KQL on panel)
    objects.append(gauge(D, "praxis-res-tpr-gauge", "Avg TPR@high (all rows)",
                         avg_agg("tpr_at_high", "TPR@high")))
    objects.append(legend_table(
        D, "praxis-res-recall", "Malicious Recall @ High Priority",
        {"c1": terms_agg("scenario", "Scenario", order_col="c3", size=10),
         "c2": terms_agg("condition", "Condition"),
         "c3": max_agg("recall", "Recall")},
        ["c1", "c2", "c3"]))
    # Dedicated highlight: the enriched CRITICAL tier decomposed into true positives
    # (confirmed PII attacks) vs false positives (authorized bulk PII exports that carry
    # the same confirmatory signals). Scoped to condition:enriched so each scenario's
    # single enriched row is the critical-tier count; FP series forced red.
    objects.append(xy_stacked(
        D, "praxis-res-critical-tpfp",
        "Enriched Critical Tier — True vs False Positives by Scenario",
        {"x":   terms_agg("scenario", "Scenario", order_col="cord", size=10),
         "ytp": max_agg("true_positives", "True positives (confirmed PII attacks)"),
         "yfp": max_agg("false_positives", "False positives (authorized bulk exports)"),
         "cord": max_agg("high_priority_volume", "order")},
        ["x", "ytp", "yfp", "cord"], "x", ["ytp", "yfp"],
        y_configs=[{"forAccessor": "ytp", "color": "#54B399"},
                   {"forAccessor": "yfp", "color": "#E7664C"}],
        query="condition:enriched"))
    grid = [
        {"i": "praxis-res-volume", "x": 0, "y": 0, "w": 24, "h": 18},
        {"i": "praxis-res-tpr", "x": 24, "y": 0, "w": 24, "h": 18},
        {"i": "praxis-res-fpr", "x": 0, "y": 18, "w": 24, "h": 18},
        {"i": "praxis-res-recall", "x": 24, "y": 18, "w": 24, "h": 18},
        {"i": "praxis-res-critical-tpfp", "x": 0, "y": 36, "w": 48, "h": 18},
        {"i": "praxis-res-tpr-gauge", "x": 0, "y": 54, "w": 48, "h": 14},
    ]
    desc = ("Baseline (no PII context) vs Enriched (PII Context Framework) across the five "
            "scenarios. Enriched concentrates high-priority alerts onto true positives, "
            "collapsing volume and raising TPR@high. The 'Enriched Critical Tier — True vs "
            "False Positives' bar decomposes the promoted critical tier per scenario: green = "
            "confirmed PII attacks, red = the authorized bulk-export false positives that carry "
            "the same confirmatory signals (the honest, de-leaked precision limit). Inferential "
            "statistics are in the .docx report.")
    objects.append(dashboard_obj("praxis-results-dashboard",
                                 "Praxis — Validation Results (Baseline vs Enriched)",
                                 desc, grid, window))
    return objects
