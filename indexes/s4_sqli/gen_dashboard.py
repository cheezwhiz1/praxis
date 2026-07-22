#!/usr/bin/env python3
"""Build this scenario's Kibana dashboard (enriched gauges/tables + baseline contrast).
Thin wrapper over lib.lens_dsl.build_scenario_dashboard; scenario key = directory name."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
from lens_dsl import build_scenario_dashboard, write_objects  # noqa: E402
from topology import WINDOW, SCENARIO_TITLE  # noqa: E402

K = os.path.basename(HERE)
objects, did = build_scenario_dashboard(
    K, SCENARIO_TITLE[K], f"{K}_enriched", f"{K}_baseline", WINDOW[K])

if __name__ == "__main__":
    write_objects(objects, os.path.join(HERE, "dashboard.ndjson"))
    print(f"  dashboard id: {did}")
