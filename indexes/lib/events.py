#!/usr/bin/env python3
"""
ECS event construction shared by all five scenario generators.

Every event is generated ONCE and indexed into BOTH the `*_baseline` and
`*_enriched` indices (the only difference is which ingest pipeline runs). Each
event carries a ground-truth `labels.is_malicious` flag used by the report to
compute true/false-positive rates. Benign events reproduce SOC alert-fatigue
noise; a documented subset deliberately trips standard detection rules (large
transfer, encoded PowerShell, failed-auth burst, geo-anomaly, DB-query volume)
so that the baseline condition raises false positives the enriched condition
does not.
"""
import json
import os
import random
from datetime import timedelta

# Deterministic: same seed -> identical dataset across runs (v6 §3.6).
_RNG = random.Random(1337)


def eph_port():
    return _RNG.randint(49152, 65535)


def iso(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.000Z")


def event(
    *, ts, src_ip, dst_ip, dst_port, transport="tcp",
    threat_name, severity, norm_risk_level, former_category,
    flowbits=None, sensor="SENSOR", iface="eth0", vlan=20,
    rule_category="", rule_name="", event_category=None,
    attack_phase=None, correlation_id=None, mitre_technique=None,
    src_bytes=0, dst_bytes=0, src_packets=1, dst_packets=0,
    pii_type=None, is_malicious=False, scenario=None,
    # baseline standard-rule signals (derived from real event attributes, not the label)
    ps_encoded=False, auth_result=None, geo_anomaly=False, db_rows=0,
    response="Allow",
):
    e = {
        "@timestamp": iso(ts),
        "source":      {"ip": src_ip, "port": eph_port(), "bytes": src_bytes, "packets": src_packets},
        "destination": {"ip": dst_ip, "port": dst_port, "bytes": dst_bytes, "packets": dst_packets},
        "network":     {"transport": transport},
        "threat":      {"name": threat_name},
        "event": {
            "type": "alert",
            "severity": severity,
            "norm_risk_level": norm_risk_level,
            "category": event_category or [],
            "action": "allowed" if response == "Allow" else "blocked",
            "response": response,
        },
        "log":      {"level": "warning" if severity <= 2 else "notice"},
        "rule":     {"category": rule_category, "name": rule_name},
        "observer": {
            "hostname": sensor, "product": "Suricata", "vendor": "Suricata",
            "type": "IDS/IPS",
            "ingress": {"interface": {"name": iface}, "vlan": {"id": vlan}},
        },
        "metadata": {
            "former_category": former_category,
            "flowbits": flowbits or [],
        },
        "labels": {"is_malicious": bool(is_malicious), "scenario": scenario},
    }
    if attack_phase:
        e["custom"] = {"str1": attack_phase}
        e["metadata"]["attack_phase"] = attack_phase
    if correlation_id:
        e["metadata"]["correlation_id"] = correlation_id
    if mitre_technique:
        e["metadata"]["mitre_technique"] = mitre_technique
    if pii_type:
        e["metadata"]["pii_type"] = pii_type
    # optional standard-rule signals (only set when true/relevant to keep docs lean)
    if ps_encoded:
        e["metadata"]["ps_encoded"] = True
    if auth_result:
        e["metadata"]["auth_result"] = auth_result
    if geo_anomaly:
        e["metadata"]["geo_anomaly"] = True
    if db_rows:
        e["metadata"]["db_rows"] = int(db_rows)
    return e


def annotate_technique_counts(events):
    """Set metadata.technique_count = # distinct MITRE techniques observed in the
    event's correlation window. Counts ALL correlated events, benign included:
    keying the count on malice would leak the ground-truth label into the promotion
    gate (a benign authorized bulk workflow exhibits correlated admin techniques too).
    Uncorrelated events (no correlation_id) get 0."""
    windows = {}
    for e in events:
        cid = e["metadata"].get("correlation_id")
        tech = e["metadata"].get("mitre_technique")
        if cid and tech:
            windows.setdefault(cid, set()).add(tech)
    for e in events:
        cid = e["metadata"].get("correlation_id")
        if cid:
            e["metadata"]["technique_count"] = len(windows.get(cid, set()))
        else:
            e["metadata"]["technique_count"] = 0
    return events


# ── Benign noise helpers ──────────────────────────────────────────────────────
def benign(scenario, base, minute, src_ip, dst_ip, dst_port, kind, **kw):
    """Convenience wrapper for a benign business-activity event. `kind` selects a
    realistic template; some kinds intentionally trip baseline standard rules."""
    ts = base + timedelta(minutes=minute)
    defaults = dict(
        scenario=scenario, is_malicious=False, ts=ts, src_ip=src_ip,
        dst_ip=dst_ip, dst_port=dst_port,
    )
    templates = {
        # ordinary, low-signal traffic — should stay low in BOTH conditions
        "web":        dict(threat_name="Outbound HTTPS Web Browsing", severity=4, norm_risk_level="Low",
                           former_category="NETWORK", flowbits=[], rule_category="policy", rule_name="Web Traffic"),
        "auth_ok":    dict(threat_name="Successful Interactive Logon", severity=4, norm_risk_level="Low",
                           former_category="AUTH", event_category=["authentication"], auth_result="success",
                           rule_category="auth", rule_name="Logon Success"),
        "file_read":  dict(threat_name="Authorized File Share Access", severity=4, norm_risk_level="Low",
                           former_category="POLICY", rule_category="file", rule_name="File Access"),
        "dns":        dict(threat_name="Recursive DNS Query", severity=4, norm_risk_level="Low",
                           former_category="NETWORK", rule_category="dns", rule_name="DNS Query"),
        # noisy-but-benign — these TRIP a baseline standard rule (false positives)
        "backup":     dict(threat_name="Scheduled Database Backup Transfer", severity=4, norm_risk_level="Low",
                           former_category="POLICY", rule_category="exfil-threshold",
                           rule_name="Large Outbound Transfer", dst_bytes=kw.pop("bytes", 180_000_000)),
        "admin_ps":   dict(threat_name="Administrative Encoded PowerShell", severity=4, norm_risk_level="Low",
                           former_category="POLICY", rule_category="host", rule_name="Encoded PowerShell",
                           ps_encoded=True),
        "auth_fail":  dict(threat_name="Repeated Failed Logon (mistyped password)", severity=4, norm_risk_level="Low",
                           former_category="AUTH", event_category=["authentication"], auth_result="failure",
                           rule_category="auth", rule_name="Failed Auth Threshold"),
        "report":     dict(threat_name="Scheduled Reporting Query", severity=4, norm_risk_level="Low",
                           former_category="POLICY", rule_category="db", rule_name="DB Query Volume",
                           db_rows=kw.pop("rows", 90_000)),
        "vpn_travel": dict(threat_name="VPN Logon From New Geography (traveling exec)", severity=4, norm_risk_level="Low",
                           former_category="AUTH", event_category=["authentication"], auth_result="success",
                           geo_anomaly=True, rule_category="auth", rule_name="Geo Anomaly"),
        "vuln_scan":  dict(threat_name="Authorized Vulnerability Scan", severity=4, norm_risk_level="Low",
                           former_category="SCAN", flowbits=["ET.Scan"], rule_category="scan",
                           rule_name="Internal Scan"),
    }
    params = dict(defaults)
    params.update(templates[kind])
    params.update(kw)
    return event(**params)


def scatter_benign(scenario, base, net, count, day_span_hours=72, hard=2, pii_ambient=3):
    """Generate `count` benign events spread across the scenario window, mixing
    quiet traffic with rule-tripping noise.

    De-leaking (validation realism): benign business activity legitimately touches
    PII and can involve correlated multi-step admin actions, so a subset of benign
    events is given the SAME confirmatory signals the promotion gate keys on —
    explicit `pii_type` and `technique_count` — forcing the enriched model to
    discriminate on more than signals that only malicious events happened to carry:
      * `hard`        authorized DR/analytics bulk exports on the highest-value host:
                      Tier-1 pii_type + a correlated 2-technique admin window + large
                      volume. Behaviourally near-identical to the insider attack, so
                      the model that promotes them is a realistic FALSE POSITIVE.
      * `pii_ambient` quiet, single-step legitimate PII reads (helpdesk/app lookups):
                      explicit Tier-1/2 pii_type but low volume and technique_count 0.
                      A correctly-calibrated model should NOT promote these (base
                      severity stays below the critical threshold) — a correct reject."""
    from topology import ASSETS  # local import to avoid cycles
    crit = {a["ip"]: a["asset_criticality"] for a in ASSETS}
    hosts = list(net.values())
    top = sorted(hosts, key=lambda ip: crit.get(ip, 0), reverse=True)[:2] or hosts[:1]
    out = []
    quiet = ["web", "auth_ok", "file_read", "dns"]
    noisy = ["backup", "admin_ps", "auth_fail", "report", "vpn_travel", "vuln_scan"]
    for i in range(count):
        minute = _RNG.randint(0, day_span_hours * 60)
        # ~30% of benign events are the noisy, rule-tripping kind
        kind = _RNG.choice(noisy) if _RNG.random() < 0.30 else _RNG.choice(quiet)
        src = _RNG.choice(hosts)
        dst = _RNG.choice(hosts + ["203.0.113." + str(_RNG.randint(2, 250))])
        port = _RNG.choice([443, 445, 53, 3389, 1433, 22, 80])
        out.append(benign(scenario, base, minute, src, dst, port, kind))
    # hard benign: authorized DR/analytics bulk export on a Tier-1 host — carries the
    # real PII (customer SSNs/financial records) and correlated admin techniques an
    # authentic export exhibits, so it is behaviourally near-identical to an insider.
    HARD_PII = ["financial_records", "ssn"]
    HARD_TECH = ["T1078.002", "T1530"]
    wid = "corr-%s-authbulk" % scenario
    for j in range(hard):
        minute = _RNG.randint(0, day_span_hours * 60)
        dst = top[j % len(top)]
        out.append(event(
            ts=base + timedelta(minutes=minute), src_ip=top[(j + 1) % len(top)], dst_ip=dst,
            dst_port=1433, threat_name="Authorized Analytics Bulk Export (DR window)",
            severity=3, norm_risk_level="Medium", former_category="POLICY",
            rule_category="db", rule_name="Large Outbound Transfer",
            sensor="SENSOR", attack_phase=None, scenario=scenario, is_malicious=False,
            correlation_id=wid, mitre_technique=HARD_TECH[j % len(HARD_TECH)],
            pii_type=HARD_PII[j % len(HARD_PII)],
            src_bytes=210_000_000, dst_bytes=4200, db_rows=95_000))
    # ambient benign PII access: legitimate low-volume lookups that DO involve PII
    # but are single-step and quiet — should stay below the critical tier.
    AMBIENT_PII = ["ssn", "account_number", "name_dob", "financial_records"]
    for j in range(pii_ambient):
        minute = _RNG.randint(0, day_span_hours * 60)
        dst = top[j % len(top)]
        src = hosts[j % len(hosts)] if len(hosts) > 1 else top[0]
        out.append(event(
            ts=base + timedelta(minutes=minute), src_ip=src, dst_ip=dst, dst_port=1433,
            threat_name="Authorized Customer Record Lookup (app/helpdesk)",
            severity=4, norm_risk_level="Low", former_category="POLICY",
            rule_category="db", rule_name="Record Lookup",
            sensor="SENSOR", attack_phase=None, scenario=scenario, is_malicious=False,
            pii_type=AMBIENT_PII[j % len(AMBIENT_PII)],
            src_bytes=8200, dst_bytes=180_000, db_rows=1))
    return out


# ── Dual-index bulk output ────────────────────────────────────────────────────
def write_events(scenario_dir, events):
    """Write events.ndjson (empty-action bulk form) for a scenario. The same file
    is POSTed to both `<key>_baseline/_bulk` and `<key>_enriched/_bulk`."""
    events = sorted(events, key=lambda e: e["@timestamp"])
    path = os.path.join(scenario_dir, "events.ndjson")
    with open(path, "w") as f:
        for e in events:
            f.write(json.dumps({"index": {}}) + "\n")
            f.write(json.dumps(e) + "\n")
    n_mal = sum(1 for e in events if e["labels"]["is_malicious"])
    print(f"  wrote {len(events)} events ({n_mal} malicious / {len(events)-n_mal} benign) -> {path}")
    return path
