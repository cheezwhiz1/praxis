#!/usr/bin/env python3
"""
Scenario 4 — SQL Injection to Cardholder-Data Exfiltration (v6 §3.6).
Chain: T1190 (exploit public web app) -> T1505 (web shell) -> T1074/T1041
(stage + exfil credit-card records). Tests whether the framework elevates
application-layer indicators that look like routine error logs in isolation
once they are associated with the PCI-CDE cardholder database (Tier-1).
"""
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from events import event, scatter_benign, annotate_technique_counts, write_events  # noqa: E402
from topology import BASE, NET, EXT, SENSORS  # noqa: E402

K = "s4_sqli"
base, net, ext = BASE[K], NET[K], EXT[K]
S1, S2 = SENSORS[K]
W1, W2, W3 = "corr-s4-exploit", "corr-s4-foothold", "corr-s4-exfil"


def mal(h, src, dst, port, tname, sev, risk, cat, tech, phase, cid,
        flow=None, pii=None, sb=0, db=0, transport="tcp", **kw):
    return event(ts=base + timedelta(hours=h), src_ip=src, dst_ip=dst, dst_port=port,
                 transport=transport, threat_name=tname, severity=sev, norm_risk_level=risk,
                 former_category=cat, flowbits=flow or [], sensor=S1, rule_category="ids",
                 rule_name=tname, attack_phase=phase, correlation_id=cid, mitre_technique=tech,
                 src_bytes=sb, dst_bytes=db, is_malicious=True, scenario=K, pii_type=pii, **kw)


M = [
    # Phase 1 — SQL injection probing + exploit of the public web app
    mal(0.0, ext["attacker"], net["web_app"], 443, "ET WEB_SERVER SQL Injection UNION SELECT Probe",
        3, "Medium", "WEBATTACK", "T1190", "initial_access", W1, ["ET.Scan"], sb=8200, db=4400),
    mal(0.3, ext["attacker"], net["web_app"], 443, "ET WEB_SERVER SQLi Error-Based Extraction",
        2, "High", "WEBATTACK", "T1190", "initial_access", W1, ["ET.Exploit"], sb=12400, db=96000),
    mal(0.6, ext["attacker"], net["web_app"], 443, "ET WEB_SERVER Boolean-Blind SQLi Automation",
        2, "High", "EXPLOIT", "T1190", "initial_access", W1, ["ET.Exploit"], sb=16800, db=42000),
    # Phase 2 — web shell deployment + QUIET foothold pivots toward the CDE DB (Tier-1)
    mal(1.5, ext["attacker"], net["web_app"], 443, "ET WEB_SERVER PHP Web Shell Upload",
        2, "High", "WEBATTACK", "T1505", "persistence", W2, ["ET.Evil"], sb=34000, db=1800),
    mal(2.0, net["web_app"], net["web_db"], 1433, "ET INFO Web App DB Read via Injected Query",
        4, "Low", "WEBATTACK", "T1505", "data_discovery", W2, [], pii="credit_card", sb=2400, db=88000),
    mal(3.0, net["web_app"], net["web_db"], 1433, "ET INFO Cardholder Table Schema Enumeration",
        3, "Medium", "RECON", "T1190", "reconnaissance", W2, [], pii="credit_card", sb=3200, db=64000),
    mal(4.0, net["web_app"], net["app_mid"], 8080, "ET INFO Web Shell Command Relay",
        4, "Low", "WEBATTACK", "T1505", "lateral_movement", W2, [], sb=4200, db=9800),
    # Phase 3 — staging + exfiltration of cardholder data (loud volume)
    mal(10.0, net["web_db"], net["web_app"], 1433, "ET EXFIL Full PAN Result-Set Staging",
        1, "Critical", "INSIDER", "T1074", "data_discovery", W3, [], pii="payment_card_full_track", sb=6200, db=18500000, db_rows=95000),
    mal(12.0, net["web_app"], ext["exfil"], 443, "ET EXFIL Credit-Card Batch Egress via Web Shell",
        1, "Critical", "EXFIL", "T1041", "exfiltration", W3, ["ET.Evil"], pii="payment_card_full_track", sb=42000000, db=3400),
    mal(18.0, net["web_app"], ext["webshell_c2"], 443, "ET EXFIL Round-2 Card Data Staging Egress",
        1, "Critical", "EXFIL", "T1041", "exfiltration", W3, ["ET.Evil", "ET.Exploit"], pii="credit_card", sb=28000000, db=2600),
]

events = M + scatter_benign(K, base, net, 120, day_span_hours=36)
annotate_technique_counts(events)

if __name__ == "__main__":
    write_events(os.path.dirname(os.path.abspath(__file__)), events)
