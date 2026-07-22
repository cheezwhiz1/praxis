#!/usr/bin/env python3
"""
Scenario 2 — Credential Harvesting & Online-Banking Account Takeover (v6 §3.6).
Chain: T1566.002 -> T1539/T1185 -> T1078 -> collection -> T1041.
Targets online-banking credentials and account data on the auth gateway,
banking app server, and customer DB.
"""
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from events import event, scatter_benign, annotate_technique_counts, write_events  # noqa: E402
from topology import BASE, NET, EXT, SENSORS  # noqa: E402

K = "s2_ato"
base, net, ext = BASE[K], NET[K], EXT[K]
S1, S2 = SENSORS[K]
W1, W2, W3 = "corr-s2-phish", "corr-s2-takeover", "corr-s2-exfil"


def mal(h, src, dst, port, tname, sev, risk, cat, tech, phase, cid,
        flow=None, pii=None, sb=0, db=0, transport="tcp", **kw):
    return event(ts=base + timedelta(hours=h), src_ip=src, dst_ip=dst, dst_port=port,
                 transport=transport, threat_name=tname, severity=sev, norm_risk_level=risk,
                 former_category=cat, flowbits=flow or [], sensor=S1, rule_category="ids",
                 rule_name=tname, attack_phase=phase, correlation_id=cid, mitre_technique=tech,
                 src_bytes=sb, dst_bytes=db, is_malicious=True, scenario=K, pii_type=pii, **kw)


M = [
    # Phase 1 — phishing link delivery + credential-harvest page
    mal(0.0, ext["phish"], net["user_ws"], 443, "ET PHISHING Online-Banking Credential Harvest Link",
        2, "High", "WEBATTACK", "T1566.002", "initial_access", W1, ["ET.Evil"], sb=3200, db=48000),
    mal(0.3, net["user_ws"], ext["phish"], 443, "ET PHISHING Credential POST to Harvest Page",
        2, "High", "WEBATTACK", "T1566.002", "credential_access", W1, ["ET.Evil"], pii="banking_credentials", sb=6400, db=1800),
    # Phase 2 — session token theft / browser session hijack (QUIET precursor on Tier-1 app)
    mal(0.8, net["user_ws"], net["ibank_app"], 443, "ET INFO Anomalous Session Token Reuse",
        3, "Medium", "AUTH", "T1539", "credential_access", W1, [], pii="session_token", sb=2400, db=9200),
    mal(1.1, net["user_ws"], net["ibank_app"], 443, "ET INFO Browser Session Cookie Replay",
        4, "Low", "AUTH", "T1185", "credential_access", W1, [], pii="session_token", sb=1800, db=7400),
    # Phase 3 — account takeover: anomalous auth from new geo against the auth gateway
    mal(6.0, ext["proxy"], net["auth_gw"], 443, "ET AUTH Impossible-Travel Logon (new geography)",
        2, "High", "AUTH", "T1078", "account_takeover", W2, [], pii="banking_credentials",
        geo_anomaly=True, auth_result="success", sb=4200, db=12000),
    mal(6.4, ext["proxy"], net["auth_gw"], 443, "ET AUTH MFA Fatigue Approval Anomaly",
        3, "Medium", "AUTH", "T1078", "account_takeover", W2, [], geo_anomaly=True, sb=2200, db=6400),
    # QUIET precursor: authenticated pivot to banking app + customer DB (Tier-1, low signature)
    mal(7.0, net["auth_gw"], net["ibank_app"], 443, "ET INFO Privileged Banking API Session",
        3, "Medium", "LATERAL", "T1078", "account_takeover", W2, [], pii="account_number", sb=3600, db=44000),
    mal(8.0, net["ibank_app"], net["cust_db"], 1433, "ET INFO Account Records Lookup (elevated)",
        4, "Low", "LATERAL", "T1530", "data_discovery", W2, [], pii="account_number", sb=5200, db=96000),
    # Phase 4 — bulk account/PII discovery on customer DB
    mal(20.0, net["ibank_app"], net["cust_db"], 1433, "ET EXFIL Bulk Account & SSN DB Export",
        1, "Critical", "INSIDER", "T1530", "data_discovery", W3, [], pii="ssn", sb=8200, db=14800000, db_rows=120000),
    # Phase 5 — exfiltration of harvested credentials + account data
    mal(30.0, net["ibank_app"], ext["exfil"], 443, "ET EXFIL Harvested Banking Credential Bundle",
        1, "Critical", "EXFIL", "T1041", "exfiltration", W3, ["ET.Evil"], pii="banking_credentials", sb=8600000, db=2400),
    mal(31.0, net["cust_db"], ext["exfil"], 443, "ET EXFIL Customer Account Number Batch Egress",
        1, "Critical", "EXFIL", "T1041", "exfiltration", W3, ["ET.Evil"], pii="account_number", sb=22000000, db=3200),
    mal(36.0, net["user_ws"], ext["c2"], 53, "ET EXFIL DNS Tunneled Credential Exfil",
        2, "High", "EXFIL", "T1041", "exfiltration", W3, ["ET.DNSTunnel"], transport="udp", pii="mixed_pii", sb=1400000, db=90000),
]

events = M + scatter_benign(K, base, net, 120, day_span_hours=48)
annotate_technique_counts(events)

if __name__ == "__main__":
    write_events(os.path.dirname(os.path.abspath(__file__)), events)
