#!/usr/bin/env python3
"""
Scenario 5 — Ransomware-as-a-Service Double-Extortion (v6 §3.6, most complex).
Chain: T1133 (exposed remote service) -> T1570 (lateral tool transfer) ->
T1560/T1537 (bulk staging + cloud exfil of HR + customer PII) -> TA0010
(pre-encryption exfil) -> T1486 (encryption). Extended dwell time tests whether
the framework surfaces early-stage behavioral indicators as elevated priority
before the bulk-exfiltration and encryption phases generate obvious signals (H3).
"""
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from events import event, scatter_benign, annotate_technique_counts, write_events  # noqa: E402
from topology import BASE, NET, EXT, SENSORS  # noqa: E402

K = "s5_ransomware"
base, net, ext = BASE[K], NET[K], EXT[K]
S1, S2 = SENSORS[K]
W1, W2, W3, W4 = "corr-s5-access", "corr-s5-spread", "corr-s5-exfil", "corr-s5-impact"


def mal(h, src, dst, port, tname, sev, risk, cat, tech, phase, cid,
        flow=None, pii=None, sb=0, db=0, transport="tcp", **kw):
    return event(ts=base + timedelta(hours=h), src_ip=src, dst_ip=dst, dst_port=port,
                 transport=transport, threat_name=tname, severity=sev, norm_risk_level=risk,
                 former_category=cat, flowbits=flow or [], sensor=S1, rule_category="ids",
                 rule_name=tname, attack_phase=phase, correlation_id=cid, mitre_technique=tech,
                 src_bytes=sb, dst_bytes=db, is_malicious=True, scenario=K, pii_type=pii, **kw)


M = [
    # Phase 1 — initial access via exposed remote service (brute force then valid logon)
    mal(0.0, ext["vpn_bruteforce"], net["vpn_gw"], 443, "ET AUTH VPN Credential Brute-Force Burst",
        2, "High", "AUTH", "T1133", "initial_access", W1, [], auth_result="failure", sb=42000, db=8800),
    mal(1.0, ext["vpn_bruteforce"], net["vpn_gw"], 443, "ET AUTH VPN Logon Success After Brute-Force",
        3, "Medium", "AUTH", "T1133", "initial_access", W1, [], auth_result="success", sb=3200, db=9400),
    # Phase 2 — QUIET spread: lateral tool transfer toward Tier-1 data stores (low signature)
    mal(6.0, net["vpn_gw"], net["file_srv"], 445, "ET INFO Lateral Tool Transfer (PsExec-like)",
        4, "Low", "LATERAL", "T1570", "lateral_movement", W2, [], sb=2400000, db=6200),
    mal(8.0, net["file_srv"], net["dc"], 389, "ET INFO Directory Enumeration From File Server",
        4, "Low", "RECON", "T1570", "reconnaissance", W2, [], sb=4200, db=38000),
    mal(12.0, net["file_srv"], net["hr_db"], 1433, "ET INFO HR Database Record Access (staged)",
        3, "Medium", "INSIDER", "T1560", "data_discovery", W2, [], pii="ssn", sb=5200, db=740000, db_rows=88000),
    mal(16.0, net["file_srv"], net["cust_db"], 1433, "ET INFO Customer Database Bulk Read (staged)",
        4, "Low", "INSIDER", "T1560", "data_discovery", W2, [], pii="account_number", sb=6400, db=1200000, db_rows=110000),
    mal(20.0, net["file_srv"], net["backup_srv"], 445, "ET INFO Backup Repository Enumeration",
        3, "Medium", "INSIDER", "T1560", "collection", W2, [], pii="mixed_pii", sb=5800, db=9200000),
    # Phase 3 — bulk staging + pre-encryption exfil of HR + customer PII (loud)
    mal(40.0, net["file_srv"], net["file_srv"], 0, "ET INFO Mass Archive of HR + Customer Records",
        3, "Medium", "INSIDER", "T1560", "collection", W3, [], pii="mixed_pii", sb=88000000, db=0),
    mal(44.0, net["file_srv"], ext["exfil"], 443, "ET EXFIL Pre-Encryption HR PII Exfiltration",
        1, "Critical", "EXFIL", "T1537", "exfiltration", W3, ["ET.Evil"], pii="ssn_dob_full_identity", sb=52000000, db=4200),
    mal(46.0, net["cust_db"], ext["exfil"], 443, "ET EXFIL Pre-Encryption Customer PII Exfiltration",
        1, "Critical", "EXFIL", "T1537", "exfiltration", W3, ["ET.Evil"], pii="account_number", sb=64000000, db=3600),
    mal(50.0, net["file_srv"], ext["c2"], 443, "ET MALWARE RaaS Affiliate C2 Check-in",
        2, "High", "C2", "T1570", "exfiltration", W3, ["ET.BotCC"], sb=4200, db=62000),
    # Phase 4 — impact: ransomware deployment + encryption across shares
    mal(96.0, net["file_srv"], net["cust_db"], 445, "ET MALWARE Ransomware Encryption Sweep (SMB)",
        1, "Critical", "RANSOMWARE", "T1486", "impact", W4, ["ET.Evil", "ET.RAT"], sb=6200000, db=4400),
    mal(97.0, net["file_srv"], net["hr_db"], 445, "ET MALWARE Ransomware Encryption Sweep (HR share)",
        1, "Critical", "RANSOMWARE", "T1486", "impact", W4, ["ET.Evil", "ET.RAT"], sb=5800000, db=4200),
    mal(98.0, net["file_srv"], net["backup_srv"], 445, "ET MALWARE Backup Repository Encryption/Deletion",
        1, "Critical", "RANSOMWARE", "T1486", "impact", W4, ["ET.Evil"], sb=4200000, db=3800),
]

events = M + scatter_benign(K, base, net, 140, day_span_hours=120)
annotate_technique_counts(events)

if __name__ == "__main__":
    write_events(os.path.dirname(os.path.abspath(__file__)), events)
