#!/usr/bin/env python3
"""
Scenario 1 — Remote Access Trojan with PII Exfiltration (v6 §3.6 primary/PoC).
Chain: T1566.001 -> T1547.001 -> T1071.001 -> T1550.002/T1021.001 -> T1083/T1005 -> T1074.001/T1041.
Targets SSN + bank-account records on the payment/database servers.
"""
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from events import event, scatter_benign, annotate_technique_counts, write_events  # noqa: E402
from topology import BASE, NET, EXT, SENSORS  # noqa: E402

K = "s1_rat"
base, net, ext = BASE[K], NET[K], EXT[K]
S1, S2 = SENSORS[K]
W1, W2, W3 = "corr-s1-access", "corr-s1-internal", "corr-s1-exfil"


def mal(h, src, dst, port, tname, sev, risk, cat, tech, phase, cid,
        flow=None, pii=None, sb=0, db=0, transport="tcp", **kw):
    return event(ts=base + timedelta(hours=h), src_ip=src, dst_ip=dst, dst_port=port,
                 transport=transport, threat_name=tname, severity=sev, norm_risk_level=risk,
                 former_category=cat, flowbits=flow or [], sensor=S1, rule_category="ids",
                 rule_name=tname, attack_phase=phase, correlation_id=cid, mitre_technique=tech,
                 src_bytes=sb, dst_bytes=db, is_malicious=True, scenario=K, pii_type=pii, **kw)


M = [
    # Phase 1 — initial access (patient-zero workstation; low PII value yet)
    mal(0.0, ext["dropper"], net["user_ws"], 80, "ET MALWARE MediBank RAT Dropper Download",
        1, "Critical", "TROJAN", "T1566.001", "initial_access", W1, ["ET.Evil", "ET.RAT"], sb=4200, db=612000),
    mal(0.2, ext["dropper"], net["user_ws"], 80, "ET MALWARE Second-Stage DLL Retrieval",
        2, "High", "MALWARE", "T1566.001", "initial_access", W1, ["ET.Malware"], sb=1800, db=340000),
    mal(0.4, net["user_ws"], net["user_ws"], 0, "ET PERSISTENCE Registry Run Key Set (HKCU)",
        3, "Medium", "POLICY", "T1547.001", "persistence", W1, [], ps_encoded=True),
    # Phase 2 — C2 establishment
    mal(0.6, net["user_ws"], ext["c2"], 443, "ET MALWARE RAT Beacon CnC Checkin",
        2, "High", "C2", "T1071.001", "c2_establishment", W1, ["ET.BotCC"], sb=2400, db=88000),
    mal(1.5, net["user_ws"], ext["c2"], 443, "ET MALWARE In-Memory Payload Download",
        2, "High", "C2", "T1071.001", "c2_establishment", W1, ["ET.BotCC"], sb=1200, db=2100000),
    # Phase 3 — reconnaissance (touching high-value assets; low signature -> baseline misses)
    mal(5.0, net["user_ws"], net["dc"], 389, "ET INFO LDAP Directory Enumeration",
        3, "Medium", "RECON", "T1083", "reconnaissance", W2, [], sb=6400, db=42000),
    mal(5.4, net["user_ws"], net["payment_srv"], 8443, "ET SCAN Payment Server Service Probe",
        3, "Medium", "SCAN", "T1083", "reconnaissance", W2, ["ET.Scan"], sb=880, db=1200),
    mal(5.8, net["user_ws"], net["db_srv"], 1433, "ET SCAN SQL Server Discovery Probe",
        4, "Low", "RECON", "T1083", "reconnaissance", W2, [], sb=560, db=900),
    # Phase 4 — lateral movement onto finance + exec hosts and DB
    mal(13.0, net["user_ws"], net["finance_ws"], 445, "ET LATERAL Pass-the-Hash Authentication",
        3, "Medium", "LATERAL", "T1550.002", "lateral_movement", W2, [], sb=3400, db=8200),
    mal(13.5, net["finance_ws"], net["db_srv"], 1433, "ET LATERAL SQL Server Credentialed Access",
        3, "Medium", "LATERAL", "T1021.001", "lateral_movement", W2, [], sb=5200, db=64000),
    mal(15.0, net["finance_ws"], ext["c2"], 443, "ET MALWARE Secondary Host Beacon",
        2, "High", "C2", "T1071.001", "lateral_movement", W2, ["ET.BotCC"], sb=2200, db=41000),
    mal(18.0, net["user_ws"], net["exec_ws"], 3389, "ET LATERAL RDP Pivot to Executive Host",
        3, "Medium", "LATERAL", "T1021.001", "lateral_movement", W2, [], sb=4400, db=9800),
    # Phase 5 — data discovery on Tier-1 assets
    mal(48.0, net["finance_ws"], net["db_srv"], 1433, "ET EXFIL Bulk Patient/Financial DB Query",
        2, "High", "INSIDER", "T1005", "data_discovery", W3, [], pii="ssn", sb=9200, db=10800000),
    mal(49.0, net["finance_ws"], net["payment_srv"], 8443, "ET EXFIL PCI-CDE Payment API Bulk Read",
        1, "Critical", "INSIDER", "T1005", "data_discovery", W3, [], pii="account_number", sb=7400, db=21000000),
    mal(50.0, net["user_ws"], ext["c2"], 443, "ET MALWARE Keylogger Banking Credential Upload",
        1, "Critical", "EXFIL", "T1005", "data_discovery", W3, ["ET.Evil"], pii="banking_credentials", sb=880000, db=2400),
    # Phase 6 — exfiltration
    mal(72.0, net["db_srv"], ext["exfil"], 443, "ET EXFIL Medical/Financial PII Bulk POST",
        1, "Critical", "EXFIL", "T1041", "exfiltration", W3, ["ET.Evil"], pii="ssn_dob_full_identity", sb=21000000, db=4200),
    mal(73.0, net["db_srv"], ext["exfil"], 443, "ET EXFIL Account Number Batch Transfer",
        1, "Critical", "EXFIL", "T1041", "exfiltration", W3, ["ET.Evil"], pii="account_number", sb=10800000, db=2200),
    mal(78.0, net["payment_srv"], ext["exfil"], 443, "ET EXFIL Full-Track Card Data Egress",
        1, "Critical", "EXFIL", "T1041", "exfiltration", W3, ["ET.Evil", "ET.RAT"], pii="payment_card_full_track", sb=104900000, db=6200),
    mal(84.0, net["payment_srv"], ext["c2b"], 443, "ET MALWARE Secondary C2 From Payment Server",
        1, "Critical", "C2", "T1071.001", "exfiltration", W3, ["ET.BotCC"], sb=4200, db=52000),
    mal(90.0, net["user_ws"], ext["c2"], 53, "ET EXFIL DNS Tunneling Covert Channel",
        2, "High", "EXFIL", "T1041", "exfiltration", W3, ["ET.DNSTunnel"], transport="udp", pii="mixed_pii", sb=2100000, db=180000),
]

events = M + scatter_benign(K, base, net, 120, day_span_hours=96)
annotate_technique_counts(events)

if __name__ == "__main__":
    write_events(os.path.dirname(os.path.abspath(__file__)), events)
