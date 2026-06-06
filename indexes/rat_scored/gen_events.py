#!/usr/bin/env python3
"""
Generate RAT_SCORED index: APT-grade financial RAT targeting a healthcare credit union.

Score fields (base_alert_severity, asset_criticality, pii_exposure_tier,
attack_complexity, composite) are NOT set here — they are computed at index
time by the 'rat-scoring-pipeline' ES ingest pipeline defined in setup.sh.
"""
import json
import random
from datetime import datetime, timedelta

random.seed(42)

BASE = datetime(2026, 6, 15, 7, 30, 0)

def ts(delta_hours, jitter_minutes=0):
    t = BASE + timedelta(hours=delta_hours, minutes=jitter_minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Infrastructure
USER_WS      = "10.20.1.88"
FINANCE_WS   = "10.20.1.92"
FINANCE_WS2  = "10.20.1.95"
EXEC_WS      = "10.20.1.200"
DOMAIN_CTRL  = "10.20.0.10"
PAYMENT_SRV  = "10.20.5.20"
DB_SRV       = "10.20.5.30"
C2_PRIMARY   = "185.220.101.72"
C2_SECONDARY = "194.165.16.88"
EXFIL_SRV    = "91.215.153.44"
DROPPER_HOST = "45.142.212.77"
SENSOR       = "HBCU-NIDS-01"
SENSOR2      = "HBCU-NIDS-02"

# 4-hour correlation window IDs
CORR_W1 = "corr-20260615-0730"   # initial access / C2
CORR_W2 = "corr-20260615-1130"   # recon
CORR_W3 = "corr-20260616-0730"   # lateral movement
CORR_W4 = "corr-20260616-1930"   # privilege escalation
CORR_W5 = "corr-20260617-0730"   # data discovery
CORR_W6 = "corr-20260618-0730"   # exfiltration


def event(
    timestamp, src_ip, dst_ip, dst_port, transport,
    threat_name, severity, norm_risk_level, log_level,
    former_category, flowbits, vlan, iface, sensor, rule_category,
    attack_phase, correlation_id,
    src_bytes=0, dst_bytes=0, src_packets=1, dst_packets=0,
    pii_type=None, response="Allow"
):
    e = {
        "@timestamp": timestamp,
        "source": {
            "ip": src_ip,
            "port": random.randint(49152, 65535),
            "bytes": src_bytes,
            "packets": src_packets
        },
        "destination": {
            "ip": dst_ip,
            "port": dst_port,
            "bytes": dst_bytes,
            "packets": dst_packets
        },
        "network": {"transport": transport},
        "threat": {"name": threat_name},
        "event": {
            "type": "alert",
            "severity": severity,
            "norm_risk_level": norm_risk_level,
            "response": response,
            "action": "allowed"
        },
        "log": {"level": log_level},
        "rule": {"category": rule_category},
        "observer": {
            "hostname": sensor,
            "product": "Suricata",
            "vendor": "Suricata",
            "type": "IDS/IPS",
            "ingress": {"interface": {"name": iface}, "vlan": {"id": vlan}}
        },
        "metadata": {
            "former_category": former_category,
            "flowbits": flowbits,
            "affected_product": ["Windows"],
            "attack_target": ["Healthcare Financial Systems"],
            "correlation_id": correlation_id
        },
        "custom": {"str1": attack_phase}
    }
    if pii_type:
        e["metadata"]["pii_type"] = pii_type
    return e


events = []

# ── Phase 1: Initial Access (T+0h) ───────────────────────────────────────────
events.append(event(
    ts(0, 5), USER_WS, DROPPER_HOST, 80, "TCP",
    "ET TROJAN Win32.MediBank Dropper Download via HTTP (Spear-Phishing Link)",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.Malware", "ET.ThreatIntel"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "initial_access", CORR_W1,
    src_bytes=512, dst_bytes=307200,
))

events.append(event(
    ts(0, 12), USER_WS, DROPPER_HOST, 80, "TCP",
    "ET MALWARE MediBank.RAT Second-Stage DLL Fetch - Loader Activity Detected",
    1, "Critical", "Critical", "MALWARE",
    ["ET.Evil", "ET.Malware"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "initial_access", CORR_W1,
    src_bytes=256, dst_bytes=614400,
))

# ── Phase 2: C2 Establishment (T+0h to T+4h) ─────────────────────────────────
events.append(event(
    ts(0, 20), USER_WS, C2_PRIMARY, 443, "TCP",
    "ET TROJAN MediBank RAT First-Stage C2 Check-in (TLS Encrypted Beacon)",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.RAT", "ET.ThreatIntel"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "c2_establishment", CORR_W1,
    src_bytes=1024, dst_bytes=8192,
))

events.append(event(
    ts(0, 35), USER_WS, C2_PRIMARY, 443, "TCP",
    "ET TROJAN MediBank RAT Stage-2 Payload Download - In-Memory Injection",
    1, "Critical", "Critical", "MALWARE",
    ["ET.Evil", "ET.Malware", "ET.RAT"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "c2_establishment", CORR_W1,
    src_bytes=2048, dst_bytes=2097152,
))

events.append(event(
    ts(1, 0), USER_WS, C2_PRIMARY, 443, "TCP",
    "ET TROJAN MediBank RAT Periodic Heartbeat (5-Minute Interval)",
    2, "High", "High", "TROJAN",
    ["ET.Evil", "ET.RAT"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "c2_establishment", CORR_W1,
    src_bytes=380, dst_bytes=192,
))

events.append(event(
    ts(2, 0), USER_WS, C2_PRIMARY, 443, "TCP",
    "ET TROJAN MediBank/Dridex-variant BotNet Registration POST Detected",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.BotCC", "ET.Malware"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "c2_establishment", CORR_W1,
    src_bytes=3072, dst_bytes=1024,
))

# ── Phase 3: Reconnaissance (T+4h to T+12h) ──────────────────────────────────
events.append(event(
    ts(4, 10), USER_WS, DOMAIN_CTRL, 389, "TCP",
    "ET SCAN LDAP Enumeration - Active Directory Object Harvesting",
    1, "Critical", "Critical", "SCAN",
    ["ET.Scan", "ET.Evil"],
    1100, "mon0", SENSOR, "Attempted Information Leak",
    "reconnaissance", CORR_W2,
    src_bytes=512, dst_bytes=32768,
))

events.append(event(
    ts(4, 25), USER_WS, "10.20.5.0", 445, "TCP",
    "ET SCAN SMB Sweep - Internal Server Segment from Compromised Workstation",
    1, "Critical", "Critical", "SCAN",
    ["ET.Scan"],
    1100, "mon0", SENSOR, "Attempted Information Leak",
    "reconnaissance", CORR_W2,
    src_bytes=1024, dst_bytes=512,
))

events.append(event(
    ts(5, 0), USER_WS, PAYMENT_SRV, 8443, "TCP",
    "ET TROJAN RAT Probing PCI-CDE Payment Processing Server - Port 8443",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.Malware"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "reconnaissance", CORR_W2,
    src_bytes=256, dst_bytes=128,
))

events.append(event(
    ts(6, 0), USER_WS, "10.20.1.0", 3389, "TCP",
    "ET SCAN RDP Scanner - Enumerating Lateral Movement Candidates",
    1, "Critical", "Critical", "SCAN",
    ["ET.Scan", "ET.Evil"],
    1100, "mon0", SENSOR, "Attempted Information Leak",
    "reconnaissance", CORR_W2,
    src_bytes=512, dst_bytes=256,
))

# ── Phase 4: Lateral Movement (T+12h to T+36h) ───────────────────────────────
events.append(event(
    ts(12, 5), USER_WS, FINANCE_WS, 445, "TCP",
    "ET EXPLOIT Pass-the-Hash SMB Authentication from Compromised Workstation",
    1, "Critical", "Critical", "EXPLOIT",
    ["ET.Evil", "ET.Exploit"],
    1100, "mon0", SENSOR, "Attempted User Privilege Gain",
    "lateral_movement", CORR_W3,
    src_bytes=4096, dst_bytes=2048,
))

events.append(event(
    ts(12, 18), USER_WS, FINANCE_WS, 3389, "TCP",
    "ET POLICY RDP Lateral Move - Source is Known-Compromised Host",
    1, "Critical", "Critical", "POLICY",
    ["ET.Evil"],
    1100, "mon0", SENSOR, "Potential Corporate Privacy Violation",
    "lateral_movement", CORR_W3,
    src_bytes=8192, dst_bytes=65536,
))

events.append(event(
    ts(12, 35), FINANCE_WS, C2_PRIMARY, 443, "TCP",
    "ET TROJAN MediBank RAT Beacon from Newly Infected Finance Workstation",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.RAT", "ET.ThreatIntel"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "lateral_movement", CORR_W3,
    src_bytes=380, dst_bytes=192,
))

events.append(event(
    ts(18, 3), FINANCE_WS, DB_SRV, 1433, "TCP",
    "ET TROJAN RAT SQL Server Connection from Compromised Finance Workstation",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.Malware"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "lateral_movement", CORR_W3,
    src_bytes=4096, dst_bytes=32768,
))

events.append(event(
    ts(20, 0), FINANCE_WS, EXEC_WS, 3389, "TCP",
    "ET POLICY Unauthorized RDP to CFO Workstation - Lateral Escalation Detected",
    1, "Critical", "Critical", "POLICY",
    ["ET.Evil"],
    1100, "mon0", SENSOR, "Potential Corporate Privacy Violation",
    "lateral_movement", CORR_W3,
    src_bytes=8192, dst_bytes=65536,
))

events.append(event(
    ts(20, 20), EXEC_WS, C2_PRIMARY, 443, "TCP",
    "ET TROJAN MediBank RAT Beacon from Compromised CFO Workstation",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.RAT", "ET.BotCC"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "lateral_movement", CORR_W3,
    src_bytes=380, dst_bytes=192,
))

# ── Phase 5: Privilege Escalation (T+36h to T+48h) ───────────────────────────
events.append(event(
    ts(36, 10), FINANCE_WS, DOMAIN_CTRL, 88, "TCP",
    "ET EXPLOIT Kerberoasting Attack - SPN Ticket Request Flood to DC",
    1, "Critical", "Critical", "EXPLOIT",
    ["ET.Evil", "ET.Exploit"],
    1100, "mon0", SENSOR, "Attempted User Privilege Gain",
    "privilege_escalation", CORR_W4,
    src_bytes=2048, dst_bytes=16384,
))

events.append(event(
    ts(36, 30), FINANCE_WS, DOMAIN_CTRL, 445, "TCP",
    "ET EXPLOIT Pass-the-Ticket Kerberos Lateral Auth - Domain Controller Targeted",
    1, "Critical", "Critical", "EXPLOIT",
    ["ET.Evil", "ET.Exploit"],
    1100, "mon0", SENSOR, "Attempted User Privilege Gain",
    "privilege_escalation", CORR_W4,
    src_bytes=4096, dst_bytes=8192,
))

events.append(event(
    ts(40, 0), EXEC_WS, DOMAIN_CTRL, 636, "TCP",
    "ET TROJAN RAT LDAPS Admin Query - Stolen Elevated Credential in Active Use",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.Malware"],
    1100, "mon0", SENSOR, "Attempted User Privilege Gain",
    "privilege_escalation", CORR_W4,
    src_bytes=1024, dst_bytes=65536,
))

# ── Phase 6: Data Discovery & Credential Harvest (T+48h to T+72h) ────────────
events.append(event(
    ts(48, 5), FINANCE_WS, DB_SRV, 1433, "TCP",
    "ET TROJAN MediBank RAT Patient/Financial DB Bulk Query - Privilege Misuse",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.Malware", "ET.ThreatIntel"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "data_discovery", CORR_W5,
    pii_type="medical_financial_records",
    src_bytes=4096, dst_bytes=10485760,
))

events.append(event(
    ts(50, 0), FINANCE_WS, PAYMENT_SRV, 8443, "TCP",
    "ET TROJAN RAT Payment Card Database API Access - PCI-CDE Scope Breach",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.Malware"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "data_discovery", CORR_W5,
    pii_type="payment_card",
    src_bytes=2048, dst_bytes=20971520,
))

events.append(event(
    ts(52, 0), EXEC_WS, C2_PRIMARY, 443, "TCP",
    "ET MALWARE Win32.Keylogger Financial Credential Upload - Banking Auth Tokens",
    1, "Critical", "Critical", "MALWARE",
    ["ET.Evil", "ET.Malware", "ET.BotCC"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "data_discovery", CORR_W5,
    pii_type="banking_credentials",
    src_bytes=65536, dst_bytes=1024,
))

events.append(event(
    ts(56, 0), FINANCE_WS, C2_PRIMARY, 443, "TCP",
    "ET TROJAN Win32.FormGrabber Banking POST Intercept - Full PAN Captured",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.Malware", "ET.BotCC"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "data_discovery", CORR_W5,
    pii_type="credit_card",
    src_bytes=32768, dst_bytes=512,
))

events.append(event(
    ts(60, 0), FINANCE_WS2, C2_PRIMARY, 443, "TCP",
    "ET TROJAN Banker.GenericKD SSN/PII Harvest Module - Full Identity Package",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.Malware", "ET.BotCC"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "data_discovery", CORR_W5,
    pii_type="ssn_dob_full_identity",
    src_bytes=16384, dst_bytes=512,
))

# ── Phase 7: Exfiltration (T+72h to T+120h) ──────────────────────────────────
events.append(event(
    ts(72, 5), FINANCE_WS, EXFIL_SRV, 443, "TCP",
    "ET CURRENT_EVENTS Financial/Medical PII Bulk Exfil - Encrypted HTTPS POST",
    1, "Critical", "Critical", "EXFIL",
    ["ET.Evil", "ET.Malware", "ET.ThreatIntel"],
    1100, "mon0", SENSOR, "Potential Corporate Privacy Violation",
    "exfiltration", CORR_W6,
    pii_type="medical_financial_records",
    src_bytes=20971520, dst_bytes=2048,
))

events.append(event(
    ts(72, 30), FINANCE_WS2, EXFIL_SRV, 443, "TCP",
    "ET CURRENT_EVENTS Bulk Account/Routing Number Exfiltration Detected",
    1, "Critical", "Critical", "EXFIL",
    ["ET.Evil", "ET.Malware"],
    1100, "mon0", SENSOR, "Potential Corporate Privacy Violation",
    "exfiltration", CORR_W6,
    pii_type="account_number",
    src_bytes=10485760, dst_bytes=1024,
))

events.append(event(
    ts(80, 0), EXEC_WS, EXFIL_SRV, 443, "TCP",
    "ET CURRENT_EVENTS Executive Financial Records Exfiltration Detected",
    1, "Critical", "Critical", "EXFIL",
    ["ET.Evil", "ET.Malware", "ET.ThreatIntel"],
    1100, "mon0", SENSOR, "Potential Corporate Privacy Violation",
    "exfiltration", CORR_W6,
    pii_type="financial_records",
    src_bytes=41943040, dst_bytes=2048,
))

events.append(event(
    ts(84, 0), PAYMENT_SRV, EXFIL_SRV, 443, "TCP",
    "ET TROJAN Payment Card Full-Track Data Exfil from PCI-CDE Server",
    1, "Critical", "Critical", "EXFIL",
    ["ET.Evil", "ET.Malware", "ET.BotCC"],
    1200, "mon1", SENSOR2, "Potential Corporate Privacy Violation",
    "exfiltration", CORR_W6,
    pii_type="payment_card_full_track",
    src_bytes=104857600, dst_bytes=2048,
))

events.append(event(
    ts(84, 30), PAYMENT_SRV, C2_SECONDARY, 8080, "TCP",
    "ET TROJAN MediBank RAT Secondary C2 Registration from Payment Server",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.RAT"],
    1200, "mon1", SENSOR2, "A Network Trojan was Detected",
    "exfiltration", CORR_W6,
    src_bytes=1024, dst_bytes=4096,
))

events.append(event(
    ts(90, 0), FINANCE_WS, EXFIL_SRV, 443, "TCP",
    "ET CURRENT_EVENTS Repeated Credit Card PII Exfiltration - Staging Round 2",
    1, "Critical", "Critical", "EXFIL",
    ["ET.Evil", "ET.Malware"],
    1100, "mon0", SENSOR, "Potential Corporate Privacy Violation",
    "exfiltration", CORR_W6,
    pii_type="credit_card",
    src_bytes=31457280, dst_bytes=1024,
))

events.append(event(
    ts(96, 0), FINANCE_WS, C2_PRIMARY, 53, "UDP",
    "ET TROJAN MediBank RAT DNS Tunneling C2 - Covert Exfil Channel Active",
    1, "Critical", "Critical", "TROJAN",
    ["ET.Evil", "ET.RAT", "ET.DNSTunnel"],
    1100, "mon0", SENSOR, "A Network Trojan was Detected",
    "exfiltration", CORR_W6,
    pii_type="mixed_pii",
    src_bytes=4096, dst_bytes=2048,
))

# ── Build bulk payload ─────────────────────────────────────────────────────────
bulk_lines = []
for e in events:
    bulk_lines.append(json.dumps({"index": {"_index": "rat_scored"}}))
    bulk_lines.append(json.dumps(e))

with open("/tmp/rat_scored_bulk.ndjson", "w") as f:
    f.write("\n".join(bulk_lines) + "\n")

print(f"Generated {len(events)} events across 7 attack phases")
for phase in ["initial_access", "c2_establishment", "reconnaissance",
              "lateral_movement", "privilege_escalation", "data_discovery", "exfiltration"]:
    n = sum(1 for e in events if e["custom"]["str1"] == phase)
    print(f"  {phase}: {n} events")

