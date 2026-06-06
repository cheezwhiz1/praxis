#!/usr/bin/env python3
"""
Generate TEST_RAT index data simulating a financial RAT targeting PII.
Attack phases: Initial Access → C2 Establishment → Recon → Lateral Movement
              → Credential Harvest → PII Exfiltration → Persistence
"""
import json
from datetime import datetime, timedelta

BASE = datetime(2026, 5, 20, 8, 0, 0)  # attack starts 2026-05-20

def ts(delta_hours, jitter_minutes=0):
    t = BASE + timedelta(hours=delta_hours, minutes=jitter_minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

# Infrastructure
INTERNAL_FINANCE   = "10.50.1.100"   # finance workstation 1 (patient zero)
INTERNAL_FINANCE2  = "10.50.1.105"   # finance workstation 2 (lateral move target)
INTERNAL_MANAGER   = "10.50.1.110"   # CFO laptop
PAYMENT_SERVER     = "10.50.2.50"    # payment processing server
C2_PRIMARY         = "185.220.101.45"  # TOR exit / known RAT C2
C2_SECONDARY       = "194.165.16.10"  # secondary C2
EXFIL_SERVER       = "91.215.153.200" # exfiltration drop server
DROPPER_HOST       = "45.142.212.100" # initial dropper delivery host
SENSOR             = "FNBK01-Z-NIDS-01"
SENSOR2            = "FNBK01-Z-NIDS-02"

def event(
    timestamp, src_ip, dst_ip, dst_port, transport,
    threat_name, severity, norm_risk_level, log_level,
    former_category, flowbits, vlan, interface, sensor,
    rule_category, response="Allow", attack_phase=None, pii_type=None,
    src_port=None, src_bytes=0, dst_bytes=0, src_packets=1, dst_packets=0
):
    import random
    sp = src_port or random.randint(49152, 65535)
    e = {
        "@timestamp": timestamp,
        "source": {"ip": src_ip, "port": sp, "bytes": src_bytes, "packets": src_packets},
        "destination": {"ip": dst_ip, "port": dst_port, "bytes": dst_bytes, "packets": dst_packets},
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
            "ingress": {"interface": {"name": interface}, "vlan": {"id": vlan}}
        },
        "metadata": {
            "former_category": former_category,
            "flowbits": flowbits,
            "affected_product": ["Windows"],
            "attack_target": ["Financial Systems"]
        }
    }
    if attack_phase:
        e["custom"] = {"str1": attack_phase}
    if pii_type:
        e["metadata"]["pii_type"] = pii_type
    return e

events = []

# ── Phase 1: Initial Access (T+0h to T+2h) ───────────────────────────────────
events.append(event(
    ts(0, 3), INTERNAL_FINANCE, DROPPER_HOST, 80, "TCP",
    "ET TROJAN Win32.FinancialRAT Initial Dropper Download via HTTP",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware", "ET.ThreatIntel"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="initial_access", src_bytes=512, dst_bytes=284672
))

events.append(event(
    ts(0, 8), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT/Banker First-Stage CnC Checkin (HTTPS)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware", "ET.RAT"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="c2_establishment", src_bytes=1240, dst_bytes=4096
))

events.append(event(
    ts(0, 15), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET MALWARE Win32.RAT Staged Payload Download Detected",
    1, "Critical", "Critical",
    "MALWARE", ["ET.Evil", "ET.Malware"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="c2_establishment", src_bytes=2048, dst_bytes=524288
))

events.append(event(
    ts(0, 22), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT Periodic Beacon (Interval 300s)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT", "ET.ThreatIntel"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="c2_establishment", src_bytes=412, dst_bytes=256
))

events.append(event(
    ts(1, 0), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT Periodic Beacon (Interval 300s)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT", "ET.ThreatIntel"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="c2_establishment", src_bytes=412, dst_bytes=256
))

events.append(event(
    ts(1, 5), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN Win32.Dridex/Zeus-variant Banking Trojan CnC Registration",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.BotCC", "ET.Malware"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="c2_establishment", src_bytes=2880, dst_bytes=1024
))

# ── Phase 2: Reconnaissance (T+2h to T+12h) ──────────────────────────────────
events.append(event(
    ts(2, 10), INTERNAL_FINANCE, "10.50.0.1", 389, "TCP",
    "ET SCAN LDAP Enumeration - Financial Network AD Recon",
    1, "Critical", "Critical",
    "SCAN", ["ET.Scan", "ET.Evil"],
    2100, "mon1", SENSOR,
    "Attempted Information Leak",
    attack_phase="reconnaissance", src_bytes=512, dst_bytes=18432
))

events.append(event(
    ts(2, 18), INTERNAL_FINANCE, "10.50.2.0", 445, "TCP",
    "ET SCAN SMB Scanner - Internal Network Sweep from Compromised Host",
    1, "Critical", "Critical",
    "SCAN", ["ET.Scan"],
    2100, "mon1", SENSOR,
    "Attempted Information Leak",
    attack_phase="reconnaissance", src_bytes=1024, dst_bytes=512
))

events.append(event(
    ts(2, 35), INTERNAL_FINANCE, PAYMENT_SERVER, 8443, "TCP",
    "ET TROJAN RAT Probing Financial Payment Processing Port",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="reconnaissance", src_bytes=256, dst_bytes=128
))

events.append(event(
    ts(3, 0), INTERNAL_FINANCE, "10.50.1.0", 3389, "TCP",
    "ET SCAN RDP Scanner - RAT Identifying Lateral Move Targets",
    1, "Critical", "Critical",
    "SCAN", ["ET.Scan", "ET.Evil"],
    2100, "mon1", SENSOR,
    "Attempted Information Leak",
    attack_phase="reconnaissance", src_bytes=512, dst_bytes=256
))

# ── Phase 3: Lateral Movement (T+12h to T+36h) ───────────────────────────────
events.append(event(
    ts(12, 5), INTERNAL_FINANCE, INTERNAL_FINANCE2, 445, "TCP",
    "ET EXPLOIT Win32 Pass-the-Hash SMB Authentication Attempt",
    1, "Critical", "Critical",
    "EXPLOIT", ["ET.Evil", "ET.Exploit"],
    2100, "mon1", SENSOR,
    "Attempted User Privilege Gain",
    attack_phase="lateral_movement", src_bytes=4096, dst_bytes=2048
))

events.append(event(
    ts(12, 12), INTERNAL_FINANCE, INTERNAL_FINANCE2, 3389, "TCP",
    "ET POLICY RDP Connection from Known-Compromised Host",
    1, "Critical", "Critical",
    "POLICY", ["ET.Evil"],
    2100, "mon1", SENSOR,
    "Potential Corporate Privacy Violation",
    attack_phase="lateral_movement", src_bytes=8192, dst_bytes=32768
))

events.append(event(
    ts(12, 25), INTERNAL_FINANCE2, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT CnC Beacon from Newly Infected Host",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT", "ET.ThreatIntel"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="lateral_movement", src_bytes=412, dst_bytes=256
))

events.append(event(
    ts(18, 3), INTERNAL_FINANCE, PAYMENT_SERVER, 1433, "TCP",
    "ET TROJAN RAT SQL Server Connection from Compromised Workstation",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="lateral_movement", src_bytes=4096, dst_bytes=16384
))

events.append(event(
    ts(20, 0), INTERNAL_FINANCE, INTERNAL_MANAGER, 3389, "TCP",
    "ET POLICY Unauthorized RDP to Finance Manager Workstation (Lateral Movement)",
    1, "Critical", "Critical",
    "POLICY", ["ET.Evil"],
    2100, "mon1", SENSOR,
    "Potential Corporate Privacy Violation",
    attack_phase="lateral_movement", src_bytes=8192, dst_bytes=32768
))

events.append(event(
    ts(20, 15), INTERNAL_MANAGER, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT CnC Beacon - CFO Workstation Compromised",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT", "ET.BotCC"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="lateral_movement", src_bytes=412, dst_bytes=256
))

# ── Phase 4: Credential Harvest / PII Access (T+36h to T+72h) ────────────────
events.append(event(
    ts(36, 5), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET MALWARE Win32.Keylogger Financial Credential Upload Detected",
    1, "Critical", "Critical",
    "MALWARE", ["ET.Evil", "ET.Malware", "ET.ThreatIntel"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="credential_harvest", pii_type="banking_credentials",
    src_bytes=28672, dst_bytes=1024
))

events.append(event(
    ts(36, 20), INTERNAL_MANAGER, C2_PRIMARY, 443, "TCP",
    "ET MALWARE Win32.Keylogger Financial Credential Upload Detected",
    1, "Critical", "Critical",
    "MALWARE", ["ET.Evil", "ET.Malware"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="credential_harvest", pii_type="banking_credentials",
    src_bytes=45056, dst_bytes=1024
))

events.append(event(
    ts(40, 0), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN Win32.FormGrabber Banking Site POST Intercept (Credit Card Data)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware", "ET.BotCC"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="credential_harvest", pii_type="credit_card",
    src_bytes=16384, dst_bytes=512
))

events.append(event(
    ts(40, 30), INTERNAL_FINANCE2, C2_PRIMARY, 443, "TCP",
    "ET TROJAN Win32.FormGrabber Banking Site POST Intercept (Account Numbers)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware", "ET.BotCC"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="credential_harvest", pii_type="account_number",
    src_bytes=12288, dst_bytes=512
))

events.append(event(
    ts(44, 10), INTERNAL_FINANCE, PAYMENT_SERVER, 8443, "TCP",
    "ET TROJAN RAT Accessing Payment Card Database API (PCI Scope)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="credential_harvest", pii_type="payment_card",
    src_bytes=2048, dst_bytes=2097152
))

events.append(event(
    ts(48, 0), INTERNAL_MANAGER, C2_PRIMARY, 443, "TCP",
    "ET MALWARE Win32.ScreenGrabber Encrypted Screenshot Upload (Financial Docs)",
    1, "Critical", "Critical",
    "MALWARE", ["ET.Evil", "ET.Malware"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="credential_harvest", pii_type="financial_documents",
    src_bytes=3145728, dst_bytes=1024
))

events.append(event(
    ts(52, 0), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN Banker.GenericKD SSN/PII Harvesting Module Active",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware", "ET.BotCC"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="credential_harvest", pii_type="ssn",
    src_bytes=8192, dst_bytes=512
))

# ── Phase 5: PII Exfiltration (T+72h to T+120h) ──────────────────────────────
events.append(event(
    ts(72, 5), INTERNAL_FINANCE, EXFIL_SERVER, 443, "TCP",
    "ET CURRENT_EVENTS Financial PII Bulk Exfiltration via HTTPS POST",
    1, "Critical", "Critical",
    "EXFIL", ["ET.Evil", "ET.Malware", "ET.ThreatIntel"],
    2100, "mon1", SENSOR,
    "Potential Corporate Privacy Violation",
    attack_phase="exfiltration", pii_type="credit_card",
    src_bytes=10485760, dst_bytes=2048
))

events.append(event(
    ts(72, 45), INTERNAL_FINANCE2, EXFIL_SERVER, 443, "TCP",
    "ET CURRENT_EVENTS Financial PII Bulk Exfiltration via HTTPS POST",
    1, "Critical", "Critical",
    "EXFIL", ["ET.Evil", "ET.Malware"],
    2100, "mon1", SENSOR,
    "Potential Corporate Privacy Violation",
    attack_phase="exfiltration", pii_type="account_number",
    src_bytes=5242880, dst_bytes=1024
))

events.append(event(
    ts(80, 0), INTERNAL_MANAGER, EXFIL_SERVER, 443, "TCP",
    "ET CURRENT_EVENTS Executive Financial Data Exfiltration Detected",
    1, "Critical", "Critical",
    "EXFIL", ["ET.Evil", "ET.Malware", "ET.ThreatIntel"],
    2100, "mon1", SENSOR,
    "Potential Corporate Privacy Violation",
    attack_phase="exfiltration", pii_type="financial_records",
    src_bytes=20971520, dst_bytes=2048
))

events.append(event(
    ts(84, 0), PAYMENT_SERVER, EXFIL_SERVER, 443, "TCP",
    "ET TROJAN Payment Card Database Exfil - Full PAN Track Data Detected",
    1, "Critical", "Critical",
    "EXFIL", ["ET.Evil", "ET.Malware", "ET.BotCC"],
    2100, "mon2", SENSOR2,
    "Potential Corporate Privacy Violation",
    attack_phase="exfiltration", pii_type="payment_card_full_track",
    src_bytes=52428800, dst_bytes=2048
))

events.append(event(
    ts(84, 30), PAYMENT_SERVER, C2_SECONDARY, 8080, "TCP",
    "ET TROJAN RAT Secondary CnC Check-in from Payment Server",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT"],
    2200, "mon2", SENSOR2,
    "A Network Trojan was Detected",
    attack_phase="exfiltration", src_bytes=1024, dst_bytes=4096
))

events.append(event(
    ts(90, 10), INTERNAL_FINANCE, EXFIL_SERVER, 443, "TCP",
    "ET CURRENT_EVENTS Repeated PII Exfiltration Staging - Credit Card Numbers",
    1, "Critical", "Critical",
    "EXFIL", ["ET.Evil", "ET.Malware"],
    2100, "mon1", SENSOR,
    "Potential Corporate Privacy Violation",
    attack_phase="exfiltration", pii_type="credit_card",
    src_bytes=15728640, dst_bytes=1024
))

events.append(event(
    ts(96, 0), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT DNS Tunneling C2 Communication",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT", "ET.DNSTunnel"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="exfiltration", pii_type="mixed_pii",
    src_bytes=4096, dst_bytes=2048
))

# ── Phase 6: Persistence (T+120h to T+168h) ───────────────────────────────────
events.append(event(
    ts(120, 0), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT Update Module Download - RAT Upgrade",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.Malware", "ET.RAT"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="persistence", src_bytes=2048, dst_bytes=1048576
))

events.append(event(
    ts(120, 30), INTERNAL_FINANCE, C2_SECONDARY, 8080, "TCP",
    "ET TROJAN RAT Secondary Backdoor Registration - Redundant Persistence",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT", "ET.BotCC"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="persistence", src_bytes=1024, dst_bytes=512
))

events.append(event(
    ts(144, 0), INTERNAL_FINANCE, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT Periodic Beacon (Interval 300s)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="persistence", src_bytes=412, dst_bytes=256
))

events.append(event(
    ts(144, 5), INTERNAL_FINANCE2, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT Periodic Beacon (Interval 300s)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="persistence", src_bytes=412, dst_bytes=256
))

events.append(event(
    ts(144, 10), INTERNAL_MANAGER, C2_PRIMARY, 443, "TCP",
    "ET TROJAN FinancialRAT Periodic Beacon (Interval 300s)",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT"],
    2100, "mon1", SENSOR,
    "A Network Trojan was Detected",
    attack_phase="persistence", src_bytes=412, dst_bytes=256
))

events.append(event(
    ts(168, 0), PAYMENT_SERVER, C2_SECONDARY, 8080, "TCP",
    "ET TROJAN RAT Long-term Persistence Beacon from Payment Server",
    1, "Critical", "Critical",
    "TROJAN", ["ET.Evil", "ET.RAT"],
    2200, "mon2", SENSOR2,
    "A Network Trojan was Detected",
    attack_phase="persistence", src_bytes=412, dst_bytes=256
))

# Build bulk payload
bulk_lines = []
for e in events:
    bulk_lines.append(json.dumps({"index": {"_index": "test_rat"}}))
    bulk_lines.append(json.dumps(e))

with open("/tmp/rat_bulk.ndjson", "w") as f:
    f.write("\n".join(bulk_lines) + "\n")

print(f"Generated {len(events)} events across 6 attack phases")
for phase in ["initial_access","c2_establishment","reconnaissance","lateral_movement",
              "credential_harvest","exfiltration","persistence"]:
    n = sum(1 for e in events if e.get("custom", {}).get("str1") == phase)
    print(f"  {phase}: {n} events")
