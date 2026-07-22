#!/usr/bin/env python3
"""
Network topology and asset inventory for the five Praxis scenarios.

Each scenario lives in its own /24 for clarity. The ASSETS list is the single
source of truth for the `asset_inventory` enrichment index: every internal IP maps
to a criticality (0-50), an asset_type, a PII data_classification tier, and the PII
categories it stores. The enriched pipeline looks up source.ip and destination.ip
against this inventory and scores on the higher-criticality endpoint.

data_classification tiers (v6 PII taxonomy):
  tier1  Critical PII   (SSN, full PAN, bank acct+routing)      -> pii base 20
  tier2  High PII        (name+DOB, account credentials)         -> pii base 14
  tier3  Moderate PII    (email, phone)                          -> pii base  8
  tier4  Low PII         (public / minimal)                      -> pii base  3
  none   no PII association                                      -> pii base  0
"""
from datetime import datetime

# Campaign clock. All scenarios are generated relative to their own BASE so their
# timelines do not overlap on the shared Kibana time axis.
BASE = {
    "s1_rat":        datetime(2026, 6, 15,  7, 30, 0),
    "s2_ato":        datetime(2026, 6, 22,  9,  0, 0),
    "s3_insider":    datetime(2026, 6, 29, 13,  0, 0),
    "s4_sqli":       datetime(2026, 7,  6, 10, 15, 0),
    "s5_ransomware": datetime(2026, 7, 13,  2,  0, 0),
}

# Kibana dashboard default time window per scenario (UTC ISO, inclusive).
WINDOW = {
    "s1_rat":        ("2026-06-15T00:00:00.000Z", "2026-06-19T23:59:59.999Z"),
    "s2_ato":        ("2026-06-22T00:00:00.000Z", "2026-06-25T23:59:59.999Z"),
    "s3_insider":    ("2026-06-29T00:00:00.000Z", "2026-07-02T23:59:59.999Z"),
    "s4_sqli":       ("2026-07-06T00:00:00.000Z", "2026-07-09T23:59:59.999Z"),
    "s5_ransomware": ("2026-07-13T00:00:00.000Z", "2026-07-18T23:59:59.999Z"),
}

# ── Attacker infrastructure (external) ────────────────────────────────────────
EXT = {
    "s1_rat":        {"dropper": "45.142.212.77",  "c2": "185.220.101.72", "c2b": "194.165.16.88",  "exfil": "91.215.153.44"},
    "s2_ato":        {"phish":   "45.147.230.15",  "c2": "185.220.100.34", "proxy": "193.239.85.12", "exfil": "91.219.236.19"},
    "s3_insider":    {"cloud":   "52.216.94.10",   "cloudsync": "162.125.7.20", "exfil": "45.9.148.33"},
    "s4_sqli":       {"attacker": "80.94.92.140",  "webshell_c2": "185.220.102.8", "exfil": "91.215.85.66"},
    "s5_ransomware": {"vpn_bruteforce": "45.135.232.71", "c2": "185.220.101.99", "toolhost": "5.188.206.18", "exfil": "91.215.153.77"},
}

SENSORS = {
    "s1_rat":        ("HBCU-NIDS-01", "HBCU-NIDS-02"),
    "s2_ato":        ("MFCU-EDGE-01", "MFCU-EDGE-02"),
    "s3_insider":    ("MFCU-CORE-01", "MFCU-CORE-02"),
    "s4_sqli":       ("MFCU-DMZ-01",  "MFCU-DMZ-02"),
    "s5_ransomware": ("MFCU-CORE-01", "MFCU-DC-01"),
}

# ── Internal hosts per scenario (names -> IP) ─────────────────────────────────
NET = {
    "s1_rat": {
        "user_ws":     "10.20.1.88",   # patient zero
        "finance_ws":  "10.20.1.92",
        "finance_ws2": "10.20.1.95",
        "exec_ws":     "10.20.1.200",  # CFO
        "dc":          "10.20.0.10",
        "payment_srv": "10.20.5.20",
        "db_srv":      "10.20.5.30",
    },
    "s2_ato": {
        "user_ws":     "10.30.1.40",
        "helpdesk_ws": "10.30.1.55",
        "auth_gw":     "10.30.4.10",   # authentication gateway
        "ibank_app":   "10.30.4.20",   # online-banking app server
        "cust_db":     "10.30.5.30",   # customer/account DB
    },
    "s3_insider": {
        "dba_ws":      "10.40.1.60",   # database administrator workstation
        "app_ws":      "10.40.1.61",
        "cust_db":     "10.40.5.30",   # full customer records DB
        "backup_srv":  "10.40.5.40",   # backup repository (contains everything)
        "jump_host":   "10.40.2.10",
    },
    "s4_sqli": {
        "web_app":     "10.50.2.20",   # public-facing financial web app (DMZ)
        "web_db":      "10.50.5.25",   # cardholder DB (PCI CDE)
        "app_mid":     "10.50.2.30",   # middleware / app tier
        "log_srv":     "10.50.3.15",
    },
    "s5_ransomware": {
        "vpn_gw":      "10.60.0.5",    # exposed remote service
        "file_srv":    "10.60.5.50",   # file server (mixed PII)
        "hr_db":       "10.60.5.60",   # HR database
        "cust_db":     "10.60.5.30",   # customer database
        "dc":          "10.60.0.10",
        "backup_srv":  "10.60.5.40",
        "user_ws":     "10.60.1.70",
    },
}

# ── Asset inventory (criticality + PII classification) ────────────────────────
# (scenario, host_key, ip, criticality, asset_type, data_classification, pii_categories)
def _a(ip, crit, atype, dclass, cats):
    return {"ip": ip, "asset_criticality": crit, "asset_type": atype,
            "data_classification": dclass, "pii_categories": cats}

ASSETS = [
    # s1_rat
    _a(NET["s1_rat"]["user_ws"],     15, "user_workstation",     "none",  "none"),
    _a(NET["s1_rat"]["finance_ws"],  30, "finance_workstation",  "tier4", "internal_docs"),
    _a(NET["s1_rat"]["finance_ws2"], 30, "finance_workstation",  "tier4", "internal_docs"),
    _a(NET["s1_rat"]["exec_ws"],     40, "exec_workstation",     "tier3", "exec_email"),
    _a(NET["s1_rat"]["dc"],          45, "domain_controller",    "tier2", "account_credentials"),
    _a(NET["s1_rat"]["payment_srv"], 50, "payment_server",       "tier1", "payment_card_full_track,bank_account"),
    _a(NET["s1_rat"]["db_srv"],      48, "database_server",      "tier1", "ssn,account_number,financial_records"),
    # s2_ato
    _a(NET["s2_ato"]["user_ws"],     15, "user_workstation",     "none",  "none"),
    _a(NET["s2_ato"]["helpdesk_ws"], 20, "user_workstation",     "tier4", "internal_docs"),
    _a(NET["s2_ato"]["auth_gw"],     45, "auth_gateway",         "tier1", "banking_credentials,session_token"),
    _a(NET["s2_ato"]["ibank_app"],   44, "app_server",           "tier1", "banking_credentials,account_number"),
    _a(NET["s2_ato"]["cust_db"],     48, "database_server",      "tier1", "ssn,account_number,bank_account"),
    # s3_insider
    _a(NET["s3_insider"]["dba_ws"],     32, "admin_workstation", "none",  "none"),
    _a(NET["s3_insider"]["app_ws"],     22, "user_workstation",  "none",  "none"),
    _a(NET["s3_insider"]["cust_db"],    50, "database_server",   "tier1", "ssn,account_number,dob,financial_records"),
    _a(NET["s3_insider"]["backup_srv"], 42, "backup_server",     "tier1", "mixed_pii,ssn,account_number"),
    _a(NET["s3_insider"]["jump_host"],  35, "jump_host",         "tier4", "internal_docs"),
    # s4_sqli
    _a(NET["s4_sqli"]["web_app"],    44, "web_server",           "tier3", "email,phone"),
    _a(NET["s4_sqli"]["web_db"],     50, "database_server",      "tier1", "payment_card_full_track,credit_card"),
    _a(NET["s4_sqli"]["app_mid"],    36, "app_server",           "tier4", "internal_docs"),
    _a(NET["s4_sqli"]["log_srv"],    25, "log_server",           "none",  "none"),
    # s5_ransomware
    _a(NET["s5_ransomware"]["vpn_gw"],     40, "vpn_gateway",     "tier2", "account_credentials"),
    _a(NET["s5_ransomware"]["file_srv"],   43, "file_server",     "tier2", "mixed_pii,name_dob"),
    _a(NET["s5_ransomware"]["hr_db"],      46, "database_server", "tier1", "ssn,dob,financial_records"),
    _a(NET["s5_ransomware"]["cust_db"],    48, "database_server", "tier1", "ssn,account_number,bank_account"),
    _a(NET["s5_ransomware"]["dc"],         45, "domain_controller","tier2", "account_credentials"),
    _a(NET["s5_ransomware"]["backup_srv"], 42, "backup_server",   "tier1", "mixed_pii"),
    _a(NET["s5_ransomware"]["user_ws"],    15, "user_workstation","none",  "none"),
]

SCENARIOS = ["s1_rat", "s2_ato", "s3_insider", "s4_sqli", "s5_ransomware"]

SCENARIO_TITLE = {
    "s1_rat":        "Remote Access Trojan with PII Exfiltration",
    "s2_ato":        "Credential Harvesting & Online-Banking Account Takeover",
    "s3_insider":    "Privileged-Insider Bulk Data Export (DBA)",
    "s4_sqli":       "SQL Injection to Cardholder-Data Exfiltration",
    "s5_ransomware": "Ransomware-as-a-Service Double-Extortion",
}
