#!/usr/bin/env python3
"""
MITRE ATT&CK technique reference for the five Praxis attack scenarios.

`attack_complexity` in the enriched scoring model is derived from the number of
DISTINCT techniques observed across a correlation window (a multi-stage campaign
scores higher than an isolated event). The generators tag each malicious event
with `metadata.mitre_technique`; `events.annotate_technique_counts()` then counts
distinct techniques per correlation window and writes `metadata.technique_count`,
which the ingest pipeline scales to 5-20.
"""

# technique_id -> (name, tactic)
TECHNIQUES = {
    # Initial access
    "T1566.001": ("Spearphishing Attachment", "initial-access"),
    "T1566.002": ("Spearphishing Link", "initial-access"),
    "T1190":     ("Exploit Public-Facing Application", "initial-access"),
    "T1133":     ("External Remote Services", "initial-access"),
    "T1078":     ("Valid Accounts", "initial-access"),
    "T1078.002": ("Valid Accounts: Domain Accounts", "initial-access"),
    # Execution / persistence
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1505":     ("Server Software Component (Web Shell)", "persistence"),
    "T1059.001": ("PowerShell", "execution"),
    # Discovery / collection
    "T1083":     ("File and Directory Discovery", "discovery"),
    "T1005":     ("Data from Local System", "collection"),
    "T1530":     ("Data from Cloud/Information Repositories", "collection"),
    "T1560":     ("Archive Collected Data", "collection"),
    "T1185":     ("Browser Session Hijacking", "collection"),
    # Credential access
    "T1539":     ("Steal Web Session Cookie", "credential-access"),
    "T1003":     ("OS Credential Dumping", "credential-access"),
    # Lateral movement
    "T1021.001": ("Remote Services: RDP", "lateral-movement"),
    "T1570":     ("Lateral Tool Transfer", "lateral-movement"),
    "T1550.002": ("Pass the Hash", "lateral-movement"),
    # Command and control
    "T1071.001": ("Application Layer Protocol: Web", "command-and-control"),
    "T1572":     ("Protocol Tunneling", "command-and-control"),
    # Exfiltration
    "T1074.001": ("Local Data Staging", "exfiltration"),
    "T1041":     ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1048":     ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1567":     ("Exfiltration Over Web Service", "exfiltration"),
    "T1537":     ("Transfer Data to Cloud Account", "exfiltration"),
    "TA0010":    ("Exfiltration (tactic)", "exfiltration"),
    # Impact
    "T1486":     ("Data Encrypted for Impact", "impact"),
}


def tname(tid):
    return TECHNIQUES.get(tid, (tid, "unknown"))[0]


def ttactic(tid):
    return TECHNIQUES.get(tid, (tid, "unknown"))[1]
