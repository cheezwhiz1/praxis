#!/usr/bin/env python3
"""
Scenario 3 — Privileged-Insider Bulk Data Export by a DBA (v6 §3.6).
Chain: T1078.002 (legitimate domain creds) -> T1530 (bulk collection) -> T1048/T1567
(exfil via cloud sync). The hardest case for standard detection: the actor uses
authorized credentials within role scope, so signatures look benign — the enriched
model separates authorized access from unauthorized bulk export via correlation
volume + PII sensitivity of the customer DB (Tier-1).
"""
import os
import sys
from datetime import timedelta

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "lib"))
from events import event, scatter_benign, annotate_technique_counts, write_events  # noqa: E402
from topology import BASE, NET, EXT, SENSORS  # noqa: E402

K = "s3_insider"
base, net, ext = BASE[K], NET[K], EXT[K]
S1, S2 = SENSORS[K]
W1, W2 = "corr-s3-collect", "corr-s3-exfil"


def mal(h, src, dst, port, tname, sev, risk, cat, tech, phase, cid,
        flow=None, pii=None, sb=0, db=0, transport="tcp", **kw):
    return event(ts=base + timedelta(hours=h), src_ip=src, dst_ip=dst, dst_port=port,
                 transport=transport, threat_name=tname, severity=sev, norm_risk_level=risk,
                 former_category=cat, flowbits=flow or [], sensor=S1, rule_category="ids",
                 rule_name=tname, attack_phase=phase, correlation_id=cid, mitre_technique=tech,
                 src_bytes=sb, dst_bytes=db, is_malicious=True, scenario=K, pii_type=pii, **kw)


M = [
    # Phase 1 — legitimate-credential abuse (looks entirely normal to signatures)
    mal(0.0, net["dba_ws"], net["cust_db"], 1433, "ET INFO DBA Interactive DB Logon (valid creds)",
        4, "Low", "AUTH", "T1078.002", "initial_access", W1, [], auth_result="success", sb=2200, db=6400),
    mal(0.5, net["dba_ws"], net["jump_host"], 22, "ET INFO Admin SSH to Jump Host (valid creds)",
        4, "Low", "AUTH", "T1078.002", "initial_access", W1, [], auth_result="success", sb=1800, db=4200),
    # Phase 2 — QUIET precursors: staged bulk collection from the Tier-1 customer DB
    mal(1.0, net["dba_ws"], net["cust_db"], 1433, "ET INFO Sequential Full-Table Record Scan",
        4, "Low", "INSIDER", "T1530", "data_discovery", W1, [], pii="ssn", sb=4200, db=520000, db_rows=140000),
    mal(2.0, net["dba_ws"], net["cust_db"], 1433, "ET INFO Off-Hours Customer Table Bulk SELECT",
        3, "Medium", "INSIDER", "T1530", "data_discovery", W1, [], pii="account_number", sb=6200, db=2400000, db_rows=180000),
    mal(3.0, net["dba_ws"], net["backup_srv"], 445, "ET INFO Ad-hoc Copy of Nightly Backup Set",
        3, "Medium", "INSIDER", "T1530", "collection", W1, [], pii="mixed_pii", sb=5200, db=8800000),
    # Phase 3 — archive + stage locally
    mal(4.0, net["dba_ws"], net["dba_ws"], 0, "ET INFO Local Archive of Exported Records (7z)",
        4, "Low", "INSIDER", "T1560", "collection", W1, [], pii="mixed_pii", sb=42000000, db=0),
    # Phase 4 — exfil via external cloud-sync service (loud volume -> both conditions see it)
    mal(20.0, net["dba_ws"], ext["cloudsync"], 443, "ET EXFIL Customer Records to Cloud Sync Service",
        1, "Critical", "EXFIL", "T1567", "exfiltration", W2, ["ET.Evil"], pii="ssn_dob_full_identity", sb=48000000, db=4200),
    mal(21.0, net["dba_ws"], ext["cloud"], 443, "ET EXFIL Secondary Bucket Upload (account data)",
        1, "Critical", "EXFIL", "T1048", "exfiltration", W2, ["ET.Evil"], pii="account_number", sb=26000000, db=3600),
    mal(30.0, net["dba_ws"], ext["exfil"], 443, "ET EXFIL Financial Records Alt-Protocol Egress",
        1, "Critical", "EXFIL", "T1048", "exfiltration", W2, ["ET.Evil"], pii="financial_records", sb=18000000, db=2800),
]

events = M + scatter_benign(K, base, net, 130, day_span_hours=48)
annotate_technique_counts(events)

if __name__ == "__main__":
    write_events(os.path.dirname(os.path.abspath(__file__)), events)
