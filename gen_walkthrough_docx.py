#!/usr/bin/env python3
"""
Generate RAT Attack Demo Walkthrough as a .docx file.
Run: python3 gen_walkthrough_docx.py
Output: RAT_Attack_Demo_Walkthrough.docx
"""
from docx import Document
from docx.shared import Pt, RGBColor, Inches, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml.ns import qn
from docx.oxml import OxmlElement
import copy

doc = Document()

# ── Page margins ──────────────────────────────────────────────────────────────
section = doc.sections[0]
section.top_margin    = Inches(1)
section.bottom_margin = Inches(1)
section.left_margin   = Inches(1.1)
section.right_margin  = Inches(1.1)

# ── Color palette ─────────────────────────────────────────────────────────────
DARK_BLUE   = RGBColor(0x1F, 0x39, 0x64)   # headings
MED_BLUE    = RGBColor(0x2E, 0x74, 0xB5)   # sub-headings / accents
ORANGE      = RGBColor(0xC5, 0x50, 0x1C)   # phase labels
GREEN       = RGBColor(0x37, 0x86, 0x42)   # success/good
RED_DARK    = RGBColor(0x9B, 0x1B, 0x1B)   # risk/critical
LIGHT_GREY  = RGBColor(0xF2, 0xF2, 0xF2)   # table header fill
MID_GREY    = RGBColor(0xD9, 0xD9, 0xD9)
TEXT_BLACK  = RGBColor(0x1A, 0x1A, 0x1A)

# ── Style helpers ─────────────────────────────────────────────────────────────
def set_run_color(run, color): run.font.color.rgb = color
def set_cell_bg(cell, hex_color):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    shd  = OxmlElement('w:shd')
    shd.set(qn('w:val'),   'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'),  hex_color)
    tcPr.append(shd)

def set_col_width(cell, width_inches):
    tc   = cell._tc
    tcPr = tc.get_or_add_tcPr()
    tcW  = OxmlElement('w:tcW')
    tcW.set(qn('w:w'),    str(int(width_inches * 1440)))
    tcW.set(qn('w:type'), 'dxa')
    tcPr.append(tcW)

def h1(text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(18)
    p.paragraph_format.space_after  = Pt(6)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold      = True
    run.font.size = Pt(18)
    set_run_color(run, DARK_BLUE)
    # bottom border
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement('w:pBdr')
    bottom = OxmlElement('w:bottom')
    bottom.set(qn('w:val'),  'single')
    bottom.set(qn('w:sz'),   '6')
    bottom.set(qn('w:space'),'1')
    bottom.set(qn('w:color'), '1F3964')
    pBdr.append(bottom)
    pPr.append(pBdr)
    return p

def h2(text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(12)
    p.paragraph_format.space_after  = Pt(4)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold      = True
    run.font.size = Pt(13)
    set_run_color(run, MED_BLUE)
    return p

def h3(text):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(8)
    p.paragraph_format.space_after  = Pt(3)
    p.paragraph_format.keep_with_next = True
    run = p.add_run(text)
    run.bold      = True
    run.font.size = Pt(11)
    set_run_color(run, DARK_BLUE)
    return p

def body(text, bold_spans=None):
    """Add a body paragraph. bold_spans = list of substrings to bold."""
    p = doc.add_paragraph()
    p.paragraph_format.space_after = Pt(4)
    if bold_spans:
        remaining = text
        for span in bold_spans:
            idx = remaining.find(span)
            if idx == -1:
                continue
            if idx > 0:
                r = p.add_run(remaining[:idx])
                r.font.size = Pt(10.5)
                set_run_color(r, TEXT_BLACK)
            r2 = p.add_run(span)
            r2.bold = True
            r2.font.size = Pt(10.5)
            set_run_color(r2, TEXT_BLACK)
            remaining = remaining[idx + len(span):]
        if remaining:
            r = p.add_run(remaining)
            r.font.size = Pt(10.5)
            set_run_color(r, TEXT_BLACK)
    else:
        run = p.add_run(text)
        run.font.size = Pt(10.5)
        set_run_color(run, TEXT_BLACK)
    return p

def code(text):
    p = doc.add_paragraph()
    p.paragraph_format.left_indent  = Inches(0.3)
    p.paragraph_format.space_after  = Pt(2)
    p.paragraph_format.space_before = Pt(2)
    run = p.add_run(text)
    run.font.name = 'Courier New'
    run.font.size = Pt(9)
    set_run_color(run, RGBColor(0x17, 0x3A, 0x1F))
    pPr = p._p.get_or_add_pPr()
    pBdr = OxmlElement('w:pBdr')
    for side in ('top','left','bottom','right'):
        el = OxmlElement(f'w:{side}')
        el.set(qn('w:val'),   'single')
        el.set(qn('w:sz'),    '4')
        el.set(qn('w:space'), '4')
        el.set(qn('w:color'), 'AAAAAA')
        pBdr.append(el)
    pPr.append(pBdr)
    # background shade
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'),   'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'),  'F6F8FA')
    pPr.append(shd)
    return p

def bullet(text, level=0, color=None):
    p = doc.add_paragraph(style='List Bullet')
    p.paragraph_format.left_indent   = Inches(0.3 + level * 0.25)
    p.paragraph_format.space_after   = Pt(2)
    run = p.add_run(text)
    run.font.size = Pt(10.5)
    set_run_color(run, color if color else TEXT_BLACK)
    return p

def make_table(headers, rows, col_widths=None, header_color='1F3964'):
    cols = len(headers)
    t    = doc.add_table(rows=1 + len(rows), cols=cols)
    t.style = 'Table Grid'
    t.alignment = WD_TABLE_ALIGNMENT.LEFT

    # header row
    for i, h in enumerate(headers):
        cell = t.cell(0, i)
        set_cell_bg(cell, header_color)
        if col_widths:
            set_col_width(cell, col_widths[i])
        p = cell.paragraphs[0]
        run = p.add_run(h)
        run.bold = True
        run.font.size = Pt(9.5)
        run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
        cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

    # data rows
    for ri, row in enumerate(rows):
        bg = 'FFFFFF' if ri % 2 == 0 else 'EEF3FB'
        for ci, val in enumerate(row):
            cell = t.cell(ri + 1, ci)
            set_cell_bg(cell, bg)
            if col_widths:
                set_col_width(cell, col_widths[ci])
            p = cell.paragraphs[0]
            if isinstance(val, tuple):
                text, bold = val
                run = p.add_run(text)
                run.bold = bold
            else:
                run = p.add_run(str(val))
            run.font.size = Pt(9.5)
            run.font.color.rgb = TEXT_BLACK
            cell.vertical_alignment = WD_ALIGN_VERTICAL.CENTER

    doc.add_paragraph()  # spacing after table
    return t

def spacer(n=1):
    for _ in range(n):
        p = doc.add_paragraph()
        p.paragraph_format.space_after = Pt(2)


# ══════════════════════════════════════════════════════════════════════════════
# TITLE PAGE
# ══════════════════════════════════════════════════════════════════════════════
spacer(2)
title_p = doc.add_paragraph()
title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
tr = title_p.add_run("RAT Attack Demo Walkthrough")
tr.bold = True
tr.font.size = Pt(26)
set_run_color(tr, DARK_BLUE)

sub_p = doc.add_paragraph()
sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
sr = sub_p.add_run("Operation MediBank — Healthcare Credit Union APT Simulation")
sr.font.size = Pt(13)
set_run_color(sr, MED_BLUE)

sub_p2 = doc.add_paragraph()
sub_p2.alignment = WD_ALIGN_PARAGRAPH.CENTER
sr2 = sub_p2.add_run("Elasticsearch · Logstash · Kibana 9.3.0  |  4-Component Additive Risk Scoring")
sr2.font.size = Pt(11)
set_run_color(sr2, RGBColor(0x60, 0x60, 0x60))
spacer(2)

doc.add_page_break()

# ══════════════════════════════════════════════════════════════════════════════
# 1. OVERVIEW
# ══════════════════════════════════════════════════════════════════════════════
h1("1. Overview")
body(
    "This demo presents a simulated APT campaign — 'Operation MediBank' — a financial Remote Access Trojan (RAT) "
    "targeting a healthcare credit union. The attack plays out over 5 days across 7 distinct phases, generating "
    "31 IDS alerts that are each risk-scored in real time by Elasticsearch at index time. The demo uses two "
    "parallel indexes to contrast two scoring approaches:",
    bold_spans=["Operation MediBank", "31 IDS alerts", "5 days", "7 distinct phases"]
)
bullet("test_rat — 36 events, 6 phases. Risk score computed as a runtime field (Painless script evaluated at query time, never stored). Single-dimension scoring.", color=TEXT_BLACK)
bullet("rat_scored — 31 events, 7 phases. 4-component additive scoring model computed at index time by an ES ingest pipeline. Scores stored in score.* integer fields. Context-enriched via asset inventory lookup. This is the primary demo index.", color=TEXT_BLACK)

body("The primary demo focus is rat_scored.", bold_spans=["rat_scored"])


# ══════════════════════════════════════════════════════════════════════════════
# 2. FILE MAP
# ══════════════════════════════════════════════════════════════════════════════
h1("2. File Map")

h2("2.1  Deployment Files")
make_table(
    ["File", "Description"],
    [
        ("elastic.sh",
         "Master setup script. Pulls Docker images, generates SSL certs via elasticsearch-certutil, writes the three "
         "compose files to ~/elastic/, brings up the stack, creates the forensics index, and injects initial test data. Run once."),
        ("elastic/elastic.yml",
         "Docker Compose for Elasticsearch 9.3.0. Single-node cluster, xpack.security enabled, SSL/TLS on HTTP and transport. "
         "Binds 0.0.0.0, publishes port 9200."),
        ("elastic/kibana.yml",
         "Docker Compose for Kibana 9.3.0. Connects to Elasticsearch over HTTPS using the kibana_system service account. "
         "Self-signed SSL cert. Publishes port 5601."),
        ("elastic/logstash.yml",
         "Docker Compose for Logstash 9.3.0. Mounts the full pipeline from ~/.persistent/logstash/pipeline/ and the "
         "pipelines.yml router. Exposes 12 input ports covering Checkpoint, PaloAlto, Suricata, Windows, Wazuh, and more."),
    ],
    col_widths=[1.8, 4.8]
)

h2("2.2  Logstash Pipeline Files")
make_table(
    ["File", "Description"],
    [
        (".persistent/logstash/pipeline/inputs/inputs.conf",
         "Show this first. Defines all 12 input listeners (TCP/UDP). Routes events by type tag — PALO → paloalto pipeline, "
         "IDS → suricata pipeline, WINDOWS → ms-winlogbeat pipeline, etc. Each input listens on a dedicated port."),
        (".persistent/logstash/pipeline/outputs/output.conf",
         "Terminal output stage. Events with error[type] set (parsing/validation failures) go to the failed-logs index. "
         "All valid events route to the forensics index. Uses the Elasticsearch output plugin with SSL truststore."),
        (".persistent/logstash/pipeline/suricata/",
         "Suricata-specific filter chain. Parses raw Suricata JSON, maps fields to ECS format, computes norm_risk_level, "
         "sets former_category, and validates required fields before handing off to the output stage."),
    ],
    col_widths=[2.8, 3.8]
)

h2("2.3  rat_scored Index Files  (Primary Demo)")
make_table(
    ["File", "Description"],
    [
        ("indexes/rat_scored/gen_events.py",
         "The attack scenario generator. Defines the network topology at the top (patient zero, finance workstations, CFO machine, "
         "payment server, DB server, C2 IPs, exfil server, 4-hour correlation window IDs). Generates 31 ECS events across 7 phases. "
         "Note: score.* fields are intentionally absent — they are computed at index time by the ingest pipeline."),
        ("indexes/rat_scored/events.ndjson",
         "Pre-generated bulk payload ready for _bulk POST. 62 lines (1 action + 1 document per event). Re-generate by running gen_events.py."),
        ("indexes/rat_scored/asset_inventory.ndjson",
         "7 internal hosts: IP → asset_criticality (integer 15–50) + asset_type (string). Used by the ES enrich policy. "
         "This is what makes scoring context-aware — the pipeline looks up both source and destination IP and uses the higher-criticality endpoint."),
        ("indexes/rat_scored/setup.sh",
         "The most important file for explaining the scoring architecture. Creates the asset_inventory index, seeds it, creates and "
         "executes the asset-criticality-policy enrich policy, creates the rat-scoring-pipeline ingest pipeline (7 Painless processors), "
         "creates the rat_scored index with explicit mappings, bulk-ingests events through the pipeline, then creates the Kibana data view "
         "and imports the dashboard. Safe to re-run."),
        ("indexes/rat_scored/gen_dashboard.py",
         "Builds the 9-panel Kibana dashboard programmatically using a Python DSL for Lens objects. Contains the panel layout, "
         "gauge configuration, color banding logic (green/yellow/red), and legend table definitions. Re-generate with python3 gen_dashboard.py."),
        ("indexes/rat_scored/dashboard.ndjson",
         "Pre-generated Kibana saved objects: 5 Lens arc gauges + 4 Lens data tables + 1 dashboard container. "
         "Ready to import via saved_objects/_import API."),
    ],
    col_widths=[2.3, 4.3]
)

h2("2.4  test_rat Index Files  (Comparison)")
make_table(
    ["File", "Description"],
    [
        ("indexes/test_rat/gen_events.py",
         "36 events, 6 attack phases (adds a persistence phase). Generic financial bank topology. Uses credential_harvest as a phase name "
         "instead of data_discovery. No asset inventory lookup, no PII exposure tiers."),
        ("indexes/test_rat/setup.sh",
         "Creates the index with a risk_score runtime field — a Painless script embedded in the index mapping, evaluated at query time. "
         "Use this to contrast with rat_scored's index-time pipeline approach: same raw data, no stored scores, less differentiated."),
    ],
    col_widths=[2.3, 4.3]
)

h2("2.5  forensics Index Files  (Real Suricata Data)")
make_table(
    ["File", "Description"],
    [
        ("indexes/forensics/events.ndjson",
         "5 real Suricata IDS alerts in ECS format, as they come out of the Logstash pipeline. Dshield and compromised-host alerts. "
         "Use as the 'this is what live production data looks like' reference."),
        ("indexes/forensics/setup.sh",
         "Creates the index with a runtime risk_score field. Same pattern as test_rat. Good for the 'live data' slide."),
    ],
    col_widths=[2.3, 4.3]
)


# ══════════════════════════════════════════════════════════════════════════════
# 3. ATTACK TIMELINE
# ══════════════════════════════════════════════════════════════════════════════
h1("3. The Attack Timeline")
body(
    "All timestamps are relative to 2026-06-15 07:30 (BASE in gen_events.py). "
    "Walk this verbally while the audience views the Kibana dashboard.",
    bold_spans=["2026-06-15 07:30"]
)

make_table(
    ["Phase", "Time Window", "Events", "What is Happening"],
    [
        ("1. Initial Access",       "T+0 to T+12 min",  "2",
         "Patient zero (10.20.1.88) downloads the MediBank dropper from 45.142.212.77 over HTTP. "
         "Second event = 2nd-stage DLL fetch (~600 KB payload). Severity: Critical."),
        ("2. C2 Establishment",     "T+20 min to T+2h",  "4",
         "Patient zero beacons to 185.220.101.72:443 (TOR exit). Downloads in-memory payload (2 MB). "
         "Establishes 5-minute heartbeat. Registers with BotNet C2 (ET.BotCC). Severity: Critical."),
        ("3. Reconnaissance",       "T+4h to T+6h",      "4",
         "LDAP sweep of Active Directory (10.20.0.10:389). SMB sweep of server segment (:445). "
         "Probes payment server 10.20.5.20:8443. RDP scan of workstation subnet (:3389)."),
        ("4. Lateral Movement",     "T+12h to T+20h",    "6",
         "Pass-the-Hash to finance workstation 10.20.1.92. RDP pivot. New beacon from finance box. "
         "SQL Server connection to DB server 10.20.5.30:1433. RDP to CFO 10.20.1.200. CFO machine beacons to C2."),
        ("5. Privilege Escalation", "T+36h to T+40h",    "3",
         "Kerberoasting SPN flood to DC port 88. Pass-the-Ticket to DC port 445. "
         "LDAPS admin query from CFO machine using stolen elevated credentials."),
        ("6. Data Discovery",       "T+48h to T+60h",    "5",
         "Finance box bulk-queries patient/financial DB (10 MB response). PCI-CDE payment API access (20 MB). "
         "Keylogger uploads banking credentials. FormGrabber captures full PAN. SSN/PII harvest module fires."),
        ("7. Exfiltration",         "T+72h to T+96h",    "7",
         "Medical/financial PII bulk POST to 91.215.153.44 (20 MB). Account numbers (10 MB). Executive records (40 MB). "
         "Payment server itself exfils full-track card data (100 MB). Secondary C2 from payment server. "
         "Round 2 credit card staging (30 MB). DNS tunneling covert channel."),
    ],
    col_widths=[1.5, 1.3, 0.65, 3.2]
)


# ══════════════════════════════════════════════════════════════════════════════
# 4. SCORING ARCHITECTURE
# ══════════════════════════════════════════════════════════════════════════════
h1("4. Scoring Architecture")

h2("4.1  Two Models — Why?")
body("Open this contrast early in the demo before showing the dashboard.")
make_table(
    ["Approach", "Index", "How", "Trade-off"],
    [
        ("Runtime field",    "test_rat / forensics",
         "Painless script embedded in the index mapping; computed on every query",
         "Free to change without reindex; slower at query time; single-dimension; scores not stored"),
        ("Ingest pipeline",  "rat_scored",
         "7 Painless processors run once at index time; scores stored in score.* integer fields",
         "Faster at query time; contextually enriched via asset lookup; 4 axes to tune independently"),
    ],
    col_widths=[1.2, 1.5, 2.3, 1.65]
)

h2("4.2  Component ①  —  Base Alert Severity  (0–45)")
body(
    "Source: three ECS fields already present on the raw IDS event. "
    "Raw score capped at 60, then scaled to 0–45 with Math.round(raw / 60.0 * 45).",
    bold_spans=["Math.round(raw / 60.0 * 45)"]
)
make_table(
    ["Field", "Value", "Points"],
    [
        ("event.norm_risk_level", "Critical",          "+20"),
        ("event.norm_risk_level", "High",              "+12"),
        ("event.norm_risk_level", "Medium",            "+6"),
        ("event.norm_risk_level", "Low",               "+2"),
        ("metadata.former_category", "EXFIL",          "+22"),
        ("metadata.former_category", "TROJAN / MALWARE", "+20"),
        ("metadata.former_category", "EXPLOIT",        "+18"),
        ("metadata.former_category", "SCAN",           "+8"),
        ("metadata.former_category", "POLICY",         "+5"),
        ("metadata.flowbits", "ET.Evil / ET.RAT",      "+5 each"),
        ("metadata.flowbits", "ET.Exploit / ET.BotCC", "+4 each"),
        ("metadata.flowbits", "ET.Malware / ET.ThreatIntel / ET.DNSTunnel", "+3 each"),
    ],
    col_widths=[2.2, 2.4, 1.0]
)

h2("4.3  Component ②  —  Asset Criticality  (0–25)")
body(
    "An ES Enrich processor (asset-criticality-policy) looks up source.ip and destination.ip against the asset_inventory index. "
    "A Painless script takes max(src_criticality, dst_criticality) and divides by 2 "
    "(raw values are 0–50, halved = 0–25). This means a probe targeting the payment server scores as high as one originating from it.",
    bold_spans=["max(src_criticality, dst_criticality)", "targeting the payment server"]
)
make_table(
    ["IP", "Asset Type", "Raw Criticality", "Score Contribution"],
    [
        ("10.20.5.20",  "payment_server",      "50", "25"),
        ("10.20.5.30",  "database_server",     "45", "22"),
        ("10.20.1.200", "exec_workstation",    "45", "22"),
        ("10.20.0.10",  "domain_controller",   "40", "20"),
        ("10.20.1.92",  "finance_workstation", "30", "15"),
        ("10.20.1.95",  "finance_workstation", "30", "15"),
        ("10.20.1.88",  "user_workstation (patient zero)", "15", "7"),
    ],
    col_widths=[1.4, 1.9, 1.4, 1.8]
)

h2("4.4  Component ③  —  PII Exposure Tier  (2–20)")
body(
    "Two inputs: an explicit metadata.pii_type field on the event, and an inferred type resolved from the enriched asset_type. "
    "Floor is 2 (always present). Capped at 20 (tier + volume bonus).",
    bold_spans=["Floor is 2", "Capped at 20"]
)
make_table(
    ["PII Type / Asset Type", "Source", "Base Tier"],
    [
        ("payment_card_full_track, credit_card, banking_credentials, ssn_dob_full_identity, account_number, financial_records, payment_card",
         "Explicit metadata.pii_type", "15"),
        ("medical_financial_records, mixed_pii",       "Explicit metadata.pii_type", "10"),
        ("payment_server",                             "Inferred from asset_type",   "12"),
        ("database_server",                            "Inferred from asset_type",   "9"),
        ("domain_controller",                          "Inferred from asset_type",   "8"),
        ("finance_workstation",                        "Inferred from asset_type",   "6"),
        ("exec_workstation",                           "Inferred from asset_type",   "4"),
        ("(no match)",                                 "Floor",                      "2"),
    ],
    col_widths=[3.2, 1.8, 0.9]
)
body(
    "Volume bonus (0–5, only applied when base tier > 0): derived from max(source.bytes, destination.bytes).",
    bold_spans=["Volume bonus"]
)
make_table(
    ["Data Volume", "Bonus"],
    [
        ("≥ 100 MB", "+5  ← 100 MB full-track card exfil event maxes this out"),
        ("≥ 10 MB",  "+4"),
        ("≥ 1 MB",   "+3"),
        ("≥ 100 KB", "+2"),
        ("≥ 1 KB",   "+1"),
    ],
    col_widths=[1.5, 4.0]
)

h2("4.5  Component ④  —  Attack Complexity  (4–10)")
body("Phase proxy + technique category bonus from former_category. Result uncapped in the Painless script but practically bounded ~10 by the input ranges.")
make_table(
    ["Attack Phase (custom.str1)", "Phase Points", "Category Bonus (former_category)"],
    [
        ("initial_access",        "2", "EXPLOIT / EXFIL  +3"),
        ("c2_establishment",      "3", "TROJAN / MALWARE  +2"),
        ("reconnaissance",        "5", "SCAN  +1"),
        ("lateral_movement",      "5", ""),
        ("privilege_escalation",  "6", ""),
        ("data_discovery",        "7", ""),
        ("exfiltration",          "7", ""),
    ],
    col_widths=[2.5, 1.3, 2.8]
)

h2("4.6  Composite Score")
body(
    "score.composite  =  ① base_alert_severity  +  ② asset_criticality  +  ③ pii_exposure_tier  +  ④ attack_complexity",
    bold_spans=["score.composite"]
)
body("Computed by a final Painless script in the ingest pipeline and stored as an integer field. Range: 8–100.")
body("Color bands used in all Kibana arc gauges:")
make_table(
    ["Band", "Range", "Meaning"],
    [
        ("Green",  "0 – 40",   "Low risk"),
        ("Yellow", "40 – 68",  "Elevated risk"),
        ("Red",    "68 – 100", "Critical risk"),
    ],
    col_widths=[1.0, 1.0, 4.5]
)


# ══════════════════════════════════════════════════════════════════════════════
# 5. KIBANA DASHBOARD WALKTHROUGH
# ══════════════════════════════════════════════════════════════════════════════
h1("5. Kibana Dashboard Walkthrough")
body("Navigate to:")
code("https://192.168.86.55:5601/app/dashboards#/view/rat-scored-dashboard")
body("Set the time range to:  2026-06-15 00:00  →  2026-06-19 23:59")

h2("5.1  Row 1 — Composite Risk Score  (full-width arc gauge)")
body(
    "Displays avg(score.composite) across all 31 events on a 0–100 arc. "
    "The needle will sit deep in the red zone. This is the headline KPI — "
    "'The average risk score across this 5-day campaign is in the critical range.'",
    bold_spans=["avg(score.composite)", "headline KPI"]
)

h2("5.2  Row 2 — Additive Step-Up Gauges  (4 panels side by side)")
body("Walk left to right. Each gauge adds one component to the previous — the needle visually steps up.")
make_table(
    ["Panel", "Formula", "Narrative"],
    [
        ("① Base Alert Severity",
         "avg(score.base_alert_severity)",
         "Purely based on the IDS signature and risk level — no context about what was hit"),
        ("② + Asset Criticality",
         "avg(base) + avg(asset)",
         "Now we know what was hit — payment servers and database servers, not random hosts"),
        ("③ + PII Exposure Tier",
         "avg(base+asset) + avg(pii)",
         "Now we factor in what data was at risk — full-track card data, SSNs, banking credentials"),
        ("④ + Attack Complexity",
         "avg(base+asset+pii) + avg(complexity)",
         "Finally, how sophisticated the chain was — 7 distinct MITRE phases over 5 days. This equals the composite."),
    ],
    col_widths=[1.5, 2.4, 2.7]
)

h2("5.3  Row 3 — Legend Tables  (one under each gauge)")
make_table(
    ["Panel", "Fields Shown", "What to Point Out"],
    [
        ("① Risk Level Breakdown",
         "event.norm_risk_level | event count",
         "Almost all 31 events are Critical — shows the attacker maintained high-confidence detections throughout"),
        ("② Asset Inventory Match",
         "source.ip | destination.ip | score.asset_type | score.asset_criticality",
         "Payment server (50) and DB server (45) appear at the top. Proves the enrich lookup worked — context is live."),
        ("③ PII Exposure Detail",
         "score.pii_label | score.pii_exposure_tier | event count",
         "payment_card_full_track at tier 20 (maxed by 100 MB volume). Inferred entries show asset-type inference working for events without explicit pii_type."),
        ("④ Attack Phase & Technique",
         "custom.str1 | threat.name | event count",
         "Walk the 7 phases top to bottom. The Suricata signature names narrate the entire campaign story."),
    ],
    col_widths=[1.5, 2.0, 3.1]
)

h2("5.4  Applying KQL Filters  (interactive demo moment)")
body("In the Kibana search bar, type the following to show how all 5 gauges update live:")
code('custom.str1 : "exfiltration"')
body(
    "The composite score will spike because exfiltration events combine: high PII tiers (explicit pii_type fields), "
    "high-value target assets (payment server, DB server), and maximum attack complexity (phase score 7 + EXFIL category bonus +3).",
    bold_spans=["composite score will spike"]
)
code('custom.str1 : "initial_access"')
body("Score drops significantly — patient zero only, no PII data yet, low asset criticality (user workstation = 7), low phase complexity.")

h2("5.5  Contrast with test_rat  (runtime field model)")
body("Navigate to the second dashboard:")
code("https://192.168.86.55:5601/app/dashboards#/view/rat-dashboard")
body(
    "Point out: same attack structure, but the score is a single number with no breakdown. "
    "No asset lookup, no PII tiers, no stored score fields. You cannot drill into why an event scored high. "
    "This shows why the ingest pipeline model is worth the setup cost.",
    bold_spans=["no breakdown", "why an event scored high"]
)


# ══════════════════════════════════════════════════════════════════════════════
# 6. DEMO SCRIPT — SUGGESTED ORDER
# ══════════════════════════════════════════════════════════════════════════════
h1("6. Demo Script — Suggested Talking Order")

steps = [
    ("elastic.sh",
     "Open the script. Point to the ifconfig block at line 8 (detects the host IP dynamically). "
     "Show the certutil commands that generate SSL certs inside a throwaway container. "
     "Show the curl health-check loop that waits for Elasticsearch before starting Kibana and Logstash. "
     "Say: 'This single script bootstraps the entire stack with zero manual configuration.'"),
    ("inputs.conf",
     "Show the 12 input listeners. Highlight the type tag routing at the bottom. "
     "Say: 'Logstash is listening for live data on 12 ports covering every source type in the environment.'"),
    ("output.conf",
     "Show the if/else on error[type]. Say: 'Every valid event goes to the forensics index. "
     "Parsing failures are quarantined in failed-logs — nothing gets silently dropped.'"),
    ("gen_events.py  (rat_scored)",
     "Show the network topology constants at the top. Walk through the 7 phase comment blocks. "
     "Point out that the event() function never sets score.* fields. "
     "Say: 'The events carry the raw IDS telemetry — the intelligence comes from the pipeline.'"),
    ("asset_inventory.ndjson",
     "Read out the 7 rows. Show the criticality ladder from payment_server (50) down to user_workstation (15). "
     "Say: 'This is the asset context layer. Seven lines of JSON that fundamentally change how every event scores.'"),
    ("setup.sh",
     "Walk the 8 numbered sections. Spend most time on section 3 (the Python heredoc building the pipeline JSON). "
     "Open the Painless strings for the asset script — show the max(src, dst) logic. "
     "Show the PII tier script — point out the inferred asset_type fallback. "
     "Say: 'The pipeline runs 7 Painless processors in sequence, once, at index time.'"),
    ("Open Kibana — rat_scored dashboard",
     "Walk Row 1 → Row 2 (step-up gauges, left to right) → Row 3 (legend tables). "
     "Apply the exfiltration KQL filter. Apply the initial_access filter to show the contrast. Clear the filter."),
    ("Open Kibana — rat dashboard (test_rat)",
     "Show the simpler runtime-field dashboard. "
     "Say: 'Same attack, single number, no breakdown — you can see the score but you can't explain it.'"),
]

for i, (label, detail) in enumerate(steps, 1):
    p = doc.add_paragraph()
    p.paragraph_format.space_before = Pt(6)
    p.paragraph_format.space_after  = Pt(2)
    p.paragraph_format.left_indent  = Inches(0.0)
    r1 = p.add_run(f"Step {i}:  ")
    r1.bold = True
    r1.font.size = Pt(11)
    set_run_color(r1, DARK_BLUE)
    r2 = p.add_run(label)
    r2.bold = True
    r2.font.size = Pt(11)
    set_run_color(r2, MED_BLUE)
    body_p = doc.add_paragraph()
    body_p.paragraph_format.left_indent = Inches(0.35)
    body_p.paragraph_format.space_after = Pt(4)
    rr = body_p.add_run(detail)
    rr.font.size = Pt(10.5)
    set_run_color(rr, TEXT_BLACK)


# ══════════════════════════════════════════════════════════════════════════════
# 7. QUICK REFERENCE
# ══════════════════════════════════════════════════════════════════════════════
h1("7. Quick Reference")

h2("Stack URLs")
make_table(
    ["Service", "URL"],
    [
        ("Kibana",         "https://192.168.86.55:5601"),
        ("Elasticsearch",  "https://192.168.86.55:9200"),
    ],
    col_widths=[1.5, 5.0]
)

h2("Credentials")
make_table(
    ["Account", "Username", "Password", "Used For"],
    [
        ("Superuser",       "elastic",       "Sanjay1234",  "All API calls, curl commands, Kibana login"),
        ("Kibana service",  "kibana_system", "Sanjay12345", "Internal Kibana→Elasticsearch auth (set by elastic.sh)"),
    ],
    col_widths=[1.4, 1.4, 1.4, 2.4]
)

h2("Re-seed All Indexes After a Stack Rebuild")
code("cd ~/praxis && source .env")
code("ES_PASS=$ES_PASS bash indexes/forensics/setup.sh")
code("ES_PASS=$ES_PASS bash indexes/test_rat/setup.sh")
code("ES_PASS=$ES_PASS bash indexes/rat_scored/setup.sh")

h2("Useful One-liners")
code("# Verify Elasticsearch is up\ncurl -sk -u elastic:$ES_PASS https://192.168.86.55:9200")
code("# Check event counts\ncurl -sk -u elastic:$ES_PASS https://192.168.86.55:9200/_cat/count/rat_scored?v")
code("# Sample a scored event\ncurl -sk -u elastic:$ES_PASS 'https://192.168.86.55:9200/rat_scored/_search?size=1&sort=@timestamp:asc&pretty'")
code("# Import dashboard manually\nsource .env\ncurl -sk -u elastic:$ES_PASS \\\n  -XPOST 'https://192.168.86.55:5601/api/saved_objects/_import?overwrite=true' \\\n  -H 'kbn-xsrf: true' \\\n  -F 'file=@indexes/rat_scored/dashboard.ndjson;type=application/ndjson'")


# ══════════════════════════════════════════════════════════════════════════════
# Save
# ══════════════════════════════════════════════════════════════════════════════
out = "/home/elastic/praxis/RAT_Attack_Demo_Walkthrough.docx"
doc.save(out)
print(f"Saved: {out}")
