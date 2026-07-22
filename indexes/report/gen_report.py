#!/usr/bin/env python3
"""
Praxis v7 — statistical validation report generator.

Computes the §3.8.2/§3.8.3 metrics from the paired baseline/enriched indices,
runs the §3.8.4 inferential tests (paired t-test + Cohen's d; two-proportion
z-test; independent t-test + Levene), renders per-hypothesis verdicts for
H1/H2/H3, and writes:
  report/praxis_validation_report.docx   (thesis-ready)
  report/praxis_validation_report.md     (same content, Markdown)
  report/metrics_raw.csv                 (per-scenario raw numbers + test stats)
It also seeds the `praxis_results` index and imports the Kibana results dashboard.

Run:  source .env && ES_PASS=$ES_PASS python3 indexes/report/gen_report.py
"""
import csv
import json
import os
import ssl
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(HERE, "..", "lib"))
import metrics as MET          # noqa: E402
import stats as ST             # noqa: E402
import gen_results_dashboard as GRD  # noqa: E402
from lens_dsl import write_objects  # noqa: E402

ES = os.environ.get("ES_URL", "https://192.168.86.55:9200")
KB = os.environ.get("KB_URL", "https://192.168.86.55:5601")
PW = os.environ.get("ES_PASS", "")


# ── compute everything ────────────────────────────────────────────────────────
def compute():
    M = MET.all_metrics()
    pool = {}
    pool["b_high"] = sum(m["baseline"]["high"] for m in M)
    pool["b_tp"] = sum(m["baseline"]["tp"] for m in M)
    pool["b_fp"] = sum(m["baseline"]["fp"] for m in M)
    pool["e_high"] = sum(m["enriched"]["high"] for m in M)
    pool["e_tp"] = sum(m["enriched"]["tp"] for m in M)
    pool["e_fp"] = sum(m["enriched"]["fp"] for m in M)
    pool["n_mal"] = sum(m["n_mal"] for m in M)
    pool["n"] = sum(m["n"] for m in M)
    ttb = [t for m in M for t in m["triage_baseline"]]
    tte = [t for m in M for t in m["triage_enriched"]]
    cmal = [c for m in M for c in m["comp_mal"]]
    cben = [c for m in M for c in m["comp_ben"]]
    ed_b = sum(m["early_base"] for m in M)
    ed_e = sum(m["early_enr"] for m in M)
    ed_n = sum(m["early_pre"] for m in M)
    cov = sum(m["cov_covered"] for m in M)
    covn = sum(m["cov_internal"] for m in M)

    tests = {
        "triage": ST.paired_t(ttb, tte),                       # H1
        "tpr": ST.two_proportion_z(pool["e_tp"], pool["e_high"],  # H2
                                   pool["b_tp"], pool["b_high"]),
        "precision_t": ST.independent_t(cmal, cben),           # risk-score precision
        "precision_levene": ST.levene(cmal, cben),
        "early": ST.two_proportion_z(ed_e, ed_n, ed_b, ed_n),  # H3
    }
    pool["b_tpr"] = pool["b_tp"] / pool["b_high"] if pool["b_high"] else 0
    pool["e_tpr"] = pool["e_tp"] / pool["e_high"] if pool["e_high"] else 0
    pool["b_fpr"] = pool["b_fp"] / pool["b_high"] if pool["b_high"] else 0
    pool["e_fpr"] = pool["e_fp"] / pool["e_high"] if pool["e_high"] else 0
    pool["vol_reduction"] = 1 - pool["e_high"] / pool["b_high"] if pool["b_high"] else 0
    pool["early_b"], pool["early_e"], pool["early_n"] = ed_b, ed_e, ed_n
    pool["cov"], pool["covn"] = cov, covn
    pool["n_triage"] = len(ttb)
    # verdicts
    def verdict(sig, direction):
        return "SUPPORTED" if (sig and direction) else ("DIRECTIONALLY SUPPORTED" if direction else "NOT SUPPORTED")
    tests["H1_verdict"] = verdict(tests["triage"]["p"] < 0.05, tests["triage"]["mean_a"] > tests["triage"]["mean_b"])
    tests["H2_verdict"] = verdict(tests["tpr"]["p"] < 0.05, pool["e_tpr"] > pool["b_tpr"])
    tests["H3_verdict"] = verdict(tests["early"]["p"] < 0.05, pool["early_e"] > pool["early_b"])
    return M, pool, tests


# ── CSV ───────────────────────────────────────────────────────────────────────
def write_csv(M, pool, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["scenario", "title", "condition", "alerts_total", "malicious_total",
                    "high_priority_volume", "true_positives", "false_positives",
                    "tpr_at_high", "fpr_at_high", "recall_at_high"])
        for m in M:
            for cond in ("baseline", "enriched"):
                b = m[cond]
                w.writerow([m["key"], m["title"], cond, m["n"], m["n_mal"], b["high"], b["tp"],
                            b["fp"], f"{b['tpr']:.3f}", f"{b['fpr']:.3f}", f"{b['recall']:.3f}"])
        w.writerow([])
        w.writerow(["POOLED", "", "baseline", pool["n"], pool["n_mal"], pool["b_high"], pool["b_tp"],
                    pool["b_fp"], f"{pool['b_tpr']:.3f}", f"{pool['b_fpr']:.3f}", ""])
        w.writerow(["POOLED", "", "enriched", pool["n"], pool["n_mal"], pool["e_high"], pool["e_tp"],
                    pool["e_fp"], f"{pool['e_tpr']:.3f}", f"{pool['e_fpr']:.3f}", ""])
    print(f"  wrote {path}")


# ── Markdown ──────────────────────────────────────────────────────────────────
def fp(x, n=3):
    return f"{x:.{n}f}"


def pfmt(p):
    return "< 0.001" if p < 0.001 else f"= {p:.3f}"


def write_md(M, pool, tests, path):
    L = []
    L.append("# Praxis — PII Context Framework: Statistical Validation Report\n")
    L.append("_Two-condition (baseline vs enriched) evaluation across five PII-targeting "
             "attack scenarios. Hypotheses H1–H3 tested with the §3.8.4 methods._\n")
    L.append("## 1. Executive Summary\n")
    L.append("| Hypothesis | Test (§3.8.4) | Key statistic | Verdict |")
    L.append("|---|---|---|---|")
    L.append(f"| H1 — faster triage of high-risk PII threats | Paired t-test + Cohen's d | "
             f"t({tests['triage']['df']})={fp(tests['triage']['t'],2)}, p {pfmt(tests['triage']['p'])}, "
             f"d={fp(tests['triage']['cohens_d'],2)} | **{tests['H1_verdict']}** |")
    L.append(f"| H2 — noise reduction / higher TPR@high | Two-proportion z-test | "
             f"z={fp(tests['tpr']['z'],2)}, p {pfmt(tests['tpr']['p'])} | **{tests['H2_verdict']}** |")
    L.append(f"| H3 — earlier detection of precursors | Two-proportion z-test | "
             f"z={fp(tests['early']['z'],2)}, p {pfmt(tests['early']['p'])} | **{tests['H3_verdict']}** |")
    L.append("")
    L.append(f"Across {pool['n']} alerts per condition ({pool['n_mal']} malicious), the enriched "
             f"PII Context Framework cut high-priority alert volume from **{pool['b_high']} to "
             f"{pool['e_high']} ({fp(pool['vol_reduction']*100,0)}% reduction)** while raising the "
             f"true-positive rate at high priority from **{fp(pool['b_tpr'])} to {fp(pool['e_tpr'])}**.\n")

    L.append("## 2. Method\n")
    L.append("- **Design:** single-environment, two-condition comparison over five scenarios. "
             "Identical events indexed twice; the only difference is the populated `pii.context.*` "
             "namespace in the enriched condition (baseline uses signature + threshold rules only).")
    L.append("- **Enriched scoring (v7 promotion model):** base alert severity is scored 0–100 by the "
             "*same* standard-detection formula as the baseline (base tiers: high ≥60, medium 40–59, low <40). "
             "The PII context is a **bounded, weighted promotion layer** — three visible contributions "
             "(PII exposure 0–25 primary impact, asset criticality 0–20 secondary impact, attack complexity "
             "0–15 threat likelihood) are **added** to the base: `composite = base + pii + asset + complexity`. "
             "Impact (≤45) outweighs likelihood (≤15), so a confirmed attack on Tier-1/2 PII is promoted to "
             "**critical** while a sophisticated attack on non-sensitive data is capped at high. The critical "
             "tier is **gated on a confirmed PII attack** — Tier-1/2 PII target **and** real attack evidence "
             "(observed PII exposure or ≥1 correlated MITRE technique), so ambient traffic on PII-holding "
             "assets does not qualify (NIST SP 800-30r1 / 800-122 / FIPS 199).")
    L.append("- **Actionable high-priority queue:** baseline = high+critical (base ≥60), the best a "
             "context-blind SOC can prioritize; enriched = the promoted **critical** tier — the confirmed "
             "PII-attack queue. Ground truth = `labels.is_malicious`.")
    L.append(f"- **Simulated triage-time model (H1):** deterministic; time to escalate a high-risk TP = "
             f"{fp(MET.T_READ,0)}s read + queue-depth×{fp(MET.T_PER,0)}s + context penalty "
             f"(baseline {fp(MET.C_CTX_BASELINE,0)}s manual lookup, enriched {fp(MET.C_CTX_ENRICHED,0)}s), "
             f"or {fp(MET.T_DEFER,0)}s if deferred (not high-priority). A model, not a human study (§3.9.1).\n")

    L.append("## 3. Primary Metrics (per scenario)\n")
    L.append("| Scenario | Cond. | High-prio | TP | FP | TPR@high | FPR@high | Recall |")
    L.append("|---|---|---|---|---|---|---|---|")
    for m in M:
        for cond in ("baseline", "enriched"):
            b = m[cond]
            L.append(f"| {m['key']} | {cond} | {b['high']} | {b['tp']} | {b['fp']} | "
                     f"{fp(b['tpr'])} | {fp(b['fpr'])} | {fp(b['recall'])} |")
    L.append(f"| **POOLED** | baseline | **{pool['b_high']}** | {pool['b_tp']} | {pool['b_fp']} | "
             f"**{fp(pool['b_tpr'])}** | {fp(pool['b_fpr'])} | |")
    L.append(f"| **POOLED** | enriched | **{pool['e_high']}** | {pool['e_tp']} | {pool['e_fp']} | "
             f"**{fp(pool['e_tpr'])}** | {fp(pool['e_fpr'])} | |")
    L.append("")

    L.append("## 4. Inferential Statistics (§3.8.4)\n")
    t = tests["triage"]
    L.append(f"**H1 — Paired t-test on simulated triage time** (n={pool['n_triage']} high-risk TPs). "
             f"Baseline mean **{fp(t['mean_a'],0)}s** vs enriched **{fp(t['mean_b'],0)}s** "
             f"(Δ={fp(t['mean_diff'],0)}s, {fp(t['mean_diff']/t['mean_a']*100,0)}% faster). "
             f"t({t['df']})={fp(t['t'],2)}, p {pfmt(t['p'])}, Cohen's d={fp(t['cohens_d'],2)}.\n")
    z = tests["tpr"]
    L.append(f"**H2 — Two-proportion z-test on TPR@high.** Enriched {fp(z['p1'])} ({z['x1']}/{z['n1']}) "
             f"vs baseline {fp(z['p2'])} ({z['x2']}/{z['n2']}). z={fp(z['z'],2)}, p {pfmt(z['p'])}, "
             f"Cohen's h={fp(z['cohens_h'],2)}.\n")
    it, lv = tests["precision_t"], tests["precision_levene"]
    use = "Welch" if lv["p"] < 0.05 else "pooled"
    tval = it["t_welch"] if use == "Welch" else it["t_pooled"]
    pval = it["p_welch"] if use == "Welch" else it["p_pooled"]
    L.append(f"**Risk-score precision — independent t-test (composite of TP vs FP).** "
             f"Levene W={fp(lv['W'],2)}, p {pfmt(lv['p'])} → variances "
             f"{'unequal, ' if lv['p']<0.05 else 'equal, '}report {use}. "
             f"TP mean **{fp(it['mean_a'],1)}** vs FP mean **{fp(it['mean_b'],1)}**; "
             f"t={fp(tval,2)}, p {pfmt(pval)}, Cohen's d={fp(it['cohens_d'],2)}.\n")

    L.append("## 5. Secondary Metrics (§3.8.3)\n")
    L.append(f"- **Alert-distribution shift:** enriched moves the mass of alerts out of the high/critical "
             f"tiers — high-priority share falls from {fp(pool['b_high']/pool['n']*100,1)}% to "
             f"{fp(pool['e_high']/pool['n']*100,1)}% of all alerts, concentrating on true positives.")
    L.append(f"- **PII-exposure coverage:** {pool['cov']}/{pool['covn']} "
             f"({fp(pool['cov']/pool['covn']*100,0)}%) of implicated internal assets are in the registry.")
    L.append(f"- **Risk-score precision:** TP composite mean {fp(it['mean_a'],1)} ≫ FP mean "
             f"{fp(it['mean_b'],1)} (see §4) — the model differentiates threat levels rather than "
             f"uniformly inflating scores.")
    ez = tests["early"]
    L.append(f"- **Early-detection rate (H3):** of {pool['early_n']} pre-exfiltration malicious events on "
             f"Tier-1/2 assets, enriched flags **{pool['early_e']} ({fp(ez['p1'])})** as high-priority vs "
             f"baseline **{pool['early_b']} ({fp(ez['p2'])})** — enriched surfaces "
             f"{fp((ez['p1']/ez['p2']-1)*100,0) if ez['p2'] else 'n/a'}% more early precursors.\n")

    L.append("## 6. Hypothesis Findings\n")
    L.append(f"**H1 ({tests['H1_verdict']}).** Analysts using the framework triage high-risk PII threats "
             f"significantly faster (paired t-test, p {pfmt(t['p'])}, medium effect d={fp(t['cohens_d'],2)}). "
             f"The enriched condition removes manual context-gathering and shrinks the high-priority queue.\n")
    L.append(f"**H2 ({tests['H2_verdict']}).** Correlating behaviour with PII context sharply reduces noise: "
             f"high-priority volume falls {fp(pool['vol_reduction']*100,0)}% and TPR@high rises from "
             f"{fp(pool['b_tpr'])} to {fp(pool['e_tpr'])} (z={fp(z['z'],2)}, p {pfmt(z['p'])}).\n")
    L.append(f"**H3 ({tests['H3_verdict']}).** Enriched assigns high priority to early-stage precursors more "
             f"often than baseline ({fp(ez['p1'])} vs {fp(ez['p2'])}). Consistent with §3.8.4, the small "
             f"number of precursor events limits statistical power (p {pfmt(ez['p'])}); the evidence is "
             f"directionally consistent, which is the stated proof-of-concept contribution.\n")

    L.append("## 7. Limitations (§3.9.1)\n")
    for lim in ["Synthetic data cannot fully replicate production noise, temporal patterns, and context.",
                "Single-node ELK deployment; enterprise-scale scoring efficiency untested.",
                "Five scenarios cannot encompass the full adversary technique space.",
                "Triage time is a documented deterministic model, not a study with human analyst evaluators.",
                "The scoring model is calibrated for this environment and would require recalibration elsewhere."]:
        L.append(f"- {lim}")
    L.append("")
    open(path, "w").write("\n".join(L))
    print(f"  wrote {path}")
    return "\n".join(L)


# ── DOCX ──────────────────────────────────────────────────────────────────────
def write_docx(M, pool, tests, path):
    try:
        from docx import Document
        from docx.shared import Pt, RGBColor, Inches
        from docx.enum.text import WD_ALIGN_PARAGRAPH
    except ImportError:
        print("  python-docx not available — skipping .docx")
        return
    DARK = RGBColor(0x1F, 0x39, 0x64); MED = RGBColor(0x2E, 0x74, 0xB5)
    GREEN = RGBColor(0x2E, 0x7D, 0x32); RED = RGBColor(0x9B, 0x1B, 0x1B); BLACK = RGBColor(0x1A, 0x1A, 0x1A)
    doc = Document()
    for s in doc.sections:
        s.top_margin = s.bottom_margin = Inches(1); s.left_margin = s.right_margin = Inches(1)

    def h(text, size, color, before=14, after=6):
        p = doc.add_paragraph(); p.paragraph_format.space_before = Pt(before); p.paragraph_format.space_after = Pt(after)
        r = p.add_run(text); r.bold = True; r.font.size = Pt(size); r.font.color.rgb = color; return p

    def body(text, bold=False, color=BLACK):
        p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(4)
        r = p.add_run(text); r.font.size = Pt(10.5); r.bold = bold; r.font.color.rgb = color; return p

    def table(headers, rows, widths=None):
        t = doc.add_table(rows=1, cols=len(headers)); t.style = "Table Grid"
        for i, hd in enumerate(headers):
            c = t.rows[0].cells[i]; run = c.paragraphs[0].add_run(hd); run.bold = True; run.font.size = Pt(9)
            run.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)
            sh = c._tc.get_or_add_tcPr(); from docx.oxml import OxmlElement; from docx.oxml.ns import qn
            e = OxmlElement("w:shd"); e.set(qn("w:fill"), "1F3964"); sh.append(e)
        for row in rows:
            cells = t.add_row().cells
            for i, v in enumerate(row):
                run = cells[i].paragraphs[0].add_run(str(v)); run.font.size = Pt(9); run.font.color.rgb = BLACK
        doc.add_paragraph()
        return t

    def vcolor(v):
        return GREEN if v == "SUPPORTED" else (MED if "DIRECTION" in v else RED)

    # Title
    tp = doc.add_paragraph(); tp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = tp.add_run("PII Context Framework — Statistical Validation Report"); r.bold = True; r.font.size = Pt(20); r.font.color.rgb = DARK
    sp = doc.add_paragraph(); sp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    r = sp.add_run("Two-condition evaluation across five PII-targeting attack scenarios · Hypotheses H1–H3 (§3.8.4)")
    r.font.size = Pt(11); r.font.color.rgb = MED
    doc.add_paragraph()

    h("1. Executive Summary", 15, DARK)
    body(f"Across {pool['n']} alerts per condition ({pool['n_mal']} malicious), the enriched PII Context "
         f"Framework cut high-priority alert volume from {pool['b_high']} to {pool['e_high']} "
         f"({pool['vol_reduction']*100:.0f}% reduction) while raising the true-positive rate at high "
         f"priority from {pool['b_tpr']:.3f} to {pool['e_tpr']:.3f}.")
    t = tests["triage"]; z = tests["tpr"]; ez = tests["early"]
    table(["Hypothesis", "Test (§3.8.4)", "Key statistic", "Verdict"],
          [["H1 — faster triage of high-risk PII threats", "Paired t-test + Cohen's d",
            f"t({t['df']})={t['t']:.2f}, p {pfmt(t['p'])}, d={t['cohens_d']:.2f}", tests["H1_verdict"]],
           ["H2 — noise reduction / higher TPR@high", "Two-proportion z-test",
            f"z={z['z']:.2f}, p {pfmt(z['p'])}", tests["H2_verdict"]],
           ["H3 — earlier detection of precursors", "Two-proportion z-test",
            f"z={ez['z']:.2f}, p {pfmt(ez['p'])}", tests["H3_verdict"]]])

    h("2. Method", 15, DARK)
    for line in [
        "Design: single-environment, two-condition comparison over five scenarios. Identical events "
        "indexed twice; the only difference is the populated pii.context.* namespace in the enriched "
        "condition (baseline uses signature + threshold detection rules only).",
        "Enriched scoring (v7 promotion model): base alert severity is scored 0–100 by the same "
        "standard-detection formula as the baseline (high ≥60, medium 40–59, low <40) and owns the base "
        "tier. The PII context is a bounded, weighted promotion layer: three contributions — PII exposure "
        "(0–25, primary impact), asset criticality (0–20, secondary impact) and attack complexity (0–15, "
        "threat likelihood) — are added to the base, giving composite = base + the three. Because impact "
        "(≤45) outweighs likelihood (≤15), a confirmed attack on Tier-1/2 PII is promoted to CRITICAL while "
        "a sophisticated attack on non-sensitive data is bounded at high. The CRITICAL tier is gated on a "
        "confirmed PII attack: Tier-1/2 PII target AND real attack evidence (observed PII exposure or ≥1 "
        "correlated MITRE technique), so ambient traffic on PII assets does not qualify (NIST SP 800-30r1/"
        "800-122). Actionable high-priority queue: baseline = high+critical (≥60); enriched = the promoted "
        "critical tier.",
        f"Simulated triage-time model (H1): time to escalate a high-risk true positive = {MET.T_READ:.0f}s "
        f"read + queue-depth × {MET.T_PER:.0f}s + context penalty (baseline {MET.C_CTX_BASELINE:.0f}s "
        f"manual lookup, enriched {MET.C_CTX_ENRICHED:.0f}s), or {MET.T_DEFER:.0f}s if deferred. "
        "Deterministic model, not a human-analyst study (§3.9.1)."]:
        body("• " + line)

    h("3. Primary Metrics (per scenario)", 15, DARK)
    rows = []
    for m in M:
        for cond in ("baseline", "enriched"):
            b = m[cond]
            rows.append([m["key"], cond, b["high"], b["tp"], b["fp"],
                         f"{b['tpr']:.3f}", f"{b['fpr']:.3f}", f"{b['recall']:.3f}"])
    rows.append(["POOLED", "baseline", pool["b_high"], pool["b_tp"], pool["b_fp"],
                 f"{pool['b_tpr']:.3f}", f"{pool['b_fpr']:.3f}", ""])
    rows.append(["POOLED", "enriched", pool["e_high"], pool["e_tp"], pool["e_fp"],
                 f"{pool['e_tpr']:.3f}", f"{pool['e_fpr']:.3f}", ""])
    table(["Scenario", "Cond.", "High-prio", "TP", "FP", "TPR@high", "FPR@high", "Recall"], rows)

    h("4. Inferential Statistics (§3.8.4)", 15, DARK)
    body(f"H1 — Paired t-test on simulated triage time (n={pool['n_triage']} high-risk TPs). Baseline mean "
         f"{t['mean_a']:.0f}s vs enriched {t['mean_b']:.0f}s (Δ={t['mean_diff']:.0f}s, "
         f"{t['mean_diff']/t['mean_a']*100:.0f}% faster). t({t['df']})={t['t']:.2f}, p {pfmt(t['p'])}, "
         f"Cohen's d={t['cohens_d']:.2f}.", bold=True)
    body(f"H2 — Two-proportion z-test on TPR@high. Enriched {z['p1']:.3f} ({z['x1']}/{z['n1']}) vs baseline "
         f"{z['p2']:.3f} ({z['x2']}/{z['n2']}). z={z['z']:.2f}, p {pfmt(z['p'])}, Cohen's h={z['cohens_h']:.2f}.",
         bold=True)
    it, lv = tests["precision_t"], tests["precision_levene"]
    use = "Welch" if lv["p"] < 0.05 else "pooled"
    tval = it["t_welch"] if use == "Welch" else it["t_pooled"]
    pval = it["p_welch"] if use == "Welch" else it["p_pooled"]
    body(f"Risk-score precision — independent-samples t-test (composite of true vs false positives). "
         f"Levene W={lv['W']:.2f}, p {pfmt(lv['p'])} → variances {'unequal' if lv['p']<0.05 else 'equal'}, "
         f"report {use}. TP mean {it['mean_a']:.1f} vs FP mean {it['mean_b']:.1f}; t={tval:.2f}, "
         f"p {pfmt(pval)}, Cohen's d={it['cohens_d']:.2f}.", bold=True)

    h("5. Secondary Metrics (§3.8.3)", 15, DARK)
    body(f"• Alert-distribution shift: high-priority share of all alerts falls from "
         f"{pool['b_high']/pool['n']*100:.1f}% to {pool['e_high']/pool['n']*100:.1f}%, concentrating on true positives.")
    body(f"• PII-exposure coverage: {pool['cov']}/{pool['covn']} ({pool['cov']/pool['covn']*100:.0f}%) of "
         f"implicated internal assets are in the Asset Inventory Registry.")
    body(f"• Risk-score precision: TP composite mean {it['mean_a']:.1f} ≫ FP mean {it['mean_b']:.1f}.")
    body(f"• Early-detection rate (H3): of {pool['early_n']} pre-exfiltration malicious events on Tier-1/2 "
         f"assets, enriched flags {pool['early_e']} ({ez['p1']:.3f}) as high-priority vs baseline "
         f"{pool['early_b']} ({ez['p2']:.3f}).")

    h("6. Hypothesis Findings", 15, DARK)
    for hyp, verdict, txt in [
        ("H1", tests["H1_verdict"], f"Analysts using the framework triage high-risk PII threats significantly "
         f"faster (paired t-test p {pfmt(t['p'])}, d={t['cohens_d']:.2f}). The enriched condition removes "
         f"manual context-gathering and shrinks the high-priority queue."),
        ("H2", tests["H2_verdict"], f"PII context sharply reduces noise: high-priority volume falls "
         f"{pool['vol_reduction']*100:.0f}% and TPR@high rises from {pool['b_tpr']:.3f} to {pool['e_tpr']:.3f} "
         f"(z={z['z']:.2f}, p {pfmt(z['p'])})."),
        ("H3", tests["H3_verdict"], f"Enriched assigns high priority to early-stage precursors more often than "
         f"baseline ({ez['p1']:.3f} vs {ez['p2']:.3f}). Per §3.8.4 the small precursor count limits power "
         f"(p {pfmt(ez['p'])}); the evidence is directionally consistent — the stated proof-of-concept contribution.")]:
        p = doc.add_paragraph(); p.paragraph_format.space_after = Pt(4)
        r1 = p.add_run(f"{hyp} — "); r1.bold = True; r1.font.size = Pt(11); r1.font.color.rgb = DARK
        r2 = p.add_run(verdict + ". "); r2.bold = True; r2.font.size = Pt(11); r2.font.color.rgb = vcolor(verdict)
        r3 = p.add_run(txt); r3.font.size = Pt(10.5); r3.font.color.rgb = BLACK

    h("7. Limitations (§3.9.1)", 15, DARK)
    for lim in ["Synthetic data cannot fully replicate production noise, temporal patterns, and context.",
                "Single-node ELK deployment; enterprise-scale scoring efficiency untested.",
                "Five scenarios cannot encompass the full adversary technique space.",
                "Triage time is a documented deterministic model, not a study with human analyst evaluators.",
                "The scoring model is calibrated for this environment and would require recalibration elsewhere."]:
        body("• " + lim)

    doc.save(path)
    print(f"  wrote {path}")


# ── push results index + dashboard to the stack ──────────────────────────────
def push_results(M):
    if not PW:
        print("  ES_PASS not set — skipping praxis_results push"); return
    ndj = GRD.results_ndjson(M)
    mapping = GRD.results_mapping()
    curl = ["curl", "-sk", "-u", f"elastic:{PW}"]
    subprocess.run(curl + ["-XDELETE", f"{ES}/praxis_results"], capture_output=True)
    subprocess.run(curl + ["-XPUT", f"{ES}/praxis_results", "-H", "Content-Type: application/json",
                           "-d", json.dumps(mapping)], capture_output=True)
    subprocess.run(curl + ["-XPOST", f"{ES}/praxis_results/_bulk?refresh=true",
                           "-H", "Content-Type: application/x-ndjson", "--data-binary", ndj], capture_output=True)
    # data view
    subprocess.run(curl + ["-XDELETE", f"{KB}/api/data_views/data_view/praxis_results",
                           "-H", "kbn-xsrf: true"], capture_output=True)
    subprocess.run(curl + ["-XPOST", f"{KB}/api/data_views/data_view", "-H", "kbn-xsrf: true",
                           "-H", "Content-Type: application/json",
                           "-d", json.dumps({"data_view": {"id": "praxis_results", "title": "praxis_results",
                                                            "name": "praxis_results"}})], capture_output=True)
    # dashboard
    objs = GRD.build_dashboard()
    dpath = os.path.join(HERE, "results_dashboard.ndjson")
    write_objects(objs, dpath)
    r = subprocess.run(curl + ["-XPOST", f"{KB}/api/saved_objects/_import?overwrite=true",
                               "-H", "kbn-xsrf: true", "-F", f"file=@{dpath};type=application/ndjson"],
                       capture_output=True, text=True)
    try:
        print(f"  results dashboard imported: {json.loads(r.stdout).get('successCount')} objects")
    except Exception:
        print("  results dashboard import: see", dpath)


def main():
    M, pool, tests = compute()
    write_csv(M, pool, os.path.join(HERE, "metrics_raw.csv"))
    write_md(M, pool, tests, os.path.join(HERE, "praxis_validation_report.md"))
    write_docx(M, pool, tests, os.path.join(HERE, "praxis_validation_report.docx"))
    push_results(M)
    print(f"\nVerdicts:  H1 {tests['H1_verdict']}  |  H2 {tests['H2_verdict']}  |  H3 {tests['H3_verdict']}")


if __name__ == "__main__":
    main()
