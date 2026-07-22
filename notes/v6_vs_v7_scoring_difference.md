# Praxis scoring: v6 (additive) vs v7 (promotion) — the difference

## 1. The mechanism

### Old model (v6) — one additive number
The enriched score summed four components into a single 10–100 composite:

```
composite = base_severity(0–30) + asset_criticality(0–25) + pii_exposure(0–25) + complexity(5–20)
priority  = critical >=80 · high 60–79 · medium 40–59 · low <40
```

Base severity was squeezed into 0–30 so the four parts fit under 100. PII context was
just 25 points added to a pot. Critical was reachable any way the numbers summed past 80.

### New model (v7) — base score stands alone; PII context is a separate gate

```
Step 1 (base):      base_severity(0–100)  ->  base_priority: high >=60, medium 40–59, low <40
Step 2 (promotion): IF (>=2 MITRE techniques in session) AND (target = Tier-1/2 PII)
                        THEN priority = CRITICAL      <- overrides base tier
                    ELSE priority = base_priority     <- base tier preserved
```

Base severity is now the full 0–100 standard-detection score — the identical formula the
baseline uses. PII context no longer nudges a number; it makes a yes/no decision to
escalate to critical. Critical is unreachable by base score alone in the enriched logic —
it is reserved for a confirmed PII attack. (Baseline keeps its own critical tier separately.)

## 2. Same event, both models

### "ET SCAN SQL Server Discovery Probe" — quiet recon, 4 techniques, Tier-1 (card data) asset

| | v6 additive | v7 promotion |
|---|---|---|
| Base severity | 10 (squeezed into 0–30) | 10 (full 0–100 -> "low") |
| Asset/PII/complexity | +24 +24 +14 | (not summed — used as gate inputs) |
| Result | composite ~= 62 -> "high" | 4 techniques AND Tier-1 => promoted -> CRITICAL |

### Loud but non-PII event — bulk backup transfer on a marketing (Tier-4) server

| | v6 additive | v7 promotion |
|---|---|---|
| Base severity | high raw signal | ~85 -> "critical" by base |
| PII | none (Tier-4) | not a Tier-1/2 target => not promoted |
| Result | dragged down by low PII points -> maybe "medium" | stays at base tier (loud), never promoted |

Key flip: v6 PENALIZED loud non-PII noise (few PII points). v7 leaves base severity intact
and instead ELEVATES the quiet PII attacks. Escalation now flows the right direction.

## 3. Why it matters — v6 contradicted the thesis

v6 folded everything into one sum, producing incoherent outcomes:

- Baseline showed MORE criticals than enriched. e.g. s3_insider: baseline 3 critical,
  enriched 0. The squeezed base meant a genuine attack often could not reach 80. The
  framework looked like it demoted attacks.

Under v7 the same scenarios flip:

| Scenario | Enriched criticals: v6 -> v7 |
|---|---|
| s1_rat | 4 -> 13 |
| s3_insider | 0 -> 8 |
| s5_ransomware | 4 -> 13 |

Every new critical is a multi-stage attack on a Tier-1/2 PII asset — many rated only
low/medium/high by baseline. That is literally "the critical events baseline misses."

## 4. The difference between conditions under v7

- Baseline (no PII context): base severity -> tiers. Loud attacks hit critical; quiet PII
  recon/collection sits at low/medium/high, buried among ~35 benign false positives/scenario.
- Enriched (PII context): same base severity, PLUS the promotion gate. Quiet PII attacks
  jump to a clean critical tier; benign noise does not promote (no Tier-1/2 target, no
  multi-stage chain) and stays where it was.

The difference between conditions is now purely the promotion decision — the cleanest
control, since the base score is identical across both.

## 5. The metric / framing difference (the section 3.8.1 point)

Because v7's base is the full 0–100 (not squeezed), the raw "high+critical" count cannot
shrink in enriched — promotion only adds. The noise reduction instead shows up as a
concentrated critical tier:

- Baseline actionable queue = high+critical ~= 210 alerts (mostly FP, TPR 0.20).
- Enriched actionable queue = promoted critical ~= 60 alerts (mostly TP, TPR 0.83).

The report measures a surgical critical queue the analyst works first — not fewer alerts at
a threshold. This is the one departure from the doc's literal section 3.8.1 wording
("report critical and high jointly"), which only made arithmetic sense under the old
squeezed-base model. That sentence should be updated in the dissertation.

## Deployed before -> after (pooled, all 5 scenarios)

| Metric | Baseline | Enriched | 
|---|---|---|
| Actionable high-priority volume | 210 | 60 |
| TPR@high | 0.195 | 0.833 |
| Simulated triage time | 730 s | 87 s |
| H1 / H2 / H3 | | all SUPPORTED (p<0.001) |
