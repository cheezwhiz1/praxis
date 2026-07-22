#!/usr/bin/env python3
"""
Pure-Python implementations of the inferential tests named in Praxis §3.8.4.
No numpy/scipy dependency (unavailable on the host). p-values come from the
regularized incomplete beta function (Student-t and F) and math.erfc (normal).

Provides: paired_t, independent_t (pooled + Welch), levene, two_proportion_z,
cohens_d. Each returns a plain dict of statistics ready for the report tables.
"""
import math
from statistics import mean, median, pstdev, stdev


# ── special functions ─────────────────────────────────────────────────────────
def _betacf(a, b, x):
    MAXIT, EPS, FPMIN = 200, 3.0e-12, 1.0e-300
    qab, qap, qam = a + b, a + 1.0, a - 1.0
    c = 1.0
    d = 1.0 - qab * x / qap
    if abs(d) < FPMIN:
        d = FPMIN
    d = 1.0 / d
    h = d
    for m in range(1, MAXIT + 1):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d
        if abs(d) < FPMIN:
            d = FPMIN
        c = 1.0 + aa / c
        if abs(c) < FPMIN:
            c = FPMIN
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < EPS:
            break
    return h


def betai(a, b, x):
    """Regularized incomplete beta function I_x(a, b)."""
    if x <= 0.0:
        return 0.0
    if x >= 1.0:
        return 1.0
    lbeta = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b)
    bt = math.exp(lbeta + a * math.log(x) + b * math.log(1.0 - x))
    if x < (a + 1.0) / (a + b + 2.0):
        return bt * _betacf(a, b, x) / a
    return 1.0 - bt * _betacf(b, a, 1.0 - x) / b


def t_two_tailed_p(t, df):
    if df <= 0:
        return float("nan")
    if t == 0:
        return 1.0
    return betai(df / 2.0, 0.5, df / (df + t * t))


def f_sf(f, d1, d2):
    """P(F >= f) for F-distribution with (d1, d2) df."""
    if f <= 0:
        return 1.0
    return betai(d2 / 2.0, d1 / 2.0, d2 / (d2 + d1 * f))


def normal_two_tailed_p(z):
    return math.erfc(abs(z) / math.sqrt(2.0))


# ── tests ─────────────────────────────────────────────────────────────────────
def cohens_d_paired(a, b):
    """Cohen's d for paired samples: mean(diff) / sd(diff)."""
    diffs = [x - y for x, y in zip(a, b)]
    sd = stdev(diffs) if len(diffs) > 1 else 0.0
    return (mean(diffs) / sd) if sd > 0 else 0.0


def cohens_d_independent(a, b):
    """Cohen's d with pooled SD for two independent groups."""
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return 0.0
    va, vb = stdev(a) ** 2, stdev(b) ** 2
    sp = math.sqrt(((na - 1) * va + (nb - 1) * vb) / (na + nb - 2))
    return (mean(a) - mean(b)) / sp if sp > 0 else 0.0


def paired_t(a, b):
    """Paired-samples t-test (a vs b). Positive t => a > b on average."""
    n = len(a)
    diffs = [x - y for x, y in zip(a, b)]
    md = mean(diffs)
    sd = stdev(diffs) if n > 1 else 0.0
    se = sd / math.sqrt(n) if n > 0 and sd > 0 else float("inf")
    t = md / se if se not in (0, float("inf")) else 0.0
    df = n - 1
    return {"test": "paired t-test", "n_pairs": n, "mean_diff": md,
            "t": t, "df": df, "p": t_two_tailed_p(t, df),
            "cohens_d": cohens_d_paired(a, b),
            "mean_a": mean(a), "mean_b": mean(b)}


def independent_t(a, b):
    """Independent-samples t-test, pooled (Student) + Welch. Positive t => a > b."""
    na, nb = len(a), len(b)
    ma, mb = mean(a), mean(b)
    va = stdev(a) ** 2 if na > 1 else 0.0
    vb = stdev(b) ** 2 if nb > 1 else 0.0
    # pooled / Student
    dfp = na + nb - 2
    sp2 = (((na - 1) * va + (nb - 1) * vb) / dfp) if dfp > 0 else 0.0
    se_p = math.sqrt(sp2 * (1.0 / na + 1.0 / nb)) if sp2 > 0 else float("inf")
    tp = (ma - mb) / se_p if se_p not in (0, float("inf")) else 0.0
    # Welch
    se_w = math.sqrt(va / na + vb / nb) if (va / na + vb / nb) > 0 else float("inf")
    tw = (ma - mb) / se_w if se_w not in (0, float("inf")) else 0.0
    if se_w not in (0, float("inf")):
        num = (va / na + vb / nb) ** 2
        den = (va / na) ** 2 / (na - 1) + (vb / nb) ** 2 / (nb - 1) if na > 1 and nb > 1 else 1
        dfw = num / den if den > 0 else dfp
    else:
        dfw = dfp
    return {"test": "independent t-test", "n_a": na, "n_b": nb,
            "mean_a": ma, "mean_b": mb, "sd_a": math.sqrt(va), "sd_b": math.sqrt(vb),
            "t_pooled": tp, "df_pooled": dfp, "p_pooled": t_two_tailed_p(tp, dfp),
            "t_welch": tw, "df_welch": dfw, "p_welch": t_two_tailed_p(tw, dfw),
            "cohens_d": cohens_d_independent(a, b)}


def levene(a, b):
    """Levene's test (Brown-Forsythe, median-centered) for equality of variance."""
    na, nb = len(a), len(b)
    if na < 2 or nb < 2:
        return {"test": "levene", "W": float("nan"), "df1": 1, "df2": na + nb - 2, "p": float("nan")}
    za = [abs(x - median(a)) for x in a]
    zb = [abs(x - median(b)) for x in b]
    zbar_a, zbar_b = mean(za), mean(zb)
    zbar = mean(za + zb)
    N, k = na + nb, 2
    numer = (N - k) * (na * (zbar_a - zbar) ** 2 + nb * (zbar_b - zbar) ** 2)
    denom = (k - 1) * (sum((z - zbar_a) ** 2 for z in za) + sum((z - zbar_b) ** 2 for z in zb))
    W = numer / denom if denom > 0 else float("inf")
    d1, d2 = k - 1, N - k
    return {"test": "levene", "W": W, "df1": d1, "df2": d2, "p": f_sf(W, d1, d2)}


def two_proportion_z(x1, n1, x2, n2):
    """Two-proportion z-test. x=successes, n=trials. Positive z => p1 > p2."""
    if n1 == 0 or n2 == 0:
        return {"test": "two-proportion z", "p1": float("nan"), "p2": float("nan"),
                "z": float("nan"), "p": float("nan"), "x1": x1, "n1": n1, "x2": x2, "n2": n2}
    p1, p2 = x1 / n1, x2 / n2
    pp = (x1 + x2) / (n1 + n2)
    se = math.sqrt(pp * (1 - pp) * (1.0 / n1 + 1.0 / n2))
    z = (p1 - p2) / se if se > 0 else 0.0
    # Cohen's h effect size for proportions
    h = 2 * math.asin(math.sqrt(p1)) - 2 * math.asin(math.sqrt(p2))
    return {"test": "two-proportion z", "p1": p1, "p2": p2, "z": z,
            "p": normal_two_tailed_p(z), "cohens_h": h,
            "x1": x1, "n1": n1, "x2": x2, "n2": n2}


def describe(xs):
    xs = list(xs)
    if not xs:
        return {"n": 0, "mean": float("nan"), "sd": float("nan"), "min": float("nan"), "max": float("nan")}
    return {"n": len(xs), "mean": mean(xs), "sd": (stdev(xs) if len(xs) > 1 else 0.0),
            "min": min(xs), "max": max(xs), "median": median(xs)}
