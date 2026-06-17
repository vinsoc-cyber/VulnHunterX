# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Statistical tests for benchmark evaluation (Q1-journal grade).

All functions are stdlib-only. No scipy dependency.

Provided:
  - wilson_ci          : Wilson 95% CI for a binomial proportion
  - mcnemar            : McNemar's test (paired binary classifier comparison)
  - bootstrap_ci       : Percentile bootstrap CI for an arbitrary statistic
  - cliffs_delta       : Cliff's delta nonparametric effect size

References:
  Wilson, E. B. (1927). Probable inference, the law of succession, and
    statistical inference. JASA 22(158), 209-212.
  McNemar, Q. (1947). Note on the sampling error of the difference between
    correlated proportions or percentages. Psychometrika 12(2), 153-157.
  Edgington, E. S., & Onghena, P. (2007). Randomization tests, 4th ed.
  Cliff, N. (1993). Dominance statistics: ordinal analyses to answer
    ordinal questions. Psychological Bulletin 114(3), 494.
"""

from __future__ import annotations

import math
import random
from collections.abc import Callable, Sequence
from dataclasses import dataclass

# ---- Wilson CI ------------------------------------------------------------

# Two-tailed z critical values for common confidence levels.
_Z = {
    0.80: 1.2815515655446004,
    0.90: 1.6448536269514722,
    0.95: 1.959963984540054,
    0.99: 2.5758293035489004,
}


def wilson_ci(
    successes: int, trials: int, confidence: float = 0.95
) -> tuple[float, float]:
    """Wilson score CI for a binomial proportion.

    Wilson is preferred over the Wald (normal-approximation) CI for small N
    and proportions near 0 or 1, both of which are common in SAST triage.

    Args:
      successes: number of successes (e.g., correct predictions).
      trials:    total trials (must be >= successes).
      confidence: e.g. 0.95 for a 95% CI.

    Returns:
      (lower, upper) bounds in [0, 1]. Returns (0.0, 1.0) when trials == 0.
    """
    if trials < 0 or successes < 0 or successes > trials:
        raise ValueError(
            f"Invalid inputs: successes={successes}, trials={trials}"
        )
    if trials == 0:
        return (0.0, 1.0)
    if confidence not in _Z:
        raise ValueError(
            f"Unsupported confidence {confidence}; use one of {list(_Z)}"
        )
    z = _Z[confidence]
    n = trials
    p = successes / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


# ---- McNemar's test -------------------------------------------------------


@dataclass(frozen=True)
class McNemarResult:
    """Outcome of McNemar's test for paired binary classifiers.

    Attributes:
      b: number of items A was correct on but B was wrong on.
      c: number of items B was correct on but A was wrong on.
      statistic: chi-square statistic (with continuity correction) when
                 b + c >= 25; otherwise None and the exact binomial p is used.
      p_value: two-sided p-value.
      method: "chi2_continuity" or "exact_binomial".
    """

    b: int
    c: int
    statistic: float | None
    p_value: float
    method: str


def _binomial_pmf(k: int, n: int, p: float) -> float:
    return math.comb(n, k) * (p ** k) * ((1 - p) ** (n - k))


def _exact_binomial_two_sided(b: int, c: int) -> float:
    """Two-sided exact binomial p-value for McNemar with p = 0.5."""
    n = b + c
    if n == 0:
        return 1.0
    k = min(b, c)
    # Sum probabilities of outcomes at least as extreme on both tails.
    p = 0.0
    for i in range(0, k + 1):
        p += _binomial_pmf(i, n, 0.5)
    p *= 2.0
    return min(p, 1.0)


def _chi2_sf_1df(x: float) -> float:
    """Survival function of chi-square with 1 d.f. (= 1 - CDF).

    Closed-form: P(X > x) = erfc(sqrt(x/2)).
    """
    if x <= 0:
        return 1.0
    return math.erfc(math.sqrt(x / 2.0))


def mcnemar(b: int, c: int) -> McNemarResult:
    """McNemar's test on paired binary outcomes.

    `b` and `c` are the off-diagonal counts of the 2x2 contingency table:
        b = A_correct AND B_wrong
        c = A_wrong   AND B_correct
    The diagonal cells (both right / both wrong) do not enter the test.

    For b + c < 25 the exact binomial test (p = 0.5) is used; otherwise the
    chi-square approximation with continuity correction:
        chi2 = (|b - c| - 1)^2 / (b + c)

    Args:
      b, c: off-diagonal counts.

    Returns:
      McNemarResult with statistic, p_value, and method label.
    """
    if b < 0 or c < 0:
        raise ValueError(f"Counts must be non-negative: b={b}, c={c}")
    n = b + c
    if n == 0:
        return McNemarResult(b=0, c=0, statistic=None, p_value=1.0,
                             method="exact_binomial")
    if n < 25:
        p = _exact_binomial_two_sided(b, c)
        return McNemarResult(b=b, c=c, statistic=None, p_value=p,
                             method="exact_binomial")
    chi2 = (abs(b - c) - 1) ** 2 / n
    p = _chi2_sf_1df(chi2)
    return McNemarResult(b=b, c=c, statistic=chi2, p_value=p,
                         method="chi2_continuity")


# ---- Percentile bootstrap CI ----------------------------------------------


def bootstrap_ci(
    samples: Sequence[float],
    statistic: Callable[[Sequence[float]], float],
    n_resamples: int = 10_000,
    confidence: float = 0.95,
    rng_seed: int | None = 1729,
) -> tuple[float, float, float]:
    """Percentile bootstrap CI.

    The percentile method is appropriate for symmetric, near-pivotal
    statistics (F1, FP-reduction-rate, TP-preservation-rate). For highly
    skewed distributions, BCa would be more accurate; we keep the
    implementation stdlib-only and report the percentile CI as the
    journal-acceptable default.

    Args:
      samples: observed sample (e.g., per-finding correctness 0/1).
      statistic: callable computing the statistic of interest on a resample.
      n_resamples: number of bootstrap resamples (default 10,000).
      confidence: e.g., 0.95.
      rng_seed: RNG seed for reproducibility (None => os.urandom).

    Returns:
      (point_estimate, lower, upper).
    """
    if not samples:
        return (float("nan"), float("nan"), float("nan"))
    if not 0.0 < confidence < 1.0:
        raise ValueError(f"confidence must be in (0,1); got {confidence}")
    if n_resamples < 1:
        raise ValueError("n_resamples must be >= 1")

    rng = random.Random(rng_seed)
    n = len(samples)
    point = statistic(samples)
    estimates: list[float] = []
    for _ in range(n_resamples):
        resample = [samples[rng.randrange(n)] for _ in range(n)]
        try:
            estimates.append(statistic(resample))
        except (ZeroDivisionError, ValueError):
            # Degenerate resample (e.g., all-zeros for F1); skip.
            continue
    if not estimates:
        return (point, float("nan"), float("nan"))
    estimates.sort()
    alpha = (1.0 - confidence) / 2.0
    lo_idx = int(alpha * len(estimates))
    hi_idx = int((1.0 - alpha) * len(estimates)) - 1
    lo_idx = max(0, min(lo_idx, len(estimates) - 1))
    hi_idx = max(0, min(hi_idx, len(estimates) - 1))
    return (point, estimates[lo_idx], estimates[hi_idx])


# ---- Cliff's delta --------------------------------------------------------


def cliffs_delta(a: Sequence[float], b: Sequence[float]) -> tuple[float, str]:
    """Cliff's delta nonparametric effect size.

    delta = (#(a > b) - #(a < b)) / (|a| * |b|), in [-1, +1].

    Conventional thresholds (Romano et al., 2006):
      |delta| < 0.147 : negligible
      |delta| < 0.330 : small
      |delta| < 0.474 : medium
      otherwise        : large

    Returns:
      (delta, qualitative_label).
    """
    if not a or not b:
        return (0.0, "negligible")
    gt = lt = 0
    # O(|a| * |b|) is fine for benchmark-scale samples.
    for x in a:
        for y in b:
            if x > y:
                gt += 1
            elif x < y:
                lt += 1
    delta = (gt - lt) / (len(a) * len(b))
    abs_d = abs(delta)
    if abs_d < 0.147:
        label = "negligible"
    elif abs_d < 0.330:
        label = "small"
    elif abs_d < 0.474:
        label = "medium"
    else:
        label = "large"
    return (delta, label)


# ---- Convenience wrappers -------------------------------------------------


def precision_ci(
    tp_correct: int, fp_missed: int, confidence: float = 0.95
) -> tuple[float, float] | None:
    """Wilson CI for precision = TP / (TP + FP)."""
    denom = tp_correct + fp_missed
    if denom == 0:
        return None
    return wilson_ci(tp_correct, denom, confidence)


def recall_ci(
    tp_correct: int, tp_missed: int, confidence: float = 0.95
) -> tuple[float, float] | None:
    """Wilson CI for recall = TP / (TP + FN)."""
    denom = tp_correct + tp_missed
    if denom == 0:
        return None
    return wilson_ci(tp_correct, denom, confidence)


def f1_bootstrap_ci(
    per_finding: Sequence[tuple[int, int]],
    n_resamples: int = 10_000,
    confidence: float = 0.95,
    rng_seed: int | None = 1729,
) -> tuple[float, float, float]:
    """Bootstrap CI for F1 from per-finding (label, prediction) tuples.

    Each tuple is (gt_label, pred_label) where 1 = TP, 0 = FP. F1 is
    recomputed on each resample.
    """
    indices = list(range(len(per_finding)))

    def _f1(idxs: Sequence[float]) -> float:
        tp = fn = fp = 0
        for i in idxs:
            i = int(i)
            gt, pred = per_finding[i]
            if gt == 1 and pred == 1:
                tp += 1
            elif gt == 1 and pred == 0:
                fn += 1
            elif gt == 0 and pred == 1:
                fp += 1
        denom_p = tp + fp
        denom_r = tp + fn
        if denom_p == 0 or denom_r == 0:
            return 0.0
        p = tp / denom_p
        r = tp / denom_r
        if p + r == 0:
            return 0.0
        return 2 * p * r / (p + r)

    return bootstrap_ci(
        samples=indices,  # type: ignore[arg-type]
        statistic=_f1,
        n_resamples=n_resamples,
        confidence=confidence,
        rng_seed=rng_seed,
    )
