# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for benchmarks.metrics.stats (Wilson CI, McNemar, bootstrap, Cliff)."""

from __future__ import annotations

import math

import pytest

from benchmarks.metrics.stats import (
    bootstrap_ci,
    cliffs_delta,
    f1_bootstrap_ci,
    mcnemar,
    precision_ci,
    recall_ci,
    wilson_ci,
)


# ---- Wilson CI ----


def test_wilson_ci_zero_trials():
    assert wilson_ci(0, 0) == (0.0, 1.0)


def test_wilson_ci_all_success():
    lo, hi = wilson_ci(10, 10)
    # All-success Wilson lower bound is strictly between 0.69 and 1.0.
    assert 0.69 < lo < 1.0
    assert math.isclose(hi, 1.0, abs_tol=1e-9)


def test_wilson_ci_all_failure():
    lo, hi = wilson_ci(0, 10)
    assert math.isclose(lo, 0.0, abs_tol=1e-9)
    assert 0.0 < hi < 0.31


def test_wilson_ci_balanced():
    # 5 / 10 — known textbook value approx [0.237, 0.763].
    lo, hi = wilson_ci(5, 10)
    assert math.isclose(lo, 0.237, abs_tol=0.005)
    assert math.isclose(hi, 0.763, abs_tol=0.005)


def test_wilson_ci_invalid_inputs():
    with pytest.raises(ValueError):
        wilson_ci(11, 10)
    with pytest.raises(ValueError):
        wilson_ci(-1, 10)


def test_wilson_ci_unsupported_confidence():
    with pytest.raises(ValueError):
        wilson_ci(5, 10, confidence=0.71)


def test_precision_ci_helper():
    ci = precision_ci(tp_correct=8, fp_missed=2)
    assert ci is not None
    assert 0.4 < ci[0] < 0.85
    assert 0.85 < ci[1] <= 1.0


def test_recall_ci_zero_denominator():
    assert recall_ci(0, 0) is None


# ---- McNemar's test ----


def test_mcnemar_zero_disagreement():
    r = mcnemar(0, 0)
    assert r.p_value == 1.0
    assert r.statistic is None
    assert r.method == "exact_binomial"


def test_mcnemar_exact_small_n():
    # 2 vs 8: exact binomial test with p=0.5, n=10.
    # Two-sided: 2*P(X<=2 | n=10, p=0.5) = 2 * (1 + 10 + 45) / 1024 ≈ 0.109
    r = mcnemar(2, 8)
    assert r.method == "exact_binomial"
    assert math.isclose(r.p_value, 0.109375, abs_tol=1e-6)


def test_mcnemar_chi2_for_large_n():
    # 30 vs 5 — chi2 = (|30-5|-1)^2 / 35 = 24^2/35 ≈ 16.46. p < 0.001.
    r = mcnemar(30, 5)
    assert r.method == "chi2_continuity"
    assert r.statistic is not None
    assert r.statistic > 16
    assert r.p_value < 0.001


def test_mcnemar_symmetry():
    r1 = mcnemar(8, 2)
    r2 = mcnemar(2, 8)
    assert math.isclose(r1.p_value, r2.p_value, abs_tol=1e-9)


def test_mcnemar_negative_input():
    with pytest.raises(ValueError):
        mcnemar(-1, 5)


# ---- Bootstrap CI ----


def test_bootstrap_ci_constant_sample():
    samples = [1.0] * 100
    point, lo, hi = bootstrap_ci(
        samples, statistic=lambda x: sum(x) / len(x), n_resamples=200
    )
    assert math.isclose(point, 1.0)
    assert math.isclose(lo, 1.0)
    assert math.isclose(hi, 1.0)


def test_bootstrap_ci_mean_ordering():
    samples = [0.0, 1.0] * 50
    point, lo, hi = bootstrap_ci(
        samples, statistic=lambda x: sum(x) / len(x),
        n_resamples=2000, rng_seed=1234,
    )
    assert math.isclose(point, 0.5)
    assert lo <= point <= hi
    # Width sanity: 95% CI for mean of 0/1 with n=100 is roughly [0.4, 0.6].
    assert 0.30 < lo < 0.50
    assert 0.50 < hi < 0.70


def test_bootstrap_ci_empty():
    point, lo, hi = bootstrap_ci(
        [], statistic=lambda x: sum(x), n_resamples=100
    )
    assert math.isnan(point)
    assert math.isnan(lo)
    assert math.isnan(hi)


def test_bootstrap_ci_invalid_args():
    with pytest.raises(ValueError):
        bootstrap_ci([1.0], statistic=sum, confidence=0.0)
    with pytest.raises(ValueError):
        bootstrap_ci([1.0], statistic=sum, n_resamples=0)


def test_f1_bootstrap_ci_perfect():
    # All TP, no FP, no FN — F1 should be 1.0 with tight CI.
    per_finding = [(1, 1)] * 50  # gt=TP, pred=TP, no negatives
    # Need at least one FP-label sample for F1 to be meaningful;
    # add some true-negative-style entries (gt=FP, pred=FP).
    per_finding = [(1, 1)] * 25 + [(0, 0)] * 25
    point, lo, hi = f1_bootstrap_ci(per_finding, n_resamples=500)
    assert math.isclose(point, 1.0)
    assert math.isclose(hi, 1.0)


# ---- Cliff's delta ----


def test_cliffs_delta_negligible():
    a = [1, 2, 3, 4, 5]
    delta, label = cliffs_delta(a, a)
    assert math.isclose(delta, 0.0)
    assert label == "negligible"


def test_cliffs_delta_large():
    a = [10, 11, 12, 13]
    b = [1, 2, 3, 4]
    delta, label = cliffs_delta(a, b)
    assert math.isclose(delta, 1.0)
    assert label == "large"


def test_cliffs_delta_inverse():
    a = [1, 2, 3, 4]
    b = [10, 11, 12, 13]
    delta, label = cliffs_delta(a, b)
    assert math.isclose(delta, -1.0)
    assert label == "large"


def test_cliffs_delta_empty():
    delta, label = cliffs_delta([], [1, 2, 3])
    assert delta == 0.0
    assert label == "negligible"
