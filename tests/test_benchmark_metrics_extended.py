# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""specificity / Youden J / MCC / label-tier / dismissal-budget metrics."""

from __future__ import annotations

import pytest

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.approaches.base import PRED_FP, PRED_NMD, PRED_TP, BenchmarkResult
from benchmarks.metrics.evaluator import evaluate


def _entry(label: str, i: int) -> GroundTruthEntry:
    return GroundTruthEntry(
        id=f"e{i}",
        source_dataset="t",
        cwe_id="CWE-79",
        rule_id="r",
        file_path="f.c",
        function_name="fn",
        start_line=1,
        lang="c",
        label=label,
        code_snippet="x",
    )


def _res(entry: GroundTruthEntry, pred: str, conf: str = "High") -> BenchmarkResult:
    return BenchmarkResult(
        entry=entry,
        predicted_label=pred,
        confidence=conf,
        reasoning="t",
        elapsed_seconds=0.1,
        iterations=1,
    )


def _matrix(tp: int, fn: int, tn: int, fp: int, conf: str = "High"):
    results: list[BenchmarkResult] = []
    i = 0
    for label, pred, n in (
        (LABEL_TP, PRED_TP, tp),
        (LABEL_TP, PRED_FP, fn),
        (LABEL_FP, PRED_FP, tn),
        (LABEL_FP, PRED_TP, fp),
    ):
        for _ in range(n):
            results.append(_res(_entry(label, i), pred, conf))
            i += 1
    return evaluate(results, "t", "d")


def test_specificity_youden_mcc_hand_computed():
    m = _matrix(tp=40, fn=10, tn=30, fp=20)
    assert m.specificity == pytest.approx(30 / 50)
    assert m.youden_j == pytest.approx(0.8 + 0.6 - 1)
    expected = (40 * 30 - 20 * 10) / (60 * 50 * 50 * 40) ** 0.5
    assert m.mcc == pytest.approx(expected)
    d = m.summary_dict()
    assert d["specificity"] == 0.6
    assert d["youden_j"] == 0.4
    assert d["mcc"] == pytest.approx(round(expected, 4))


def test_degenerate_returns_none():
    m = _matrix(tp=5, fn=0, tn=0, fp=0)
    assert m.specificity is None and m.youden_j is None and m.mcc is None


def test_nmd_exclude_vs_fp():
    res = [
        _res(_entry(LABEL_TP, 0), PRED_NMD),
        _res(_entry(LABEL_FP, 1), PRED_NMD),
        _res(_entry(LABEL_TP, 2), PRED_TP),
    ]
    ex = evaluate(res, "t", "d", nmd_handling="exclude")
    assert ex.specificity is None and ex.recall == 1.0
    nf = evaluate(res, "t", "d", nmd_handling="fp")
    assert nf.specificity == 1.0 and nf.recall == 0.5


def test_label_tier_breakdown():
    a = _entry(LABEL_TP, 0)
    a.metadata["label_tier"] = "gold"
    b = _entry(LABEL_FP, 1)
    b.metadata["label_tier"] = "silver"
    c = _entry(LABEL_FP, 2)
    m = evaluate([_res(a, PRED_TP), _res(b, PRED_TP), _res(c, PRED_FP)], "t", "d")
    assert set(m.tier_metrics) == {"gold", "silver"}
    tiers = {t["label_tier"]: t for t in m.summary_dict()["per_label_tier"]}
    assert tiers["silver"]["fp_missed"] == 1
    assert tiers["gold"]["recall"] == 1.0


def test_suppression_at_budget_ranked():
    plan = (
        ("High", LABEL_FP, PRED_FP, 6),
        ("Low", LABEL_FP, PRED_FP, 2),
        ("Low", LABEL_TP, PRED_FP, 1),
        ("High", LABEL_FP, PRED_TP, 2),
        ("High", LABEL_TP, PRED_TP, 9),
    )
    results = []
    i = 0
    for conf, lab, pred, n in plan:
        for _ in range(n):
            results.append(_res(_entry(lab, i), pred, conf))
            i += 1
    m = evaluate(results, "t", "d")
    zero = m.suppression_at_dismissal_budget(0.0)
    assert zero["ranked"] and zero["suppression"] == pytest.approx(6 / 10)
    assert zero["harmful_dismissal_rate"] == 0.0 and zero["min_confidence"] == "High"
    loose = m.suppression_at_dismissal_budget(0.10)
    assert loose["suppression"] == pytest.approx(8 / 10)
    assert loose["harmful_dismissal_rate"] == pytest.approx(1 / 10)


def test_suppression_unranked_without_confidence():
    m = _matrix(tp=9, fn=1, tn=4, fp=6, conf="")
    r = m.suppression_at_dismissal_budget(0.05)
    assert r["ranked"] is False
    assert r["suppression"] == pytest.approx(4 / 10)
    assert r["harmful_dismissal_rate"] == pytest.approx(1 / 10)
    assert r["within_budget"] is False


def test_excluded_results_not_scored():
    a = _entry(LABEL_TP, 0)
    a.metadata["excluded_from_scoring"] = "route=policy-only:legacy_model"
    m = evaluate([_res(a, PRED_TP), _res(_entry(LABEL_FP, 1), PRED_FP)], "t", "d")
    assert m.n_excluded == 1 and m.total_evaluated == 1 and m.total_processed == 1
