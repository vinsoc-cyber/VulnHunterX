from __future__ import annotations
from modes import version_ab as v


def test_normalize_verdict():
    assert v.normalize_verdict("True Positive") == "TP"
    assert v.normalize_verdict("False Positive") == "FP"
    assert v.normalize_verdict("Needs More Data") == "NMD"
    assert v.normalize_verdict("TP") == "TP"  # idempotent
    assert v.normalize_verdict("FP") == "FP"
    assert v.normalize_verdict("NMD") == "NMD"
    assert v.normalize_verdict("inconclusive") == "INCONCLUSIVE"  # unknown fallback: no [:4] truncation


def test_grade_real():
    assert v.grade("True Positive", "real") == "CORRECT"
    assert v.grade("False Positive", "real") == "MISS"
    assert v.grade("Needs More Data", "real") == "abstain"


def test_grade_not_real():
    assert v.grade("False Positive", "not-real") == "CORRECT"
    assert v.grade("True Positive", "not-real") == "FALSE-ALARM"
    assert v.grade("Needs More Data", "not-real") == "abstain"


def test_aggregate():
    findings = [
        {"truth": "real", "verdict": "TP", "cost_usd": 1.0},
        {"truth": "real", "verdict": "FP", "cost_usd": 1.0},
        {"truth": "not-real", "verdict": "TP", "cost_usd": 1.0},
    ]
    a = v.aggregate(findings, n_real=2)
    assert (a["tp_total"], a["tp_real"], a["false_alarm"]) == (2, 1, 1)
    assert a["precision"] == 0.5 and a["recall"] == 0.5 and a["cost_usd"] == 3.0


def test_classify_flip():
    assert v.classify_flip("FP", "TP", "real") == "IMPROVE"
    assert v.classify_flip("TP", "FP", "real") == "REGRESS"
    assert v.classify_flip("TP", "NMD", "real") == "REGRESS"
    assert v.classify_flip("NMD", "FP", "not-real") == "IMPROVE"
    assert v.classify_flip("FP", "NMD", "real") == "neutral"


def test_is_real_verdict():
    assert v.is_real_verdict("TP") and v.is_real_verdict("FP") and v.is_real_verdict("NMD")
    assert not v.is_real_verdict("ERROR")
    assert not v.is_real_verdict("?")


def test_grade_error_stub():
    # a verdict that isn't TP/FP/NMD is an error stub -> "error", NOT "abstain"
    assert v.grade("ERROR", "real") == "error"
    assert v.grade("", "not-real") == "error"
    assert v.grade("503 Service Unavailable", "real") == "error"


def test_aggregate_excludes_errors_from_recall():
    findings = [
        {"truth": "real", "verdict": "TP", "cost_usd": 1.0},
        {"truth": "real", "verdict": "ERROR", "cost_usd": 0.0},    # errored real
        {"truth": "not-real", "verdict": "NMD", "cost_usd": 1.0},  # genuine abstain
    ]
    a = v.aggregate(findings, n_real=2)
    assert a["n_error"] == 1 and a["n_error_real"] == 1
    assert a["n_abstain"] == 1
    assert a["n_real"] == 2          # oracle total unchanged
    assert a["recall"] == 1.0        # tp_real 1 / (n_real 2 - 1 errored real)
    assert a["precision"] == 1.0     # tp_real 1 / tp_total 1
