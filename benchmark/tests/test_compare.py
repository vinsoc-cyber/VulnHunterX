import pytest
from modes import version_ab as v


def _f(rule, file, line, truth, verdict, conf="High"):
    return {"rule": rule, "file": file, "line": line, "truth": truth,
            "verdict": verdict, "confidence": conf, "cost_usd": 0.1,
            "grade": v.grade(verdict, truth)}


def _score(version, findings, model="gpt-5.5", iters=5):
    n_real = sum(1 for f in findings if f["truth"] == "real")
    meta = {"version": version, "provider": "openai", "model": model, "temperature": 0,
            "max_iterations": iters, "panel_hash": "sha256:x", "timestamp": "T"}
    return {"meta": meta, "findings": findings, "aggregates": v.aggregate(findings, n_real)}


def test_compare_improve():
    prev = _score("1.0.0@a", [_f("r", "f.c", 1, "real", "FP")])
    cur = _score("1.0.0@b", [_f("r", "f.c", 1, "real", "TP")])
    churn = v.compare_scores(prev, cur, "T")
    assert churn["totals"] == {"flips": 1, "improve": 1, "regress": 0, "neutral": 0}
    assert churn["flips"][0]["direction"] == "IMPROVE"
    assert churn["deltas"]["recall"] == 1.0


def test_compare_no_flip():
    prev = _score("1.0.0@a", [_f("r", "f.c", 1, "real", "TP")])
    cur = _score("1.0.0@b", [_f("r", "f.c", 1, "real", "TP")])
    assert v.compare_scores(prev, cur, "T")["totals"]["flips"] == 0


def test_compare_confound_raises():
    prev = _score("1.0.0@a", [_f("r", "f.c", 1, "real", "TP")], model="gpt-5.5")
    cur = _score("1.0.0@b", [_f("r", "f.c", 1, "real", "TP")], model="other")
    with pytest.raises(v.ConfoundError):
        v.compare_scores(prev, cur, "T")


def test_compare_confound_iterations():
    prev = _score("1.0.0@a", [_f("r", "f.c", 1, "real", "TP")], iters=5)
    cur = _score("1.0.0@b", [_f("r", "f.c", 1, "real", "TP")], iters=10)
    with pytest.raises(v.ConfoundError):   # max_iterations is result-affecting -> a confound
        v.compare_scores(prev, cur, "T")
