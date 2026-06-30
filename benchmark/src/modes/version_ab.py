"""versionab — version-A/B verifier benchmark mode."""
from __future__ import annotations


def normalize_verdict(v: str) -> str:
    s = (v or "").strip().lower()
    if s == "tp" or "true positive" in s:
        return "TP"
    if s == "fp" or "false positive" in s:
        return "FP"
    if s == "nmd" or "more data" in s or "needs more" in s:
        return "NMD"
    return (v or "?").strip().upper()[:4]


def grade(verdict: str, truth: str) -> str:
    n = normalize_verdict(verdict)
    if truth == "real":
        return "CORRECT" if n == "TP" else ("MISS" if n == "FP" else "abstain")
    if truth == "not-real":
        return "CORRECT" if n == "FP" else ("FALSE-ALARM" if n == "TP" else "abstain")
    return "?"


def aggregate(findings: list[dict], n_real: int) -> dict:
    tp_total = sum(1 for f in findings if normalize_verdict(f["verdict"]) == "TP")
    tp_real = sum(1 for f in findings if f["truth"] == "real" and normalize_verdict(f["verdict"]) == "TP")
    false_alarm = sum(1 for f in findings if f["truth"] == "not-real" and normalize_verdict(f["verdict"]) == "TP")
    n_not_real = sum(1 for f in findings if f["truth"] == "not-real")
    cost = round(sum((f.get("cost_usd") or 0.0) for f in findings), 4)
    return {
        "tp_total": tp_total, "tp_real": tp_real, "false_alarm": false_alarm,
        "precision": (tp_real / tp_total) if tp_total else None,
        "recall": (tp_real / n_real) if n_real else None,
        "n_real": n_real, "n_not_real": n_not_real, "cost_usd": cost,
    }


def classify_flip(prev_v: str, cur_v: str, truth: str) -> str:
    pc, cc = grade(prev_v, truth), grade(cur_v, truth)
    if cc == "CORRECT" and pc != "CORRECT":
        return "IMPROVE"
    if pc == "CORRECT" and cc != "CORRECT":
        return "REGRESS"
    return "neutral"
