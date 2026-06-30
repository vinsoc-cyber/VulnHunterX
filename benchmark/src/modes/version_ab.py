"""versionab — version-A/B verifier benchmark mode."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path


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


def load_real_keys(gt_path: Path) -> set:
    real = set()
    for k in json.loads(Path(gt_path).read_text()):
        rule, rest = k.rsplit("@", 1)
        file, line = rest.rsplit(":", 1)
        real.add((rule.strip(), file.strip(), int(line)))
    return real


def panel_hash(test_case_dir: Path) -> str:
    h = hashlib.sha256()
    for f in sorted(Path(test_case_dir).rglob("*")):
        if f.is_file() and f.name != "ground_truth.json":
            h.update(str(f.relative_to(test_case_dir)).encode())
            h.update(f.read_bytes())
    return "sha256:" + h.hexdigest()[:32]


def build_score(raw_dir: Path, real_keys: set, meta: dict) -> dict:
    findings = []
    for jf in sorted(Path(raw_dir).glob("*.json")):
        if jf.name.startswith(("summary_", "report")):
            continue
        j = json.loads(jf.read_text())
        f = j["finding"]
        rule, file, line = f["rule_id"].strip(), str(f["file"]).strip(), int(f["start_line"])
        truth = "real" if (rule, file, line) in real_keys else "not-real"
        nv = normalize_verdict(j.get("verdict", "?"))
        findings.append({
            "rule": rule, "file": file, "line": line,
            "verdict": nv, "confidence": j.get("confidence"),
            "cost_usd": j.get("cost_usd") or 0.0,
            "truth": truth, "grade": grade(nv, truth),
        })
    return {"meta": meta, "findings": findings, "aggregates": aggregate(findings, len(real_keys))}
