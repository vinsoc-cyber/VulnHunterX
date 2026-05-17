#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Generate Markdown + CSV report from benchmark results.

Usage:
    python benchmarks/scripts/generate_report.py --run-dir benchmarks/results/<timestamp>
    python benchmarks/scripts/generate_report.py --run-dir benchmarks/results/<timestamp> --charts
"""

from __future__ import annotations

import argparse
import ast
import json
import logging
import re
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)


# Matches an older DiverseVul-shaped cwe_id (`CWE-['CWE-119']` / `CWE-[]`),
# emitted before the adapter's list-handling fix. Lets reports rendered from
# pre-fix summary JSONs still display readable CWE labels.
_CWE_LIST_RE = re.compile(r"^CWE-\[(.*)\]$")


def _clean_cwe(raw: str) -> str:
    if not raw:
        return "Unknown"
    m = _CWE_LIST_RE.match(raw)
    if m:
        body = m.group(1).strip()
        if not body:
            return "Unknown"
        try:
            parsed = ast.literal_eval("[" + body + "]")
        except (SyntaxError, ValueError):
            return "Unknown"
        if not parsed:
            return "Unknown"
        return str(parsed[0])
    return raw


def _pct(val: float | None, decimals: int = 1) -> str:
    if val is None:
        return "—"
    return f"{val * 100:.{decimals}f}%"


def _num(val: float | int | None, decimals: int = 3) -> str:
    if val is None:
        return "—"
    return f"{val:.{decimals}f}"


def _load_results(run_dir: Path) -> list[dict]:
    """Load all checkpoint JSON files from a run directory."""
    summaries = []
    summary_file = run_dir / "summary.json"
    if summary_file.exists():
        data = json.loads(summary_file.read_text())
        return data.get("summary", [])

    # Fall back to reading individual checkpoints
    for f in sorted(run_dir.glob("*_results.json")):
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        # Only include completed checkpoints; skip in-progress (resumed but not done)
        if data.get("status", "completed") != "completed":
            continue
        if "metrics" in data:
            summaries.append(data["metrics"])
    return summaries


def _load_run_meta(run_dir: Path) -> dict:
    """Load root-level run metadata from summary.json."""
    summary_file = run_dir / "summary.json"
    if summary_file.exists():
        data = json.loads(summary_file.read_text())
        return {k: v for k, v in data.items() if k != "summary"}
    return {}


def _run_metadata(run_dir: Path, summaries: list[dict]) -> str:
    """Build a run info section from summary.json metadata."""
    meta = _load_run_meta(run_dir)
    if not meta and not summaries:
        return ""

    model = meta.get("model", "unknown")
    provider = meta.get("provider", "")
    model_str = f"{model} ({provider})" if provider else model
    dry_run = meta.get("dry_run", False)

    datasets = sorted({s.get("dataset", "?") for s in summaries})
    approaches = meta.get("approaches_run") or sorted({s.get("approach", "?") for s in summaries})

    wall_s = meta.get("wall_seconds")
    wall_str = "—"
    if wall_s is not None:
        mins, secs = divmod(int(wall_s), 60)
        wall_str = f"{mins}m {secs}s" if mins else f"{secs}s"

    total_cost = sum(s.get("total_cost_usd", 0.0) for s in summaries)
    # Imputed cost (tokens × API list price) — populated even when LiteLLM has
    # no price for the provider (e.g. Ollama Cloud, local Ollama, self-hosted
    # OpenAI-compatible endpoints). Surface it alongside the real cost so
    # cloud/free-tier runs aren't misread as zero-cost.
    imputed_costs = [
        s.get("imputed_api_cost_usd")
        for s in summaries
        if s.get("imputed_api_cost_usd") is not None
    ]
    total_imputed = sum(imputed_costs) if imputed_costs else None
    if total_imputed is not None and (total_cost == 0.0 or total_imputed > total_cost):
        cost_str = f"${total_cost:.4f} (imputed: ${total_imputed:.4f})"
    else:
        cost_str = f"${total_cost:.4f}"

    lines = [
        "## Run Info",
        "",
        "| | |",
        "| --- | --- |",
        f"| **Model** | {model_str}{' *(dry-run)*' if dry_run else ''} |",
        f"| **Datasets** | {', '.join(datasets)} |",
        f"| **Approaches** | {', '.join(approaches)} |",
        f"| **Wall time** | {wall_str} |",
        f"| **Total cost** | {cost_str} |",
        f"| **Run dir** | `{run_dir}` |",
    ]
    return "\n".join(lines)


def _key_findings(summaries: list[dict]) -> str:
    """Auto-generate a Key Findings prose section from the summary data."""
    if not summaries:
        return ""

    llm_summaries = [s for s in summaries if s.get("approach") != "raw-sast"]
    next((s for s in summaries if s.get("approach") == "raw-sast"), None)

    bullets: list[str] = []

    # Best F1 approach
    scored = [(s.get("f1") or 0, s) for s in llm_summaries if s.get("f1") is not None]
    if scored:
        best_f1_val, best_f1_s = max(scored)
        bullets.append(
            f"**Best overall F1**: `{best_f1_s['approach']}` on `{best_f1_s['dataset']}` "
            f"with F1={_pct(best_f1_val)} (Precision={_pct(best_f1_s.get('precision'))}, "
            f"Recall={_pct(best_f1_s.get('recall'))})."
        )

    # FP reduction
    fp_summaries = [s for s in llm_summaries if s.get("fp_reduction_rate") is not None]
    if fp_summaries:
        best_fp = max(fp_summaries, key=lambda s: s.get("fp_reduction_rate") or 0)
        bullets.append(
            f"**Best FP reduction**: `{best_fp['approach']}` eliminated "
            f"{_pct(best_fp.get('fp_reduction_rate'))} of raw-SAST false positives."
        )

    # TP preservation warnings
    for s in llm_summaries:
        tp_pres = s.get("tp_preservation_rate")
        if tp_pres is not None and tp_pres < 0.80:
            bullets.append(
                f"⚠️ **Low TP preservation**: `{s['approach']}` on `{s['dataset']}` "
                f"preserved only {_pct(tp_pres)} of true positives (threshold: 80%). "
                f"Review to ensure real bugs are not being suppressed."
            )

    # NMD rate warnings
    for s in llm_summaries:
        nmd = s.get("nmd_rate")
        if nmd is not None and nmd > 0.30:
            bullets.append(
                f"⚠️ **High NMD rate**: `{s['approach']}` on `{s['dataset']}` "
                f"returned Needs-More-Data for {_pct(nmd)} of findings. "
                f"Consider increasing `--max-iterations` or providing more context."
            )

    # API-failure warnings — separate operational misses from model errors so
    # the "TP preservation" headline isn't dragged down by quota/network issues.
    for s in llm_summaries:
        api_err = s.get("pred_api_error_count") or 0
        if api_err > 0:
            denom = s.get("total_processed") or 0
            pct = f"{(api_err / denom * 100):.1f}%" if denom else "?"
            bullets.append(
                f"⚠️ **LLM API failures**: `{s['approach']}` on `{s['dataset']}` "
                f"had {api_err} findings ({pct}) fail with an LLM API error "
                f"(rate-limit / quota / network). These count as misses but are "
                f"**not** model errors. Re-run the affected entries to get an "
                f"honest picture; precision/recall above will rise as those "
                f"resolve to real verdicts."
            )

    # VulnHunterX vs generic-questions comparison
    for dataset in {s.get("dataset") for s in summaries}:
        vhx = next((s for s in summaries if s.get("approach") == "vulnhunterx" and s.get("dataset") == dataset), None)
        gq = next((s for s in summaries if s.get("approach") == "generic-questions" and s.get("dataset") == dataset), None)
        if vhx and gq and vhx.get("f1") is not None and gq.get("f1") is not None:
            diff = (vhx["f1"] or 0) - (gq["f1"] or 0)
            if abs(diff) >= 0.01:
                direction = "outperformed" if diff > 0 else "underperformed vs"
                bullets.append(
                    f"**Multi-turn benefit**: `vulnhunterx` {direction} `generic-questions` "
                    f"on `{dataset}` by {_pct(abs(diff))} F1 "
                    f"({_pct(vhx['f1'])} vs {_pct(gq['f1'])})."
                )

    # Per-CWE highlights (best and worst). Exclude buckets with n<10 so a
    # 2-entry CWE doesn't end up as "strongest" / "weakest" (Tier 3A).
    for s in llm_summaries:
        per_cwe = s.get("per_cwe", [])
        scored_cwes = [
            (c.get("f1") or 0, _clean_cwe(c["cwe_id"]))
            for c in per_cwe
            if c.get("f1") is not None and (c.get("total") or 0) >= 10
        ]
        if len(scored_cwes) >= 2:
            best_cwe = max(scored_cwes)
            worst_cwe = min(scored_cwes)
            if best_cwe[0] != worst_cwe[0]:
                bullets.append(
                    f"**CWE performance** (`{s['approach']}`): "
                    f"strongest on `{best_cwe[1]}` (F1={_pct(best_cwe[0])}), "
                    f"weakest on `{worst_cwe[1]}` (F1={_pct(worst_cwe[0])})."
                )

    # Inverted-calibration warning (Tier 3B): if High-confidence predictions
    # are *less* accurate than Low, the confidence signal is misleading and
    # the headline shouldn't quietly accept it. Calibration is a dict keyed
    # by bucket name: {"High": {total, correct, accuracy}, "Low": {...}, ...}.
    for s in llm_summaries:
        cal = s.get("calibration") or {}
        high = cal.get("High") if isinstance(cal, dict) else None
        low = cal.get("Low") if isinstance(cal, dict) else None
        if (
            high
            and low
            and (high.get("total") or 0) >= 30
            and (low.get("total") or 0) >= 30
            and high.get("accuracy") is not None
            and low.get("accuracy") is not None
            and high["accuracy"] < low["accuracy"]
        ):
            bullets.append(
                f"⚠️ **Inverted confidence calibration**: `{s['approach']}` on "
                f"`{s['dataset']}` — High-confidence predictions "
                f"({_pct(high['accuracy'])}) are *less* accurate than Low "
                f"({_pct(low['accuracy'])}). The confidence signal is "
                f"misleading or noise; tighten the High threshold or "
                f"investigate adapter quality."
            )

    if not bullets:
        return ""

    lines = ["## Key Findings", ""]
    for b in bullets:
        lines.append(f"- {b}")
    return "\n".join(lines)


def _main_table(summaries: list[dict]) -> str:
    """Build the main Markdown comparison table."""
    headers = [
        "Approach", "Dataset", "Precision", "Recall", "Eff. Recall", "F1",
        "FP Reduc.", "TP Pres.", "NMD Rate",
        "Tokens/Finding", "Cost (USD)", "Latency p95 (s)",
    ]
    rows = [headers]
    rows.append(["---"] * len(headers))

    for s in summaries:
        rows.append([
            s.get("approach", "?"),
            s.get("dataset", "?"),
            _pct(s.get("precision")),
            _pct(s.get("recall")),
            _pct(s.get("effective_recall")),
            _pct(s.get("f1")),
            _pct(s.get("fp_reduction_rate")),
            _pct(s.get("tp_preservation_rate")),
            _pct(s.get("nmd_rate")),
            _num(s.get("tokens_per_finding"), 0),
            f"${s.get('total_cost_usd', 0):.4f}",
            _num(s.get("p95_latency_s")),
        ])

    table = "\n".join("| " + " | ".join(r) + " |" for r in rows)
    explanation = "\n".join([
        "> **How to read this table:**",
        "> - **Precision**: Of findings the approach labeled as vulnerabilities, what fraction are truly vulnerable.",
        ">   Higher = fewer false alarms. Target: >80% for LLM approaches.",
        "> - **Recall**: Of all truly vulnerable findings, what fraction did the approach catch.",
        ">   Higher = fewer missed bugs. Should stay >85% vs raw-sast.",
        "> - **Eff. Recall**: Recall counting NMD verdicts on TPs as misses.",
        "> - **FP Reduc.**: How many raw-SAST false positives the approach eliminated. Higher is better.",
        "> - **TP Pres.**: How many raw-SAST true positives the approach kept. Should stay >80%.",
        "> - **NMD Rate**: Fraction of findings where the LLM could not decide. >30% indicates insufficient context.",
    ])
    return table + "\n\n" + explanation


def _calibration_table(summaries: list[dict]) -> str:
    """Build calibration accuracy table."""
    lines = ["| Approach | Dataset | Confidence | Total | Correct | Accuracy |",
             "|---|---|---|---|---|---|"]
    for s in summaries:
        cal = s.get("calibration", {})
        for bucket, data in cal.items():
            lines.append(
                f"| {s.get('approach','?')} | {s.get('dataset','?')} | {bucket} "
                f"| {data.get('total','?')} | {data.get('correct','?')} "
                f"| {_pct(data.get('accuracy'))} |"
            )
    table = "\n".join(lines) if len(lines) > 2 else "_No calibration data._"
    explanation = (
        "> **How to read this table:** Within each confidence bucket (High/Medium/Low), "
        "what fraction of predictions matched the ground truth label? "
        "A well-calibrated approach should show High accuracy > Medium > Low. "
        "If High and Low accuracy are similar, the confidence scores are not meaningful."
    )
    return table + "\n\n" + explanation


def _cwe_table(summaries: list[dict]) -> str:
    """Build per-CWE breakdown table for all approaches."""
    lines = ["| Approach | CWE | Total | Precision | Recall | F1 |",
             "|---|---|---|---|---|---|"]
    for s in summaries:
        for cwe in s.get("per_cwe", []):
            cwe_label = _clean_cwe(cwe.get("cwe_id", ""))
            total = cwe.get("total")
            # Mark small buckets (n<10) so a stray "F1=66.7% on n=2" doesn't
            # look like a real signal in the report (Tier 3A).
            if isinstance(total, int) and total < 10:
                cwe_label = f"{cwe_label} *(n={total})*"
            lines.append(
                f"| {s.get('approach','?')} | {cwe_label} "
                f"| {total if total is not None else '?'} "
                f"| {_pct(cwe.get('precision'))} "
                f"| {_pct(cwe.get('recall'))} "
                f"| {_pct(cwe.get('f1'))} |"
            )
    table = "\n".join(lines) if len(lines) > 2 else "_No per-CWE data._"
    explanation = (
        "> **How to read this table:** Each row shows metrics for one approach on one CWE vulnerability class. "
        "CWEs with low F1 across all approaches are intrinsically hard for SAST to detect "
        "(complex control flow, indirect data dependencies). "
        "CWEs where vulnhunterx outperforms generic-questions show the benefit of rule-specific guided questions."
    )
    return table + "\n\n" + explanation


def _effectiveness_delta_table(summaries: list[dict]) -> str:
    """Per-CWE F1 delta: vulnhunterx minus generic-questions, sorted descending."""
    datasets = {s.get("dataset") for s in summaries}
    all_rows: list[tuple[float, str, str, str, str, str]] = []

    for dataset in sorted(datasets):
        vhx = next((s for s in summaries if s.get("approach") == "vulnhunterx" and s.get("dataset") == dataset), None)
        gq = next((s for s in summaries if s.get("approach") == "generic-questions" and s.get("dataset") == dataset), None)
        if not vhx or not gq:
            continue

        vhx_cwe = {c["cwe_id"]: c.get("f1") for c in vhx.get("per_cwe", [])}
        gq_cwe = {c["cwe_id"]: c.get("f1") for c in gq.get("per_cwe", [])}
        all_cwes = sorted(set(vhx_cwe) | set(gq_cwe))

        for cwe in all_cwes:
            vf = vhx_cwe.get(cwe)
            gf = gq_cwe.get(cwe)
            if vf is None and gf is None:
                continue
            delta = (vf or 0) - (gf or 0) if vf is not None and gf is not None else None
            delta_str = (f"+{delta*100:.1f}%" if delta > 0 else f"{delta*100:.1f}%") if delta is not None else "—"
            all_rows.append((delta or 0, dataset, cwe, _pct(gf), _pct(vf), delta_str))

    if not all_rows:
        return "_No vulnhunterx vs generic-questions comparison available._"

    all_rows.sort(key=lambda r: r[0], reverse=True)

    lines = ["| Dataset | CWE | generic-questions F1 | vulnhunterx F1 | Delta |",
             "|---|---|---|---|---|"]
    for _, dataset, cwe, gf_str, vf_str, delta_str in all_rows:
        lines.append(f"| {dataset} | {cwe} | {gf_str} | {vf_str} | {delta_str} |")

    explanation = (
        "> **How to read this table:** Delta = vulnhunterx F1 − generic-questions F1. "
        "Positive delta (green) means rule-specific questions improved accuracy for that CWE. "
        "Negative delta means generic questions performed better — consider reviewing that rule's questions."
    )
    return "\n".join(lines) + "\n\n" + explanation


def _question_coverage_table(summaries: list[dict]) -> str:
    """Show which question rules from YAML files were exercised in this run."""
    # Collect rule_ids seen in benchmark results
    seen_rules: set[str] = set()
    total_results = 0
    default_match_total = 0
    for s in summaries:
        for r in s.get("per_rule", []):
            rid = r.get("rule_id", "")
            if rid and rid != "unknown":
                seen_rules.add(rid)
        # Sum the default-match share to differentiate "no rule_ids captured"
        # from "rule_ids captured but every one fell to default".
        match_counts = s.get("question_match_counts") or {}
        for v in match_counts.values():
            total_results += int(v or 0)
        default_match_total += int(match_counts.get("default", 0) or 0)

    if not seen_rules:
        # Tier 3C: surface this loudly. Either the adapter forgot to emit
        # rule_ids (likely a regression) or the benchmark fell entirely to
        # default questions — both are red flags worth a warning, not a
        # placid "no data" placeholder.
        if total_results > 0 and default_match_total > 0:
            pct = 100.0 * default_match_total / total_results
            return (
                f"> ⚠️ **No rule IDs captured / 100% default-match** — "
                f"{default_match_total}/{total_results} findings ({pct:.0f}%) "
                f"fell to the default-question bucket. Check the responsible "
                f"adapter — empty `rule_id` on every entry forces the loader "
                f"to skip exact/prefix/lang-prefix matching and degrades "
                f"verification quality."
            )
        return (
            "> ⚠️ **No rule IDs captured** — run benchmark with current code "
            "to capture `rule_id` per finding, or check the adapter."
        )

    # Try to load all rules from the YAML files
    try:
        import sys as _sys
        from pathlib import Path as _Path
        _repo_root = _Path(__file__).resolve().parents[2]
        if str(_repo_root / "src") not in _sys.path:
            _sys.path.insert(0, str(_repo_root / "src"))
        from vuln_hunter_x.questions.loader import QuestionsLoader
        prompts_dir = _repo_root / "config" / "prompts"
        loader = QuestionsLoader(prompts_dir=prompts_dir if prompts_dir.is_dir() else None)
        all_yaml_rules = set(loader.rules)
    except Exception:
        all_yaml_rules = set()

    if not all_yaml_rules:
        # Just report what was seen
        lines = ["| Rule ID | Exercised |", "|---|---|"]
        for r in sorted(seen_rules):
            lines.append(f"| `{r}` | ✓ |")
        return "\n".join(lines)

    # Language breakdown
    lang_stats: dict[str, dict[str, int]] = {}
    for rid in all_yaml_rules:
        lang = rid.split("/")[0] if "/" in rid else "unknown"
        if lang not in lang_stats:
            lang_stats[lang] = {"total": 0, "exercised": 0}
        lang_stats[lang]["total"] += 1
        if rid in seen_rules:
            lang_stats[lang]["exercised"] += 1

    total_all = len(all_yaml_rules)
    total_seen = len(seen_rules & all_yaml_rules)

    lines = [
        f"> **Total rules in YAML**: {total_all} | **Rules exercised this run**: {total_seen} "
        f"({total_seen/total_all*100:.0f}%)",
        "",
        "| Language | Rules in YAML | Rules Exercised | Coverage |",
        "|---|---|---|---|",
    ]
    for lang in sorted(lang_stats):
        stat = lang_stats[lang]
        coverage = stat["exercised"] / stat["total"] if stat["total"] else 0
        lines.append(
            f"| {lang} | {stat['total']} | {stat['exercised']} | {_pct(coverage)} |"
        )

    # Unexercised rules (YAML has them but no benchmark hit)
    unexercised = sorted(all_yaml_rules - seen_rules)
    if unexercised:
        lines += ["", "**Unexercised rules** (defined in YAML but not matched by any finding this run):"]
        for rid in unexercised[:30]:  # cap at 30 to keep report readable
            lines.append(f"- `{rid}`")
        if len(unexercised) > 30:
            lines.append(f"- _…and {len(unexercised) - 30} more_")

    # Rules seen in results that fell back to generic (match_type = "default" or "generic")
    fallback_rules: set[str] = set()
    for s in summaries:
        for r in s.get("per_rule", []):
            if r.get("question_match_type") in ("default", "generic"):
                fallback_rules.add(r.get("rule_id", ""))
    fallback_rules.discard("")
    if fallback_rules:
        lines += ["", "**Rules using fallback questions** (no specific rule entry in YAML):"]
        for rid in sorted(fallback_rules):
            lines.append(f"- `{rid}`")

    return "\n".join(lines)


def _per_language_table(summaries: list[dict]) -> str:
    """Build per-language precision/recall/F1 table."""
    rows_found = False
    lines = ["| Approach | Dataset | Language | Total | Precision | Recall | F1 |",
             "|---|---|---|---|---|---|---|"]
    for s in summaries:
        per_lang = s.get("per_lang", [])
        for lm in per_lang:
            rows_found = True
            lines.append(
                f"| {s.get('approach','?')} | {s.get('dataset','?')} "
                f"| {lm.get('lang','?')} | {lm.get('total','?')} "
                f"| {_pct(lm.get('precision'))} "
                f"| {_pct(lm.get('recall'))} "
                f"| {_pct(lm.get('f1'))} |"
            )
    if not rows_found:
        return "_No per-language data available._"
    return "\n".join(lines)


def _question_match_table(summaries: list[dict]) -> str:
    """Show question match type distribution per approach."""
    rows_found = False
    match_types = ["exact", "normalized", "prefix", "lang_prefix", "default", "generic"]
    lines = ["| Approach | Dataset | " + " | ".join(t.title() for t in match_types) + " |",
             "|---|---|" + "---|" * len(match_types)]
    for s in summaries:
        counts = s.get("question_match_counts", {})
        if not counts:
            continue
        rows_found = True
        total = sum(counts.values()) or 1
        cells = []
        for mt in match_types:
            n = counts.get(mt, 0)
            cells.append(f"{n} ({n/total*100:.0f}%)" if n else "0")
        lines.append(f"| {s.get('approach','?')} | {s.get('dataset','?')} | " + " | ".join(cells) + " |")
    if not rows_found:
        return "_No question match data available._"

    explanation = (
        "> **How to read this table:** Shows how findings were matched to guided questions. "
        "`Exact` = rule-specific question found. `Default`/`Generic` = fell back to generic questions — "
        "these rules are candidates for adding specific guided questions."
    )
    return "\n".join(lines) + "\n\n" + explanation


def _cost_table(summaries: list[dict]) -> str:
    """Build cost and latency table."""
    headers = [
        "Approach", "Dataset", "Total Tokens", "Total Cost",
        "Mean Latency", "p95 Latency", "Iterations (mean/max)",
    ]
    rows = [headers, ["---"] * len(headers)]
    for s in summaries:
        iters = (
            f"{_num(s.get('mean_iterations'), 1)} / {s.get('max_iterations', '—')}"
        )
        real_cost = s.get("total_cost_usd", 0.0) or 0.0
        imputed = s.get("imputed_api_cost_usd")
        if imputed is not None and (real_cost == 0.0 or imputed > real_cost):
            cost_cell = f"${real_cost:.4f} (imputed ${imputed:.4f})"
        else:
            cost_cell = f"${real_cost:.4f}"
        rows.append([
            s.get("approach", "?"),
            s.get("dataset", "?"),
            str(s.get("total_tokens", 0)),
            cost_cell,
            _num(s.get("mean_latency_s")),
            _num(s.get("p95_latency_s")),
            iters,
        ])
    return "\n".join("| " + " | ".join(r) + " |" for r in rows)


def _generate_charts(summaries: list[dict], out_dir: Path) -> list[tuple[str, str]]:
    """Generate matplotlib charts if available. Returns list of (path, title) tuples."""
    try:
        import matplotlib.colors as mcolors
        import matplotlib.pyplot as plt
        import numpy as np
    except ImportError:
        logger.warning("matplotlib not installed; skipping charts. pip install matplotlib")
        return []

    charts: list[tuple[str, str]] = []
    approaches = [s.get("approach", "?") for s in summaries]

    # ── Chart 1: Precision & Recall ───────────────────────────────────────────
    precisions = [(s.get("precision") or 0) * 100 for s in summaries]
    recalls = [(s.get("recall") or 0) * 100 for s in summaries]

    x = list(range(len(approaches)))
    fig, ax = plt.subplots(figsize=(max(6, len(approaches) * 1.5), 5))
    width = 0.35
    ax.bar([xi - width / 2 for xi in x], precisions, width, label="Precision (%)", color="#4C72B0")
    ax.bar([xi + width / 2 for xi in x], recalls, width, label="Recall (%)", color="#DD8452")
    ax.set_xticks(x)
    ax.set_xticklabels(approaches, rotation=20, ha="right")
    ax.set_ylim(0, 110)
    ax.set_ylabel("Percentage")
    ax.set_title("Precision and Recall by Approach")
    ax.axhline(80, color="red", linestyle="--", linewidth=0.8, alpha=0.6, label="80% target")
    ax.legend()
    fig.tight_layout()
    p = out_dir / "precision_recall.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    charts.append((str(p), "Precision & Recall by Approach"))
    logger.info("Chart saved: %s", p)

    # ── Chart 2: F1 Score comparison ──────────────────────────────────────────
    f1_vals = [(s.get("f1") or 0) * 100 for s in summaries]
    fig, ax = plt.subplots(figsize=(max(6, len(approaches) * 1.5), 5))
    colors = ["#4C72B0" if a != "raw-sast" else "#8c8c8c" for a in approaches]
    bars = ax.bar(x, f1_vals, color=colors)
    ax.bar_label(bars, fmt="%.1f%%", padding=3, fontsize=9)
    ax.set_xticks(x)
    ax.set_xticklabels(approaches, rotation=20, ha="right")
    ax.set_ylim(0, 115)
    ax.set_ylabel("F1 Score (%)")
    ax.set_title("F1 Score by Approach\n(grey = raw-sast baseline)")
    fig.tight_layout()
    p = out_dir / "f1_comparison.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    charts.append((str(p), "F1 Score Comparison"))
    logger.info("Chart saved: %s", p)

    # ── Chart 3: FP Reduction vs TP Preservation scatter ─────────────────────
    fp_vals = [(s.get("fp_reduction_rate") or 0) * 100 for s in summaries]
    tp_vals = [(s.get("tp_preservation_rate") or 0) * 100 for s in summaries]
    fig, ax = plt.subplots(figsize=(7, 6))
    scatter_colors = ["#8c8c8c" if a == "raw-sast" else "#4C72B0" for a in approaches]
    ax.scatter(fp_vals, tp_vals, c=scatter_colors, s=120, zorder=3)
    for i, label in enumerate(approaches):
        ax.annotate(label, (fp_vals[i], tp_vals[i]),
                    textcoords="offset points", xytext=(6, 4), fontsize=9)
    # Ideal region annotation
    ax.axhline(80, color="red", linestyle="--", linewidth=0.8, alpha=0.5, label="80% TP preservation threshold")
    ax.axvline(50, color="green", linestyle="--", linewidth=0.8, alpha=0.5, label="50% FP reduction target")
    ax.set_xlabel("FP Reduction Rate (%)")
    ax.set_ylabel("TP Preservation Rate (%)")
    ax.set_title("FP Reduction vs TP Preservation\n(ideal: upper-right quadrant)")
    ax.set_xlim(-5, 105)
    ax.set_ylim(-5, 110)
    ax.legend(fontsize=8)
    # Annotate ideal quadrant
    ax.text(75, 90, "Ideal\nquadrant", fontsize=8, color="gray",
            ha="center", va="center", style="italic")
    fig.tight_layout()
    p = out_dir / "tradeoff_scatter.png"
    fig.savefig(p, dpi=120)
    plt.close(fig)
    charts.append((str(p), "FP Reduction vs TP Preservation"))
    logger.info("Chart saved: %s", p)

    # ── Chart 4: Per-CWE F1 Heatmap ──────────────────────────────────────────
    # Collect all CWEs and build matrix
    all_cwes: list[str] = []
    for s in summaries:
        for c in s.get("per_cwe", []):
            cwe = c.get("cwe_id", "")
            if cwe and cwe not in all_cwes:
                all_cwes.append(cwe)
    all_cwes = sorted(all_cwes)

    if all_cwes and len(summaries) >= 1:
        matrix = []
        for s in summaries:
            cwe_map = {c["cwe_id"]: c.get("f1") for c in s.get("per_cwe", [])}
            row = [cwe_map.get(cwe) for cwe in all_cwes]
            matrix.append(row)

        # Build numeric array, mask Nones as -1
        data_arr = [[v if v is not None else -1.0 for v in row] for row in matrix]
        data_np = np.array(data_arr, dtype=float)

        cmap = plt.cm.RdYlGn  # red=bad, green=good
        cmap_masked = cmap
        fig, ax = plt.subplots(figsize=(max(6, len(all_cwes) * 0.9), max(3, len(summaries) * 0.8 + 1.5)))
        # Plot heatmap
        im = ax.imshow(
            np.where(data_np >= 0, data_np, np.nan),
            cmap=cmap_masked, vmin=0, vmax=1, aspect="auto"
        )
        # Grey out missing values
        masked = np.ma.masked_where(data_np >= 0, np.ones_like(data_np))
        ax.imshow(masked, cmap=mcolors.ListedColormap(["#cccccc"]), vmin=0, vmax=1, aspect="auto")

        ax.set_xticks(range(len(all_cwes)))
        ax.set_xticklabels(all_cwes, rotation=40, ha="right", fontsize=8)
        ax.set_yticks(range(len(summaries)))
        ax.set_yticklabels(approaches, fontsize=9)
        ax.set_title("Per-CWE F1 Score Heatmap\n(grey = no data, red = low, green = high)")

        # Annotate cells
        for i in range(len(summaries)):
            for j in range(len(all_cwes)):
                val = data_np[i, j]
                if val >= 0:
                    ax.text(j, i, f"{val*100:.0f}%", ha="center", va="center",
                            fontsize=7, color="black" if 0.2 < val < 0.8 else "white")

        plt.colorbar(im, ax=ax, label="F1 Score", fraction=0.03)
        fig.tight_layout()
        p = out_dir / "cwe_heatmap.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        charts.append((str(p), "Per-CWE F1 Heatmap"))
        logger.info("Chart saved: %s", p)

    # ── Chart 5: Latency comparison ───────────────────────────────────────────
    llm_s = [s for s in summaries if s.get("approach") != "raw-sast" and (s.get("mean_latency_s") or 0) > 0]
    if llm_s:
        llm_approaches = [s.get("approach", "?") for s in llm_s]
        mean_lats = [s.get("mean_latency_s") or 0 for s in llm_s]
        p95_lats = [s.get("p95_latency_s") or 0 for s in llm_s]
        xpos = list(range(len(llm_approaches)))
        width = 0.35
        fig, ax = plt.subplots(figsize=(max(5, len(llm_approaches) * 1.5), 5))
        ax.bar([xi - width / 2 for xi in xpos], mean_lats, width, label="Mean latency (s)", color="#4C72B0")
        ax.bar([xi + width / 2 for xi in xpos], p95_lats, width, label="p95 latency (s)", color="#c44e52")
        ax.set_xticks(xpos)
        ax.set_xticklabels(llm_approaches, rotation=20, ha="right")
        ax.set_ylabel("Seconds per finding")
        ax.set_title("Latency by Approach (LLM approaches only)")
        ax.legend()
        fig.tight_layout()
        p = out_dir / "latency.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        charts.append((str(p), "Latency by Approach"))
        logger.info("Chart saved: %s", p)

    # ── Chart 6: Effectiveness Delta per CWE (vulnhunterx - generic-questions) ─
    datasets = {s.get("dataset") for s in summaries}
    for dataset in sorted(datasets):
        vhx = next((s for s in summaries if s.get("approach") == "vulnhunterx" and s.get("dataset") == dataset), None)
        gq = next((s for s in summaries if s.get("approach") == "generic-questions" and s.get("dataset") == dataset), None)
        if not vhx or not gq:
            continue
        vhx_cwe = {c["cwe_id"]: c.get("f1") for c in vhx.get("per_cwe", [])}
        gq_cwe = {c["cwe_id"]: c.get("f1") for c in gq.get("per_cwe", [])}
        cwes_with_both = sorted(k for k in vhx_cwe if k in gq_cwe and vhx_cwe[k] is not None and gq_cwe[k] is not None)
        if not cwes_with_both:
            continue
        deltas = [(vhx_cwe[cwe] - gq_cwe[cwe]) * 100 for cwe in cwes_with_both]
        colors_delta = ["#2ca02c" if d >= 0 else "#d62728" for d in deltas]
        fig, ax = plt.subplots(figsize=(6, max(3, len(cwes_with_both) * 0.6 + 1.5)))
        ypos = list(range(len(cwes_with_both)))
        ax.barh(ypos, deltas, color=colors_delta)
        ax.set_yticks(ypos)
        ax.set_yticklabels(cwes_with_both, fontsize=9)
        ax.axvline(0, color="black", linewidth=0.8)
        ax.set_xlabel("F1 Delta (pp) — vulnhunterx minus generic-questions")
        ax.set_title(f"Question Effectiveness by CWE\n({dataset}: green=rule questions help, red=hurts)")
        fig.tight_layout()
        p = out_dir / f"delta_{dataset}.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        charts.append((str(p), f"Effectiveness Delta by CWE ({dataset})"))
        logger.info("Chart saved: %s", p)

    # ── Chart 7: Question match type distribution ─────────────────────────────
    match_summaries = [s for s in summaries if s.get("question_match_counts")]
    if match_summaries:
        match_types = ["exact", "normalized", "prefix", "lang_prefix", "default", "generic"]
        match_labels = ["Exact", "Normalized", "Prefix", "Lang-prefix", "Default", "Generic"]
        match_colors = ["#2ca02c", "#98df8a", "#aec7e8", "#ffbb78", "#ff7f0e", "#d62728"]
        ms_approaches = [s.get("approach", "?") for s in match_summaries]
        data_matrix = []
        for s in match_summaries:
            counts = s.get("question_match_counts", {})
            data_matrix.append([counts.get(mt, 0) for mt in match_types])
        totals = [sum(row) or 1 for row in data_matrix]
        pct_matrix = [[v / totals[i] * 100 for v in row] for i, row in enumerate(data_matrix)]

        fig, ax = plt.subplots(figsize=(max(6, len(ms_approaches) * 1.5), 5))
        xpos = list(range(len(ms_approaches)))
        bottoms = [0.0] * len(ms_approaches)
        for j, (mt_label, color) in enumerate(zip(match_labels, match_colors, strict=False)):
            vals = [pct_matrix[i][j] for i in range(len(ms_approaches))]
            if any(v > 0 for v in vals):
                ax.bar(xpos, vals, bottom=bottoms, label=mt_label, color=color)
                for i, (v, b) in enumerate(zip(vals, bottoms, strict=False)):
                    if v > 5:
                        ax.text(i, b + v / 2, f"{v:.0f}%", ha="center", va="center", fontsize=7, color="white")
                bottoms = [b + v for b, v in zip(bottoms, vals, strict=False)]
        ax.set_xticks(xpos)
        ax.set_xticklabels(ms_approaches, rotation=20, ha="right")
        ax.set_ylabel("% of findings")
        ax.set_ylim(0, 110)
        ax.set_title("Question Match Type Distribution by Approach\n(green=exact rule match, red=generic fallback)")
        ax.legend(loc="upper right", fontsize=8)
        fig.tight_layout()
        p = out_dir / "question_match.png"
        fig.savefig(p, dpi=120)
        plt.close(fig)
        charts.append((str(p), "Question Match Distribution"))
        logger.info("Chart saved: %s", p)

    return charts


def generate_report(run_dir: Path, include_charts: bool = False) -> Path:
    """Generate REPORT.md in the run directory."""
    summaries = _load_results(run_dir)
    if not summaries:
        logger.error("No benchmark results found in %s", run_dir)
        sys.exit(1)

    chart_paths = _generate_charts(summaries, run_dir) if include_charts else []

    lines: list[str] = [
        "# VulnHunterX Benchmark Report",
        "",
        _run_metadata(run_dir, summaries),
        "",
        "---",
        "",
        _key_findings(summaries),
        "",
        "---",
        "",
        "## Summary Comparison",
        "",
        _main_table(summaries),
        "",
        "---",
        "",
        "## Confidence Calibration",
        "",
        _calibration_table(summaries),
        "",
        "---",
        "",
        "## Per-CWE Breakdown",
        "",
        _cwe_table(summaries),
        "",
        "---",
        "",
        "## Effectiveness Delta (vulnhunterx vs generic-questions)",
        "",
        _effectiveness_delta_table(summaries),
        "",
        "---",
        "",
        "## Per-Language Breakdown",
        "",
        _per_language_table(summaries),
        "",
        "---",
        "",
        "## Question Match Distribution",
        "",
        _question_match_table(summaries),
        "",
        "---",
        "",
        "## Question Coverage",
        "",
        _question_coverage_table(summaries),
        "",
        "---",
        "",
        "## Cost & Latency",
        "",
        _cost_table(summaries),
        "",
    ]

    if chart_paths:
        lines += ["---", "", "## Charts", ""]
        for cp, title in chart_paths:
            rel = Path(cp).relative_to(run_dir)
            lines += [f"### {title}", "", f"![{title}]({rel})", ""]

    report_path = run_dir / "REPORT.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Report written: %s", report_path)
    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="Benchmark run directory")
    parser.add_argument("--charts", action="store_true", help="Generate matplotlib charts")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        logger.error("Run directory not found: %s", run_dir)
        return 1

    report_path = generate_report(run_dir, include_charts=args.charts)
    print(f"Report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
