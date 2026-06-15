# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Metrics computation for benchmark evaluation.

Computes per-dataset and per-CWE:
  - Precision, Recall, F1 (binary: predicted TP vs FP/BENIGN)
  - FP reduction rate vs raw SAST
  - TP preservation rate vs raw SAST
  - NMD (Needs More Data) rate
  - Confidence calibration (accuracy within each confidence bucket)
  - Cost: total tokens, estimated USD, tokens-per-finding
  - Latency: mean / median / p95 elapsed_seconds, total wall-clock time
  - Iterations: mean / max (for approaches that use multi-turn)
  - Per-rule and per-language breakdowns
  - Question match type distribution
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from benchmarks.adapters.ground_truth import LABEL_BENIGN, LABEL_FP, LABEL_TP
from benchmarks.approaches.base import PRED_ERROR, PRED_FP, PRED_NMD, PRED_TP, BenchmarkResult
from benchmarks.metrics.stats import (
    f1_bootstrap_ci,
    precision_ci,
    recall_ci,
    wilson_ci,
)

# Markers that an ERROR verdict came from an LLM-API failure (rate-limit, quota,
# network) rather than a model decision. Used to separate operational misses
# from genuine model errors when reporting per-pair metrics.
_API_ERROR_MARKERS = (
    "insufficient balance",
    "rate limit",
    "ratelimiterror",
    "rate_limit_exceeded",
    "openaiexception",
    "anthropicexception",
    "litellm.",
    "apiconnectionerror",
    "apitimeouterror",
    "503 service unavailable",
    "502 bad gateway",
)


def _is_api_error(reasoning: str | None) -> bool:
    """Return True when an ERROR verdict's reasoning matches a known LLM-API
    failure signature. Heuristic match — surface false-negatives by checking
    the markers list above rather than silently miscategorising."""
    if not reasoning:
        return False
    haystack = reasoning.lower()
    return any(marker in haystack for marker in _API_ERROR_MARKERS)


@dataclass
class CWEMetrics:
    """Metrics for a single CWE class."""

    cwe_id: str
    total: int = 0
    tp_correct: int = 0   # TP label, predicted TP
    tp_missed: int = 0    # TP label, predicted FP (false negative)
    fp_caught: int = 0    # FP label, predicted FP (correctly identified)
    fp_missed: int = 0    # FP label, predicted TP (false positive kept)
    nmd: int = 0
    errors: int = 0

    @property
    def precision(self) -> float | None:
        denom = self.tp_correct + self.fp_missed
        return self.tp_correct / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp_correct + self.tp_missed
        return self.tp_correct / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)


@dataclass
class RuleMetrics:
    """Metrics for a single CodeQL/Semgrep rule ID."""

    rule_id: str
    lang: str = ""
    total: int = 0
    tp_correct: int = 0
    tp_missed: int = 0
    fp_caught: int = 0
    fp_missed: int = 0
    nmd: int = 0
    errors: int = 0

    @property
    def precision(self) -> float | None:
        denom = self.tp_correct + self.fp_missed
        return self.tp_correct / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp_correct + self.tp_missed
        return self.tp_correct / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)


@dataclass
class CalibrationBucket:
    """Accuracy within a single confidence bucket."""

    bucket: str   # "High" | "Medium" | "Low"
    total: int = 0
    correct: int = 0  # predicted label matches ground truth

    @property
    def accuracy(self) -> float | None:
        return self.correct / self.total if self.total else None


@dataclass
class ApproachMetrics:
    """Full evaluation metrics for one approach on one dataset."""

    approach_name: str
    dataset_name: str
    nmd_handling: str   # "exclude" | "fp"

    # Counts (BENIGN excluded from precision/recall)
    total_evaluated: int = 0   # TP+FP labels only (excludes NMD, ERROR, BENIGN)
    total_processed: int = 0   # all entries processed (excludes BENIGN)
    true_labels_tp: int = 0    # ground truth TP count
    true_labels_fp: int = 0    # ground truth FP count
    pred_tp: int = 0
    pred_fp: int = 0
    pred_nmd: int = 0
    pred_error: int = 0
    # Subset of pred_error caused by an LLM API failure (rate-limit, quota,
    # network). These are NOT model errors — re-running with credit available
    # is the right remedy, not prompt engineering.
    pred_api_error_count: int = 0
    nmd_tp_count: int = 0  # NMD entries whose ground truth was TP
    # Force-decision telemetry. Counts results whose reasoning carries the
    # "[Forced decision:" sentinel — i.e. cases where the LLM did not
    # produce a confident verdict in normal iteration and the engine
    # synthesized one from signal heuristics. Surfaced separately because
    # these are the canonical truncation / context-starvation failure
    # mode (2026-05-15 16:45 diversevul run).
    forced_decision_total: int = 0
    forced_decision_defaulted_fp: int = 0   # "defaulted to FP" sentinel
    forced_decision_leaned_tp: int = 0      # "evidence leans toward TP" sentinel

    # Core accuracy
    tp_correct: int = 0    # label=TP, predicted TP
    tp_missed: int = 0     # label=TP, predicted FP (fn)
    fp_caught: int = 0     # label=FP, predicted FP (tn)
    fp_missed: int = 0     # label=FP, predicted TP

    # Per-CWE breakdown
    cwe_metrics: dict[str, CWEMetrics] = field(default_factory=dict)

    # Per-rule breakdown
    rule_metrics: dict[str, RuleMetrics] = field(default_factory=dict)

    # Per-language breakdown (reuses CWEMetrics structure, keyed by lang)
    lang_metrics: dict[str, CWEMetrics] = field(default_factory=dict)

    # Question match type distribution
    question_match_counts: dict[str, int] = field(default_factory=dict)

    # Calibration
    calibration: dict[str, CalibrationBucket] = field(default_factory=dict)
    # Iteration × confidence calibration. Buckets keyed by "<iters>/<conf>"
    # (e.g. "1/High"). The 2026-05-15 benchmark identified 1-iter High-
    # confidence as the failure mode invisible to the flat confidence
    # report; this matrix surfaces it.
    iteration_calibration: dict[str, CalibrationBucket] = field(default_factory=dict)

    # Cost & latency. total_cost_usd is the real provider-reported cost
    # (~0 for Ollama / models LiteLLM has no price for).
    total_tokens: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost_usd: float = 0.0
    elapsed_seconds: list[float] = field(default_factory=list)
    total_elapsed: float = 0.0
    # Per-pair wall-clock duration measured by the runner. Under sequential
    # execution this ≈ total_elapsed; under parallel execution
    # (run_benchmark.py -j N) it equals the actual elapsed time, while
    # total_elapsed continues to sum per-entry durations (cumulative compute).
    wall_seconds: float | None = None

    # Iterations (multi-turn approaches)
    iterations_list: list[int] = field(default_factory=list)

    # Per-finding (gt_label, pred_label) tuples (1=TP, 0=FP) for paired
    # comparisons (McNemar) and bootstrap CIs. BENIGN/NMD/ERROR excluded.
    # Each entry is keyed by a stable finding id so two approaches can be
    # paired item-by-item across runs.
    per_finding_outcomes: dict[str, tuple[int, int]] = field(default_factory=dict)

    # ---- Computed metrics ----

    @property
    def precision(self) -> float | None:
        denom = self.tp_correct + self.fp_missed
        return self.tp_correct / denom if denom else None

    @property
    def recall(self) -> float | None:
        denom = self.tp_correct + self.tp_missed
        return self.tp_correct / denom if denom else None

    @property
    def effective_recall(self) -> float | None:
        """Recall including NMD-TPs as missed: tp_correct / (tp_correct + tp_missed + nmd_tp_count)."""
        denom = self.tp_correct + self.tp_missed + self.nmd_tp_count
        return self.tp_correct / denom if denom else None

    @property
    def f1(self) -> float | None:
        p, r = self.precision, self.recall
        if p is None or r is None or (p + r) == 0:
            return None
        return 2 * p * r / (p + r)

    @property
    def nmd_rate(self) -> float | None:
        """Fraction of all processed findings (excl BENIGN) that returned NMD."""
        return self.pred_nmd / self.total_processed if self.total_processed else None

    @property
    def error_rate(self) -> float | None:
        return self.pred_error / self.total_processed if self.total_processed else None

    @property
    def tokens_per_finding(self) -> float | None:
        return self.total_tokens / self.total_evaluated if self.total_evaluated else None

    @property
    def mean_latency(self) -> float | None:
        return statistics.mean(self.elapsed_seconds) if self.elapsed_seconds else None

    @property
    def median_latency(self) -> float | None:
        return statistics.median(self.elapsed_seconds) if self.elapsed_seconds else None

    @property
    def p95_latency(self) -> float | None:
        if not self.elapsed_seconds:
            return None
        sorted_vals = sorted(self.elapsed_seconds)
        idx = int(len(sorted_vals) * 0.95)
        return sorted_vals[min(idx, len(sorted_vals) - 1)]

    @property
    def mean_iterations(self) -> float | None:
        return statistics.mean(self.iterations_list) if self.iterations_list else None

    @property
    def max_iterations(self) -> int | None:
        return max(self.iterations_list) if self.iterations_list else None

    # ---- Statistical CIs (Wilson + bootstrap) ----

    def precision_ci(self, confidence: float = 0.95) -> tuple[float, float] | None:
        """Wilson CI for precision = tp / (tp + fp)."""
        return precision_ci(self.tp_correct, self.fp_missed, confidence)

    def recall_ci(self, confidence: float = 0.95) -> tuple[float, float] | None:
        """Wilson CI for recall = tp / (tp + fn)."""
        return recall_ci(self.tp_correct, self.tp_missed, confidence)

    def f1_ci(
        self,
        n_resamples: int = 10_000,
        confidence: float = 0.95,
        rng_seed: int | None = 1729,
    ) -> tuple[float, float, float] | None:
        """Bootstrap CI for F1 over per-finding outcomes."""
        if not self.per_finding_outcomes:
            return None
        outcomes = list(self.per_finding_outcomes.values())
        return f1_bootstrap_ci(
            per_finding=outcomes,
            n_resamples=n_resamples,
            confidence=confidence,
            rng_seed=rng_seed,
        )

    def fp_reduction_ci(
        self,
        raw_sast_fp_count: int,
        confidence: float = 0.95,
    ) -> tuple[float, float] | None:
        """Wilson CI for FP-reduction rate.

        Treats reduction as a binomial (#FPs eliminated out of #raw FPs).
        """
        if raw_sast_fp_count == 0:
            return None
        eliminated = raw_sast_fp_count - self.fp_missed
        eliminated = max(0, min(eliminated, raw_sast_fp_count))
        return wilson_ci(eliminated, raw_sast_fp_count, confidence)

    def fp_reduction_rate(self, raw_sast_fp_count: int) -> float | None:
        """FP reduction vs raw SAST: (SAST_FPs - Approach_FPs) / SAST_FPs."""
        if raw_sast_fp_count == 0:
            return None
        reduced = raw_sast_fp_count - self.fp_missed
        return reduced / raw_sast_fp_count

    def tp_preservation_rate(self, raw_sast_tp_count: int) -> float | None:
        """TP preservation vs raw SAST: approach_TPs / SAST_TPs."""
        if raw_sast_tp_count == 0:
            return None
        return self.tp_correct / raw_sast_tp_count

    def summary_dict(
        self,
        raw_sast_tp: int | None = None,
        raw_sast_fp: int | None = None,
    ) -> dict[str, Any]:
        """Render this approach's metrics as a dict.

        Args:
          raw_sast_tp / raw_sast_fp: counts from the raw-SAST baseline so
              FP-reduction and TP-preservation can be computed.
        """
        d: dict[str, Any] = {
            "approach": self.approach_name,
            "dataset": self.dataset_name,
            "nmd_handling": self.nmd_handling,
            "total_evaluated": self.total_evaluated,
            "total_processed": self.total_processed,
            "precision": _fmt(self.precision),
            "recall": _fmt(self.recall),
            "f1": _fmt(self.f1),
            "effective_recall": _fmt(self.effective_recall),
            "nmd_rate": _fmt(self.nmd_rate),
            "error_rate": _fmt(self.error_rate),
            "pred_error": self.pred_error,
            "pred_api_error_count": self.pred_api_error_count,
            "forced_decision_total": self.forced_decision_total,
            "forced_decision_defaulted_fp": self.forced_decision_defaulted_fp,
            "forced_decision_leaned_tp": self.forced_decision_leaned_tp,
            "total_tokens": self.total_tokens,
            "total_input_tokens": self.total_input_tokens,
            "total_output_tokens": self.total_output_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "tokens_per_finding": _fmt(self.tokens_per_finding),
            "total_elapsed_s": round(self.total_elapsed, 2),
            "wall_seconds": (
                round(self.wall_seconds, 2) if self.wall_seconds is not None else None
            ),
            "mean_latency_s": _fmt(self.mean_latency),
            "median_latency_s": _fmt(self.median_latency),
            "p95_latency_s": _fmt(self.p95_latency),
            "mean_iterations": _fmt(self.mean_iterations),
            "max_iterations": self.max_iterations,
        }
        if raw_sast_tp is not None:
            d["tp_preservation_rate"] = _fmt(self.tp_preservation_rate(raw_sast_tp))
        if raw_sast_fp is not None:
            d["fp_reduction_rate"] = _fmt(self.fp_reduction_rate(raw_sast_fp))
            fp_red_ci = self.fp_reduction_ci(raw_sast_fp)
            if fp_red_ci is not None:
                d["fp_reduction_ci95"] = [_fmt(fp_red_ci[0]), _fmt(fp_red_ci[1])]

        # Statistical CIs (Wilson + bootstrap). Bootstrap is opt-in via env
        # to keep summary_dict() fast for the common reporting path; callers
        # who want F1 CIs should call self.f1_ci() directly.
        p_ci = self.precision_ci()
        r_ci = self.recall_ci()
        d["precision_ci95"] = (
            [_fmt(p_ci[0]), _fmt(p_ci[1])] if p_ci is not None else None
        )
        d["recall_ci95"] = (
            [_fmt(r_ci[0]), _fmt(r_ci[1])] if r_ci is not None else None
        )

        # Calibration
        cal: dict[str, Any] = {}
        for bucket, cb in self.calibration.items():
            cal[bucket] = {
                "total": cb.total,
                "correct": cb.correct,
                "accuracy": _fmt(cb.accuracy),
            }
        d["calibration"] = cal

        # Iteration × confidence calibration (sorted by iter then confidence
        # for stable diffing across runs).
        def _cal_sort_key(item: tuple[str, Any]) -> tuple[int, int]:
            key, _ = item
            try:
                iters_str, conf = key.split("/", 1)
                iters = int(iters_str)
            except (ValueError, AttributeError):
                iters, conf = 0, key
            conf_rank = {"High": 0, "Medium": 1, "Low": 2}.get(conf, 3)
            return (iters, conf_rank)

        iter_cal: dict[str, Any] = {}
        for bucket, cb in sorted(
            self.iteration_calibration.items(), key=_cal_sort_key,
        ):
            iter_cal[bucket] = {
                "total": cb.total,
                "correct": cb.correct,
                "accuracy": _fmt(cb.accuracy),
            }
        d["iteration_calibration"] = iter_cal

        # Per-CWE
        cwe_summary = []
        for cwe_id, cm in sorted(self.cwe_metrics.items()):
            cwe_summary.append(
                {
                    "cwe_id": cwe_id,
                    "total": cm.total,
                    "precision": _fmt(cm.precision),
                    "recall": _fmt(cm.recall),
                    "f1": _fmt(cm.f1),
                    # SAST-FPs the approach failed to filter out
                    # (counted as TP). Surfaced because per-CWE precision
                    # can hide whether the residual error is "missed
                    # one" or "missed all" on small buckets.
                    "fp_missed": cm.fp_missed,
                    "fp_total": cm.fp_caught + cm.fp_missed,
                }
            )
        d["per_cwe"] = cwe_summary

        # Per-rule
        rule_summary = []
        for rule_id, rm in sorted(self.rule_metrics.items()):
            rule_summary.append(
                {
                    "rule_id": rule_id,
                    "lang": rm.lang,
                    "total": rm.total,
                    "precision": _fmt(rm.precision),
                    "recall": _fmt(rm.recall),
                    "f1": _fmt(rm.f1),
                }
            )
        d["per_rule"] = rule_summary

        # Per-language
        lang_summary = []
        for lang, lm in sorted(self.lang_metrics.items()):
            lang_summary.append(
                {
                    "lang": lang,
                    "total": lm.total,
                    "precision": _fmt(lm.precision),
                    "recall": _fmt(lm.recall),
                    "f1": _fmt(lm.f1),
                }
            )
        d["per_lang"] = lang_summary

        # Question match type distribution
        d["question_match_counts"] = dict(self.question_match_counts)

        return d


def evaluate(
    results: list[BenchmarkResult],
    approach_name: str,
    dataset_name: str,
    nmd_handling: str = "exclude",
) -> ApproachMetrics:
    """Compute metrics for a list of BenchmarkResult objects.

    Args:
        results: Results from one approach on one dataset.
        approach_name: Approach identifier string.
        dataset_name: Dataset identifier string.
        nmd_handling: "exclude" (NMD excluded from precision/recall) or
                      "fp" (NMD counted as FP prediction).

    Returns:
        ApproachMetrics with all computed values.
    """
    metrics = ApproachMetrics(
        approach_name=approach_name,
        dataset_name=dataset_name,
        nmd_handling=nmd_handling,
    )

    for r in results:
        # Track question match type distribution for all results
        match_type = getattr(r, "question_match_type", "") or ""
        if match_type:
            metrics.question_match_counts[match_type] = (
                metrics.question_match_counts.get(match_type, 0) + 1
            )

        # Force-decision telemetry. The LLM client tags fallback verdicts
        # with one of two sentinels in the reasoning text — see
        # llm/client.py:_force_decision_turn.
        reasoning_str = r.reasoning or ""
        if "[Forced decision:" in reasoning_str:
            metrics.forced_decision_total += 1
            if "defaulted to FP" in reasoning_str:
                metrics.forced_decision_defaulted_fp += 1
            elif "evidence leans toward TP" in reasoning_str:
                metrics.forced_decision_leaned_tp += 1

        # Resolve NMD based on nmd_handling policy
        pred = r.predicted_label
        if pred == PRED_NMD:
            if nmd_handling == "fp":
                pred = PRED_FP
            else:
                metrics.pred_nmd += 1
                if r.entry.label == LABEL_TP:
                    metrics.nmd_tp_count += 1
                metrics.total_processed += 1
                metrics.elapsed_seconds.append(r.elapsed_seconds)
                metrics.total_elapsed += r.elapsed_seconds
                metrics.total_tokens += r.tokens_used
                metrics.total_input_tokens += r.input_tokens
                metrics.total_output_tokens += r.output_tokens
                metrics.total_cost_usd += r.cost_usd
                if r.iterations:
                    metrics.iterations_list.append(r.iterations)
                continue  # exclude from precision/recall

        if pred == PRED_ERROR:
            metrics.pred_error += 1
            if _is_api_error(r.reasoning):
                metrics.pred_api_error_count += 1
            metrics.total_processed += 1
            metrics.elapsed_seconds.append(r.elapsed_seconds)
            metrics.total_elapsed += r.elapsed_seconds
            metrics.total_tokens += r.tokens_used
            metrics.total_input_tokens += r.input_tokens
            metrics.total_output_tokens += r.output_tokens
            metrics.total_cost_usd += r.cost_usd
            if r.iterations:
                metrics.iterations_list.append(r.iterations)
            continue

        gt_label = r.entry.label

        # BENIGN entries are tracked for cost/latency but excluded from accuracy
        if gt_label == LABEL_BENIGN:
            metrics.elapsed_seconds.append(r.elapsed_seconds)
            metrics.total_elapsed += r.elapsed_seconds
            metrics.total_tokens += r.tokens_used
            metrics.total_input_tokens += r.input_tokens
            metrics.total_output_tokens += r.output_tokens
            metrics.total_cost_usd += r.cost_usd
            if r.iterations:
                metrics.iterations_list.append(r.iterations)
            continue

        # Only TP and FP labels reach here for accuracy metrics
        metrics.total_evaluated += 1
        metrics.total_processed += 1
        metrics.elapsed_seconds.append(r.elapsed_seconds)
        metrics.total_elapsed += r.elapsed_seconds
        metrics.total_tokens += r.tokens_used
        metrics.total_input_tokens += r.input_tokens
        metrics.total_output_tokens += r.output_tokens
        metrics.total_cost_usd += r.cost_usd
        if r.iterations:
            metrics.iterations_list.append(r.iterations)

        if pred == PRED_TP:
            metrics.pred_tp += 1
        else:
            metrics.pred_fp += 1

        # Per-finding paired outcome (1=TP, 0=FP) for McNemar / bootstrap.
        gt_bin = 1 if gt_label == LABEL_TP else 0
        pred_bin = 1 if pred == PRED_TP else 0
        metrics.per_finding_outcomes[r.entry.id] = (gt_bin, pred_bin)

        # Confusion matrix
        if gt_label == LABEL_TP:
            metrics.true_labels_tp += 1
            if pred == PRED_TP:
                metrics.tp_correct += 1
            else:
                metrics.tp_missed += 1
        elif gt_label == LABEL_FP:
            metrics.true_labels_fp += 1
            if pred == PRED_FP:
                metrics.fp_caught += 1
            else:
                metrics.fp_missed += 1

        # Per-CWE metrics
        cwe = r.entry.cwe_id or "Unknown"
        if cwe not in metrics.cwe_metrics:
            metrics.cwe_metrics[cwe] = CWEMetrics(cwe_id=cwe)
        cm = metrics.cwe_metrics[cwe]
        cm.total += 1
        if gt_label == LABEL_TP:
            if pred == PRED_TP:
                cm.tp_correct += 1
            else:
                cm.tp_missed += 1
        elif gt_label == LABEL_FP:
            if pred == PRED_FP:
                cm.fp_caught += 1
            else:
                cm.fp_missed += 1

        # Per-rule metrics
        rule = r.entry.rule_id or "unknown"
        lang = r.entry.lang or "unknown"
        if rule not in metrics.rule_metrics:
            metrics.rule_metrics[rule] = RuleMetrics(rule_id=rule, lang=lang)
        rm = metrics.rule_metrics[rule]
        rm.total += 1
        if gt_label == LABEL_TP:
            if pred == PRED_TP:
                rm.tp_correct += 1
            else:
                rm.tp_missed += 1
        elif gt_label == LABEL_FP:
            if pred == PRED_FP:
                rm.fp_caught += 1
            else:
                rm.fp_missed += 1

        # Per-language metrics (reuse CWEMetrics structure)
        if lang not in metrics.lang_metrics:
            metrics.lang_metrics[lang] = CWEMetrics(cwe_id=lang)
        lm = metrics.lang_metrics[lang]
        lm.total += 1
        if gt_label == LABEL_TP:
            if pred == PRED_TP:
                lm.tp_correct += 1
            else:
                lm.tp_missed += 1
        elif gt_label == LABEL_FP:
            if pred == PRED_FP:
                lm.fp_caught += 1
            else:
                lm.fp_missed += 1

        # Calibration
        confidence = r.confidence or "Unknown"
        if confidence not in metrics.calibration:
            metrics.calibration[confidence] = CalibrationBucket(bucket=confidence)
        cb = metrics.calibration[confidence]
        cb.total += 1
        is_correct = (pred == PRED_TP and gt_label == LABEL_TP) or (
            pred == PRED_FP and gt_label == LABEL_FP
        )
        if is_correct:
            cb.correct += 1

        # Iteration × confidence calibration. "0" iterations means the
        # approach reported no iteration count (e.g. raw-sast).
        iter_key = f"{r.iterations or 0}/{confidence}"
        if iter_key not in metrics.iteration_calibration:
            metrics.iteration_calibration[iter_key] = CalibrationBucket(bucket=iter_key)
        ib = metrics.iteration_calibration[iter_key]
        ib.total += 1
        if is_correct:
            ib.correct += 1

    return metrics


def _fmt(val: float | None, decimals: int = 4) -> float | None:
    if val is None:
        return None
    return round(val, decimals)


def compare_approaches_mcnemar(
    a: ApproachMetrics, b: ApproachMetrics
) -> dict[str, Any]:
    """McNemar's test on two ApproachMetrics evaluated on the same dataset.

    Pairs items by `entry.id`; only items present in BOTH approaches'
    `per_finding_outcomes` are tested. Returns a dict suitable for direct
    JSON serialization in the benchmark report.
    """
    from benchmarks.metrics.stats import mcnemar

    common = set(a.per_finding_outcomes) & set(b.per_finding_outcomes)
    a_correct_b_wrong = 0
    a_wrong_b_correct = 0
    both_correct = 0
    both_wrong = 0
    for fid in common:
        gt_a, pred_a = a.per_finding_outcomes[fid]
        gt_b, pred_b = b.per_finding_outcomes[fid]
        # Truth must agree across approaches; if it doesn't, skip the pair.
        if gt_a != gt_b:
            continue
        ca = pred_a == gt_a
        cb = pred_b == gt_b
        if ca and not cb:
            a_correct_b_wrong += 1
        elif cb and not ca:
            a_wrong_b_correct += 1
        elif ca and cb:
            both_correct += 1
        else:
            both_wrong += 1
    result = mcnemar(a_correct_b_wrong, a_wrong_b_correct)
    return {
        "approach_a": a.approach_name,
        "approach_b": b.approach_name,
        "n_paired": len(common),
        "both_correct": both_correct,
        "both_wrong": both_wrong,
        "a_correct_b_wrong": a_correct_b_wrong,
        "a_wrong_b_correct": a_wrong_b_correct,
        "statistic": result.statistic,
        "p_value": _fmt(result.p_value, decimals=6),
        "method": result.method,
    }
