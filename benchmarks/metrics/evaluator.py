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
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from typing import Any

from benchmarks.adapters.ground_truth import LABEL_BENIGN, LABEL_FP, LABEL_TP
from benchmarks.approaches.base import PRED_ERROR, PRED_FP, PRED_NMD, PRED_TP, BenchmarkResult


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

    # Core accuracy
    tp_correct: int = 0    # label=TP, predicted TP
    tp_missed: int = 0     # label=TP, predicted FP (fn)
    fp_caught: int = 0     # label=FP, predicted FP (tn)
    fp_missed: int = 0     # label=FP, predicted TP

    # Per-CWE breakdown
    cwe_metrics: dict[str, CWEMetrics] = field(default_factory=dict)

    # Calibration
    calibration: dict[str, CalibrationBucket] = field(default_factory=dict)

    # Cost & latency
    total_tokens: int = 0
    total_cost_usd: float = 0.0
    elapsed_seconds: list[float] = field(default_factory=list)
    total_elapsed: float = 0.0

    # Iterations (multi-turn approaches)
    iterations_list: list[int] = field(default_factory=list)

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
        d: dict[str, Any] = {
            "approach": self.approach_name,
            "dataset": self.dataset_name,
            "nmd_handling": self.nmd_handling,
            "total_evaluated": self.total_evaluated,
            "precision": _fmt(self.precision),
            "recall": _fmt(self.recall),
            "f1": _fmt(self.f1),
            "nmd_rate": _fmt(self.nmd_rate),
            "error_rate": _fmt(self.error_rate),
            "total_tokens": self.total_tokens,
            "total_cost_usd": round(self.total_cost_usd, 4),
            "tokens_per_finding": _fmt(self.tokens_per_finding),
            "total_elapsed_s": round(self.total_elapsed, 2),
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

        # Calibration
        cal: dict[str, Any] = {}
        for bucket, cb in self.calibration.items():
            cal[bucket] = {
                "total": cb.total,
                "correct": cb.correct,
                "accuracy": _fmt(cb.accuracy),
            }
        d["calibration"] = cal

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
                }
            )
        d["per_cwe"] = cwe_summary

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
        # Resolve NMD based on nmd_handling policy
        pred = r.predicted_label
        if pred == PRED_NMD:
            if nmd_handling == "fp":
                pred = PRED_FP
            else:
                metrics.pred_nmd += 1
                metrics.total_processed += 1
                metrics.elapsed_seconds.append(r.elapsed_seconds)
                metrics.total_elapsed += r.elapsed_seconds
                metrics.total_tokens += r.tokens_used
                metrics.total_cost_usd += r.cost_usd
                if r.iterations:
                    metrics.iterations_list.append(r.iterations)
                continue  # exclude from precision/recall

        if pred == PRED_ERROR:
            metrics.pred_error += 1
            metrics.total_processed += 1
            metrics.elapsed_seconds.append(r.elapsed_seconds)
            metrics.total_elapsed += r.elapsed_seconds
            metrics.total_tokens += r.tokens_used
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
        metrics.total_cost_usd += r.cost_usd
        if r.iterations:
            metrics.iterations_list.append(r.iterations)

        if pred == PRED_TP:
            metrics.pred_tp += 1
        else:
            metrics.pred_fp += 1

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

        # Calibration
        confidence = r.confidence or "Unknown"
        if confidence not in metrics.calibration:
            metrics.calibration[confidence] = CalibrationBucket(bucket=confidence)
        cb = metrics.calibration[confidence]
        cb.total += 1
        # "correct" means predicted label matches ground truth label
        if (pred == PRED_TP and gt_label == LABEL_TP) or (
            pred == PRED_FP and gt_label == LABEL_FP
        ):
            cb.correct += 1

    return metrics


def _fmt(val: float | None, decimals: int = 4) -> float | None:
    if val is None:
        return None
    return round(val, decimals)
