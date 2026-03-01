"""Raw SAST baseline: treat every flagged finding as True Positive (no LLM)."""

from __future__ import annotations

import time

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches.base import PRED_TP, BenchmarkApproach, BenchmarkResult


class RawSastApproach(BenchmarkApproach):
    """Baseline 1: every finding is a TP.

    This measures CodeQL/Semgrep's native precision and establishes the upper bound
    on recall. The FP reduction rate of LLM-based approaches is measured relative
    to this baseline.
    """

    name = "raw-sast"

    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        start = time.monotonic()
        return BenchmarkResult(
            entry=entry,
            predicted_label=PRED_TP,
            confidence="High",
            reasoning="Raw SAST: every flagged finding is treated as True Positive.",
            elapsed_seconds=time.monotonic() - start,
            tokens_used=0,
            cost_usd=0.0,
            iterations=0,
        )
