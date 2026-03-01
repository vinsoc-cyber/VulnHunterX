"""Single-shot LLM baseline: one LLM call, no guided questions, no multi-turn."""

from __future__ import annotations

import time

from vuln_hunter_x.core.config import Config
from vuln_hunter_x.questions.loader import QuestionsLoader
from vuln_hunter_x.verification.engine import VerificationEngine

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches.base import (
    BenchmarkApproach,
    BenchmarkResult,
    _SnippetContextExtractor,
    entry_to_finding,
    verdict_to_pred,
)


class SingleShotApproach(BenchmarkApproach):
    """Baseline 2: SecLLMHolmes-style single-shot evaluation.

    Sends one prompt to the LLM with the code snippet + generic question.
    No multi-turn, no rule-specific guided questions.
    Reuses VerificationEngine with max_iterations=1 and a bare QuestionsLoader.
    """

    name = "single-shot"

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        dry_run: bool = False,
    ) -> None:
        self._provider = provider
        self._model = model
        self._dry_run = dry_run

    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        if self._dry_run:
            return _dry_run_result(entry, self.name)

        start = time.monotonic()
        finding = entry_to_finding(entry)

        # No prompts_dir: uses only generic fallback questions
        questions_loader = QuestionsLoader(prompts_dir=None)

        config = Config.from_dict(
            {
                "provider": self._provider,
                "model": self._model,
                "max_iterations": 1,
                "verbosity": "quiet",
            }
        )

        engine = VerificationEngine(
            config=config,
            questions_loader=questions_loader,
            context_extractor=_SnippetContextExtractor(
                entry.code_snippet, entry.function_name
            ),
            context_provider=None,
        )

        result = engine.verify_findings([finding])
        elapsed = time.monotonic() - start

        if not result.verdicts:
            return BenchmarkResult(
                entry=entry,
                predicted_label="ERROR",
                confidence="",
                reasoning="No verdict returned",
                elapsed_seconds=elapsed,
            )

        v = result.verdicts[0]
        return BenchmarkResult(
            entry=entry,
            predicted_label=verdict_to_pred(v.verdict),
            confidence=v.confidence,
            reasoning=v.reasoning,
            elapsed_seconds=elapsed,
            iterations=v.iterations,
            raw_response=v.raw_response,
        )


def _dry_run_result(entry: GroundTruthEntry, approach_name: str) -> BenchmarkResult:
    """Return a deterministic mock result for dry-run testing."""
    import hashlib

    seed = int(hashlib.md5(entry.id.encode()).hexdigest()[:4], 16) % 3  # noqa: S324
    labels = ["TP", "FP", "NMD"]
    return BenchmarkResult(
        entry=entry,
        predicted_label=labels[seed],
        confidence="Medium",
        reasoning=f"[dry-run] {approach_name} mock result",
        elapsed_seconds=0.001,
        tokens_used=0,
        cost_usd=0.0,
        iterations=1,
    )
