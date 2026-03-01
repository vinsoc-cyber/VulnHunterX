"""VulnHunterX full approach: per-language guided questions + multi-turn LLM."""

from __future__ import annotations

import time
from pathlib import Path

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
from benchmarks.approaches.single_shot import _dry_run_result

# Default prompts directory containing all per-language *_questions.yaml files
_PROMPTS_DIR = (
    Path(__file__).resolve().parents[2] / "config" / "prompts"
)


class VulnHunterXApproach(BenchmarkApproach):
    """Approach 4 — the system under test.

    Uses the full VulnHunterX pipeline:
    - Rule-specific guided questions from per-language *_questions.yaml files
    - Multi-turn LLM conversation with context expansion (up to max_iterations)
    """

    name = "vulnhunterx"

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        max_iterations: int = 3,
        prompts_dir: Path | None = None,
        dry_run: bool = False,
    ) -> None:
        self._provider = provider
        self._model = model
        self._max_iterations = max_iterations
        self._dry_run = dry_run

        # Load all per-language guided questions
        prompts_dir = prompts_dir or _PROMPTS_DIR
        self._questions_loader = QuestionsLoader(prompts_dir=prompts_dir)

    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        if self._dry_run:
            return _dry_run_result(entry, self.name)

        start = time.monotonic()
        finding = entry_to_finding(entry)

        config = Config.from_dict(
            {
                "provider": self._provider,
                "model": self._model,
                "max_iterations": self._max_iterations,
                "verbosity": "quiet",
            }
        )

        engine = VerificationEngine(
            config=config,
            questions_loader=self._questions_loader,
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
