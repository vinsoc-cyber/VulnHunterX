"""Generic-questions baseline: multi-turn LLM but only default_questions.yaml."""

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

# Path to just the fallback questions file (no language-specific rules)
_DEFAULT_QUESTIONS_FILE = (
    Path(__file__).resolve().parents[2]
    / "config"
    / "prompts"
    / "default_questions.yaml"
)


class GenericQuestionsApproach(BenchmarkApproach):
    """Baseline 3: multi-turn VerificationEngine with only default_questions.yaml.

    This isolates the contribution of rule-specific guided questions vs.
    the multi-turn context expansion mechanism alone.
    """

    name = "generic-questions"

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        max_iterations: int = 3,
        dry_run: bool = False,
    ) -> None:
        self._provider = provider
        self._model = model
        self._max_iterations = max_iterations
        self._dry_run = dry_run

        # Build a QuestionsLoader that knows only the default questions
        self._questions_loader = QuestionsLoader(prompts_dir=None)
        if _DEFAULT_QUESTIONS_FILE.is_file():
            self._questions_loader.load_from_file(_DEFAULT_QUESTIONS_FILE)

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
