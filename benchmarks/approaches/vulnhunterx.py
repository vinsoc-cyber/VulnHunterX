# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

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
    _dry_run_result,
    entry_to_finding,
    verdict_to_pred,
)

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
        force_decision: bool = True,
        use_slicing: bool = False,
    ) -> None:
        self._provider = provider
        self._model = model
        self._max_iterations = max_iterations
        self._dry_run = dry_run
        self._force_decision = force_decision
        self._use_slicing = use_slicing

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
                "force_decision": self._force_decision,
            }
        )

        engine = VerificationEngine(
            config=config,
            questions_loader=self._questions_loader,
            context_extractor=_SnippetContextExtractor(
                entry.code_snippet, entry.function_name,
                use_slicing=self._use_slicing, finding=finding,
            ),
            context_provider=None,
            # Benchmark mode feeds one finding per engine call; the outer
            # benchmark runner is what fans out across entries, so pin
            # engine-level parallelism off to avoid a hidden second layer.
            jobs=1,
        )

        _, match_type = self._questions_loader.get_questions_with_match_info(finding.rule_id)

        result = engine.verify_findings([finding])
        elapsed = time.monotonic() - start

        if not result.verdicts:
            return BenchmarkResult(
                entry=entry,
                predicted_label="ERROR",
                confidence="",
                reasoning="No verdict returned",
                elapsed_seconds=elapsed,
                question_match_type=match_type,
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
            tokens_used=v.tokens_used,
            input_tokens=v.input_tokens,
            output_tokens=v.output_tokens,
            cached_input_tokens=v.cached_input_tokens,
            cost_usd=v.cost_usd,
            question_match_type=match_type,
        )
