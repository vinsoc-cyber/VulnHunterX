# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Ablation study approach: compare rule-specific vs generic vs zero-shot questions.

Runs the same finding through three question variants to isolate the contribution
of guided questions to accuracy:

  Variant A (vulnhunterx)  — rule-specific questions from *_questions.yaml
  Variant B (generic)      — only default_questions.yaml (generic fallback)
  Variant C (zero-shot)    — no guided questions at all

Each variant produces its own BenchmarkResult. The ablation approach registers
all three under the names "ablation-specific", "ablation-generic", "ablation-zero"
so they appear as separate rows in the benchmark report.

Usage:
    python benchmarks/scripts/run_benchmark.py \\
        --dataset juliet --approach ablation --limit 24
"""

from __future__ import annotations

import time
from pathlib import Path

from vuln_hunter_x.core.config import Config
from vuln_hunter_x.core.types import GuidedQuestions
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

# Default prompts directory (all language-specific YAMLs)
_PROMPTS_DIR = Path(__file__).resolve().parents[2] / "config" / "prompts"
_DEFAULT_QUESTIONS_FILE = _PROMPTS_DIR / "default_questions.yaml"


class AblationApproach(BenchmarkApproach):
    """Runs each finding through three question variants and returns all three results.

    Because BenchmarkApproach.evaluate() returns a single BenchmarkResult, this
    class exposes evaluate_all() which returns a list of three results.  The
    evaluate() method returns only the vulnhunterx (Variant A) result for
    compatibility with the standard benchmark runner loop.

    To capture all three variants, call evaluate_all() directly or use
    run_benchmark.py with --approach ablation (which calls evaluate_all via the
    ablation-aware branch in the runner).
    """

    name = "ablation"

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

        # Variant A: full rule-specific questions
        self._loader_specific = QuestionsLoader(prompts_dir=_PROMPTS_DIR)

        # Variant B: only generic default questions
        self._loader_generic = QuestionsLoader(prompts_dir=None)
        if _DEFAULT_QUESTIONS_FILE.is_file():
            self._loader_generic.load_from_file(_DEFAULT_QUESTIONS_FILE)

        # Variant C: zero-shot (empty question list — loader returns programmatic fallback
        # but we override to empty)
        self._loader_zero = QuestionsLoader(prompts_dir=None)  # no questions loaded

    def _make_config(self) -> Config:
        return Config.from_dict({
            "provider": self._provider,
            "model": self._model,
            "max_iterations": self._max_iterations,
            "verbosity": "quiet",
            "force_decision": True,
        })

    def _run_variant(
        self,
        entry: GroundTruthEntry,
        loader: QuestionsLoader,
        variant_name: str,
        match_type_override: str = "",
    ) -> BenchmarkResult:
        finding = entry_to_finding(entry)

        if match_type_override:
            match_type = match_type_override
        else:
            _, match_type = loader.get_questions_with_match_info(finding.rule_id)

        start = time.monotonic()
        engine = VerificationEngine(
            config=self._make_config(),
            questions_loader=loader,
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
                reasoning=f"[{variant_name}] No verdict returned",
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

    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        """Standard evaluate() — returns only Variant A (rule-specific) result."""
        if self._dry_run:
            return _dry_run_result(entry, "ablation-specific")
        return self._run_variant(entry, self._loader_specific, "ablation-specific")

    def evaluate_all(self, entry: GroundTruthEntry) -> list[tuple[str, BenchmarkResult]]:
        """Run all three variants and return list of (approach_name, result) tuples.

        Approach names: "ablation-specific", "ablation-generic", "ablation-zero"
        """
        if self._dry_run:
            return [
                ("ablation-specific", _dry_run_result(entry, "ablation-specific")),
                ("ablation-generic", _dry_run_result(entry, "ablation-generic")),
                ("ablation-zero", _dry_run_result(entry, "ablation-zero")),
            ]

        # Variant A — rule-specific questions
        result_a = self._run_variant(entry, self._loader_specific, "ablation-specific")

        # Variant B — generic default questions only
        result_b = self._run_variant(entry, self._loader_generic, "ablation-generic", "default")

        # Variant C — zero-shot: inject an empty question list by overriding the loader
        # with a loader that returns a minimal GuidedQuestions (no questions)
        zero_loader = _ZeroShotLoader()
        result_c = self._run_variant(entry, zero_loader, "ablation-zero", "generic")

        return [
            ("ablation-specific", result_a),
            ("ablation-generic", result_b),
            ("ablation-zero", result_c),
        ]


class _ZeroShotLoader(QuestionsLoader):
    """A QuestionsLoader that always returns an empty question list (zero-shot)."""

    def __init__(self) -> None:
        super().__init__(prompts_dir=None)

    def get_questions(self, rule_id: str) -> GuidedQuestions:
        return GuidedQuestions(
            rule_id=rule_id,
            short_description="",
            questions=[],
            context_hint="",
            additional_context=[],
        )

    def get_questions_with_match_info(self, rule_id: str) -> tuple[GuidedQuestions, str]:
        return self.get_questions(rule_id), "generic"
