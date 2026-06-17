# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Ablation study: isolate the contribution of guided questions.

The ablation holds the entire VulnHunterX pipeline constant (identical engine,
context extractor, SnippetContextProvider, and config as the ``vulnhunterx``
approach) and varies **only** the guided-question set:

  specific  — rule-specific questions from *_questions.yaml
  generic   — only default_questions.yaml (generic fallback)
  zero      — no guided questions at all

Because the *specific* arm is, by construction, identical to the ``vulnhunterx``
approach, it is NOT re-run here: the runner reuses the ``vulnhunterx`` result as
the specific arm (see the ``ablation`` alias expansion in run_benchmark.py).
This module therefore only provides the two *delta* arms as first-class,
independently checkpointable approaches:

  - ``ablation-generic``
  - ``ablation-zero``

Running ``--approach ablation`` expands to ``vulnhunterx`` (specific) +
``ablation-generic`` + ``ablation-zero`` — the full three-way comparison with
no duplicate LLM pass.

Usage:
    python benchmarks/scripts/run_benchmark.py \\
        --dataset juliet --approach ablation --limit 24
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Any, ClassVar

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.adapters.registry import OptionSpec, _to_bool
from benchmarks.approaches.base import (
    BenchmarkResult,
    _dry_run_result,
    _SnippetContextExtractor,
    entry_to_finding,
    verdict_to_pred,
)
from benchmarks.approaches.registry import (
    LLMConfig,
    RegisteredApproach,
    register_approach,
)
from vuln_hunter_x.context.snippet_provider import SnippetContextProvider
from vuln_hunter_x.core.config import Config
from vuln_hunter_x.core.types import GuidedQuestions
from vuln_hunter_x.questions.loader import QuestionsLoader
from vuln_hunter_x.verification.engine import VerificationEngine

# Default prompts directory (all language-specific YAMLs)
_PROMPTS_DIR = Path(__file__).resolve().parents[2] / "config" / "prompts"
_DEFAULT_QUESTIONS_FILE = _PROMPTS_DIR / "default_questions.yaml"


class _ZeroShotLoader(QuestionsLoader):
    """A QuestionsLoader that always returns an empty question list (zero-shot)."""

    def __init__(self) -> None:
        super().__init__(prompts_dir=None)

    def get_questions(
        self, rule_id: str, *, cwe_ids: list[str] | None = None, lang: str = "",
    ) -> GuidedQuestions:
        return GuidedQuestions(
            rule_id=rule_id,
            short_description="",
            questions=[],
            context_hint="",
            additional_context=[],
        )

    def get_questions_with_match_info(
        self, rule_id: str, *, cwe_ids: list[str] | None = None, lang: str = "",
    ) -> tuple[GuidedQuestions, str]:
        return self.get_questions(rule_id), "generic"


class _AblationVariant(RegisteredApproach):
    """One ablation arm: the vulnhunterx pipeline with a swapped question set.

    Subclasses set ``name`` and ``variant`` ("generic" | "zero"). The engine
    wiring mirrors ``VulnHunterXApproach.evaluate`` exactly so the *only*
    independent variable across arms is the guided-question loader.
    """

    requires_llm: ClassVar[bool] = True
    is_baseline: ClassVar[bool] = False
    variant: ClassVar[str] = ""  # "generic" | "zero" — override in subclass
    option_schema: ClassVar[dict[str, OptionSpec]] = {
        "max_iterations": OptionSpec(int, default=3, help="Max LLM turns per finding."),
        "force_decision": OptionSpec(
            _to_bool,
            default=True,
            help="If True, force a TP/FP verdict after max_iterations (no NMD).",
        ),
        "use_slicing": OptionSpec(
            _to_bool,
            default=False,
            help="Use variable-aware code slicing instead of full snippet.",
        ),
    }

    @classmethod
    def from_options(
        cls, llm: LLMConfig | None, options: dict[str, Any]
    ) -> _AblationVariant:
        llm = llm or LLMConfig()
        return cls(
            provider=llm.provider,
            model=llm.model,
            dry_run=llm.dry_run,
            max_iterations=options.get("max_iterations", 3),
            force_decision=options.get("force_decision", True),
            use_slicing=options.get("use_slicing", False),
        )

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        max_iterations: int = 3,
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
        self._loader = self._build_loader()

    def _build_loader(self) -> QuestionsLoader:
        if self.variant == "generic":
            loader = QuestionsLoader(prompts_dir=None)
            if _DEFAULT_QUESTIONS_FILE.is_file():
                loader.load_from_file(_DEFAULT_QUESTIONS_FILE)
            return loader
        if self.variant == "zero":
            return _ZeroShotLoader()
        raise ValueError(f"unknown ablation variant: {self.variant!r}")

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
        # Identical engine wiring to VulnHunterXApproach — only the questions
        # loader differs, so any metric delta is attributable to the questions.
        engine = VerificationEngine(
            config=config,
            questions_loader=self._loader,
            context_extractor=_SnippetContextExtractor(
                entry.code_snippet, entry.function_name,
                use_slicing=self._use_slicing, finding=finding,
            ),
            context_provider=SnippetContextProvider(
                snippet=entry.code_snippet,
                function_name=entry.function_name,
            ),
            jobs=1,
        )

        # Mirror the args the engine uses internally so the recorded match
        # type can't diverge from the questions actually fed to the LLM.
        _, match_type = self._loader.get_questions_with_match_info(
            finding.rule_id, cwe_ids=finding.cwe_ids, lang=finding.lang,
        )
        result = engine.verify_findings([finding])
        elapsed = time.monotonic() - start

        if not result.verdicts:
            return BenchmarkResult(
                entry=entry,
                predicted_label="ERROR",
                confidence="",
                reasoning=f"[{self.name}] No verdict returned",
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


@register_approach
class AblationGenericApproach(_AblationVariant):
    """Ablation arm — generic default questions only."""

    name = "ablation-generic"
    variant = "generic"


@register_approach
class AblationZeroApproach(_AblationVariant):
    """Ablation arm — zero-shot (no guided questions)."""

    name = "ablation-zero"
    variant = "zero"
