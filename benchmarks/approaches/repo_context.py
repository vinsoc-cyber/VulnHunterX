# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""VulnHunterX with full-repository context (``vulnhunterx-repo``).

Same engine, questions and prompts as the ``vulnhunterx`` approach, but the
verifier reads the real checked-out repository (``repos/<lang>/<repo_name>``)
through the engine's default repo-scoped extractor/context provider instead of
the in-memory snippet provider. The finding is built with an explicit
``repo_name`` taken from ``entry.metadata['repo_name']`` (e.g.
``<repo>__<sha8>`` from the revision-pair builder) and the engine is driven via
``verify_findings`` directly, NOT ``verify --sarif`` (which would derive the
repo name from the SARIF file stem).

Missing repository -> ERROR with a reason; there is deliberately no silent
fallback to snippet mode. A missing pre-extracted CSV context dir is NOT an
error: the engine's own repo-scoped source fallback is used.

Options: ``route=auto`` uses the policy registry; ``route=legacy`` empties it
(``PolicyRegistry([])``) so every finding takes the legacy multi-turn path.
"""

from __future__ import annotations

import dataclasses
import time
from pathlib import Path
from typing import Any

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.adapters.registry import OptionSpec, _to_bool
from benchmarks.approaches.base import (
    PRED_ERROR,
    BenchmarkResult,
    _dry_run_result,
    entry_to_finding,
    verdict_to_pred,
)
from benchmarks.approaches.registry import (
    LLMConfig,
    register_approach,
)
from benchmarks.approaches.vulnhunterx import VulnHunterXApproach
from vuln_hunter_x.context.repo_paths import resolve_repo_root
from vuln_hunter_x.core.config import Config
from vuln_hunter_x.verification.engine import VerificationEngine
from vuln_hunter_x.verification.policy.loader import PolicyRegistry

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _safe_component(value: str) -> bool:
    return bool(value) and "/" not in value and "\\" not in value and value not in (".", "..")


@register_approach
class RepoContextApproach(VulnHunterXApproach):
    """vulnhunterx with full repository context instead of snippet-only context."""

    name = "vulnhunterx-repo"
    line_anchored = True
    option_schema = {
        "max_iterations": OptionSpec(int, default=3, help="Max LLM turns per finding."),
        "force_decision": OptionSpec(
            _to_bool, default=True, help="Force TP/FP after max_iterations."
        ),
        "route": OptionSpec(
            str, default="auto", help="auto (policy registry) | legacy (no policies)."
        ),
        "repos_dir": OptionSpec(str, default="", help="Repos root (default: project repos/)."),
        "output_dir": OptionSpec(
            str, default="", help="Context/output root (default: project output/)."
        ),
    }

    @classmethod
    def from_options(cls, llm: LLMConfig | None, options: dict[str, Any]) -> RepoContextApproach:
        llm = llm or LLMConfig()
        return cls(
            provider=llm.provider,
            model=llm.model,
            dry_run=llm.dry_run,
            max_iterations=options.get("max_iterations", 3),
            force_decision=options.get("force_decision", True),
            route=options.get("route", "auto"),
            repos_dir=Path(options["repos_dir"]) if options.get("repos_dir") else None,
            output_dir=Path(options["output_dir"]) if options.get("output_dir") else None,
        )

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o",
        max_iterations: int = 3,
        prompts_dir: Path | None = None,
        dry_run: bool = False,
        force_decision: bool = True,
        route: str = "auto",
        repos_dir: Path | None = None,
        output_dir: Path | None = None,
    ) -> None:
        if route not in ("auto", "legacy"):
            raise ValueError(f"route must be 'auto' or 'legacy', got {route!r}")
        super().__init__(
            provider=provider,
            model=model,
            max_iterations=max_iterations,
            prompts_dir=prompts_dir,
            dry_run=dry_run,
            force_decision=force_decision,
        )
        self._route = route
        self._repos_dir = repos_dir or (_PROJECT_ROOT / "repos")
        self._output_dir = output_dir or (_PROJECT_ROOT / "output")

    def _error(self, entry: GroundTruthEntry, start: float, reason: str) -> BenchmarkResult:
        return BenchmarkResult(
            entry=entry,
            predicted_label=PRED_ERROR,
            confidence="",
            reasoning=reason,
            elapsed_seconds=time.monotonic() - start,
        )

    def _build_engine(self) -> VerificationEngine:
        config = Config.from_dict(
            {
                "provider": self._provider,
                "model": self._model,
                "max_iterations": self._max_iterations,
                "verbosity": "quiet",
                "force_decision": self._force_decision,
                "paths": {
                    "repos_dir": str(self._repos_dir),
                    "output_dir": str(self._output_dir),
                },
            }
        )
        engine = VerificationEngine(
            config=config,
            questions_loader=self._questions_loader,
            jobs=1,
        )
        if self._route == "legacy":
            engine._policy_registry = PolicyRegistry([])
        return engine

    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        if self._dry_run:
            return _dry_run_result(entry, self.name)
        start = time.monotonic()
        meta = entry.metadata or {}
        repo_name = str(meta.get("repo_name") or "")
        lang = str(meta.get("lang") or entry.lang or "")
        if not (_safe_component(repo_name) and _safe_component(lang)):
            return self._error(
                entry,
                start,
                f"vulnhunterx-repo needs safe metadata repo_name/lang "
                f"(got repo_name={repo_name!r}, lang={lang!r}); no snippet fallback",
            )
        if resolve_repo_root(self._repos_dir, lang, repo_name) is None:
            return self._error(
                entry,
                start,
                f"repository not checked out: {self._repos_dir / lang / repo_name}; "
                "no snippet fallback",
            )

        finding = dataclasses.replace(entry_to_finding(entry), repo_name=repo_name, lang=lang)
        engine = self._build_engine()
        _, match_type = self._questions_loader.get_questions_with_match_info(
            finding.rule_id,
            cwe_ids=finding.cwe_ids,
            lang=finding.lang,
        )
        result = engine.verify_findings([finding])
        elapsed = time.monotonic() - start
        if not result.verdicts:
            return BenchmarkResult(
                entry=entry,
                predicted_label=PRED_ERROR,
                confidence="",
                reasoning="No verdict returned",
                elapsed_seconds=elapsed,
                question_match_type=match_type,
            )
        v = result.verdicts[0]
        source = getattr(v, "decision_source", "legacy_model")
        return BenchmarkResult(
            entry=entry,
            predicted_label=verdict_to_pred(v.verdict),
            confidence=v.confidence,
            reasoning=f"[decision_source={source}] {v.reasoning}",
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
