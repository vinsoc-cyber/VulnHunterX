# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Verification engine orchestrating the LLM bug verification flow."""

from __future__ import annotations

import json
import re
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path

# Pattern that recognises a concrete code citation in reasoning text:
# "line 42", "line: 42", "at line 42", "(line 42)", or "file.c:42".
_CITATION_RE = re.compile(
    r"(?:line[:\s]+\d+|\bL\d+\b|[\w./-]+:\d+)",
    re.IGNORECASE,
)
# Pattern markers indicating purely pattern-language reasoning that lacks
# specific evidence — observed dominantly in the CWE-416 false-alarm cohort.
_GENERIC_PATTERN_MARKERS = (
    "clearly demonstrates",
    "explicitly demonstrates",
    "constitutes a",
    "constituting a",
    "obvious",
    "is a textbook",
    "is a classic",
    "is a clear",
)


def _downgrade_unsupported_confidence(verdict: Verdict) -> Verdict:
    """Demote High/Medium → Low when a TP verdict lacks specific code citations.

    Heuristic: if the verdict is a True Positive and the reasoning text contains
    pattern-matching language but NO concrete `file:line` or `line N` citation,
    downgrade confidence and append a marker to the reasoning so the post-
    processing layer can audit the change.

    No-op on False Positive verdicts and on Needs-More-Data — those don't carry
    the over-conviction risk and the calibration data shows them already noisy.
    """
    if verdict.verdict not in ("True Positive", "TP"):
        return verdict
    if verdict.confidence not in ("High", "Medium"):
        return verdict
    text = (verdict.reasoning or "").lower()
    has_citation = bool(_CITATION_RE.search(verdict.reasoning or ""))
    has_generic = any(m in text for m in _GENERIC_PATTERN_MARKERS)
    if has_generic and not has_citation:
        verdict.confidence = "Low"
        verdict.confidence_score = min(verdict.confidence_score, 0.3)
        verdict.reasoning = (
            (verdict.reasoning or "")
            + " [confidence downgraded: pattern-matching language without "
            "specific file:line citation]"
        )
    return verdict


from vuln_hunter_x.context.extractor import ContextExtractor
from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.config import Config, load_config
from vuln_hunter_x.core.types import Finding, Verdict, VerificationResult
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.questions.loader import QuestionsLoader
from vuln_hunter_x.sarif.parser import discover_sarif_files, parse_sarif_file


def _is_test_path(file_path: str) -> bool:
    """Return True if file_path is under a test/ or tests/ path segment."""
    if not file_path:
        return False
    normalized = file_path.replace("\\", "/").strip()
    if normalized.lower().startswith("file://"):
        normalized = normalized[7:].lstrip("/")
    parts = [p for p in normalized.split("/") if p]
    return any(part in ("test", "tests") for part in parts)


class VerificationEngine:
    """
    Main engine for CodeQL + LLM bug verification.

    Orchestrates the flow:
    1. Parse SARIF findings
    2. Extract code context
    3. Load guided questions
    4. Call LLM for verification
    5. Collect and save results

    Example:
        engine = VerificationEngine.from_config("config/confirm_findings.yaml")
        results = engine.verify_sarif("output/c/repo/repo.sarif", lang="c", repo_name="repo")

        for verdict in results.verdicts:
            print(f"{verdict.finding.rule_id}: {verdict.verdict}")
    """

    def __init__(
        self,
        config: Config,
        questions_loader: QuestionsLoader | None = None,
        context_extractor: ContextExtractor | None = None,
        context_provider: ContextProvider | None = None,
        llm_client: LLMClient | None = None,
    ):
        """Initialize the verification engine.

        Args:
            config: Application configuration.
            questions_loader: Custom questions loader (default: auto-created from config).
            context_extractor: Custom context extractor (default: auto-created from config).
            context_provider: Custom CSV context provider (default: auto-created from config).
            llm_client: Custom LLM client (default: auto-created from config).
        """
        self.config = config

        # Initialize components
        self.questions_loader = questions_loader or QuestionsLoader(config.paths.prompts_dir)
        self.context_extractor = context_extractor or ContextExtractor(
            config.paths.repos_dir, config.paths.output_dir
        )

        self.context_provider: ContextProvider | None = context_provider or ContextProvider(
            config.paths.output_dir,
            config.paths.repos_dir,
        )

        self.llm_client = llm_client or LLMClient(
            provider=config.llm.provider,
            model=config.llm.model,
            temperature=config.llm.temperature,
            max_tokens=config.llm.max_tokens,
        )

        # Wire CWE → question mapping if rule_categories.yaml is available
        self._profile_manager = None
        try:
            from vuln_hunter_x.core.rule_profiles import RuleProfileManager

            categories_path = config.paths.base_dir / "config" / "rule_categories.yaml"
            if categories_path.is_file():
                self._profile_manager = RuleProfileManager(categories_path)
                self.questions_loader.set_cwe_question_map(
                    self._profile_manager.cwe_question_map,
                )
        except Exception:
            pass  # Graceful degradation — CWE matching disabled

        # Callbacks for progress reporting
        self._on_finding_start: Callable[[int, int, Finding], None] | None = None
        self._on_finding_complete: Callable[[int, int, Verdict], None] | None = None

        # Open log file if configured
        self._log_fh = (
            open(config.output.log_file, "w", encoding="utf-8")  # noqa: SIM115
            if config.output.log_file
            else None
        )

    def __del__(self) -> None:
        if self._log_fh:
            self._log_fh.close()

    @classmethod
    def from_config(
        cls,
        config_path: Path | None = None,
        base_path: Path | None = None,
        **overrides,
    ) -> VerificationEngine:
        """
        Create engine from configuration file.

        Args:
            config_path: Path to configuration YAML file
            base_path: Base path for resolving relative paths
            **overrides: Override config values

        Returns:
            Configured VerificationEngine
        """
        config = load_config(Path(config_path), base_path) if config_path else Config()

        if overrides:
            config = config.merge_with_args(**overrides)

        return cls(config)

    def on_finding_start(self, callback: Callable[[int, int, Finding], None]) -> None:
        """Set callback for when finding analysis starts."""
        self._on_finding_start = callback

    def on_finding_complete(self, callback: Callable[[int, int, Verdict], None]) -> None:
        """Set callback for when finding analysis completes."""
        self._on_finding_complete = callback

    def verify_sarif(
        self,
        sarif_path: Path,
        lang: str,
        repo_name: str,
        limit: int = 0,
        exclude_test_paths: bool = True,
        category_filter: list[str] | None = None,
    ) -> VerificationResult:
        """
        Verify findings from a single SARIF file.

        Args:
            sarif_path: Path to the SARIF file
            lang: Language of the codebase
            repo_name: Name of the repository
            limit: Maximum findings to process (0 = all)
            exclude_test_paths: If True, skip findings under test/ or tests/
            category_filter: Only verify findings in these security categories

        Returns:
            VerificationResult with all verdicts
        """
        findings = parse_sarif_file(Path(sarif_path), lang, repo_name)
        if exclude_test_paths:
            findings = [f for f in findings if not _is_test_path(f.file)]
        return self.verify_findings(findings, limit, category_filter=category_filter)

    def verify_all_sarif(
        self,
        output_dir: Path | None = None,
        lang_filter: str | None = None,
        repo_filter: str | None = None,
        limit: int = 0,
        exclude_test_paths: bool = True,
        category_filter: list[str] | None = None,
    ) -> VerificationResult:
        """
        Verify findings from all SARIF files in output directory.

        Args:
            output_dir: Base output directory (default: from config)
            lang_filter: Only process this language
            repo_filter: Only process this repository
            limit: Maximum total findings to process (0 = all)
            exclude_test_paths: If True, skip findings under test/ or tests/
            category_filter: Only verify findings in these security categories

        Returns:
            VerificationResult with all verdicts
        """
        output_dir = output_dir or self.config.paths.output_dir
        sarif_files = discover_sarif_files(output_dir)

        if lang_filter:
            sarif_files = [(p, lang, n) for p, lang, n in sarif_files if lang == lang_filter]
        if repo_filter:
            sarif_files = [
                (p, lang, n) for p, lang, n in sarif_files if n.lower() == repo_filter.lower()
            ]

        # Collect all findings
        all_findings: list[Finding] = []
        for sarif_path, lang, repo_name in sarif_files:
            findings = parse_sarif_file(sarif_path, lang, repo_name)
            if exclude_test_paths:
                findings = [f for f in findings if not _is_test_path(f.file)]
            all_findings.extend(findings)

        return self.verify_findings(all_findings, limit, category_filter=category_filter)

    def verify_findings(
        self,
        findings: list[Finding],
        limit: int = 0,
        category_filter: list[str] | None = None,
    ) -> VerificationResult:
        """
        Verify a list of findings.

        Args:
            findings: List of Finding objects to verify
            limit: Maximum findings to process (0 = all)
            category_filter: Only verify findings in these security categories

        Returns:
            VerificationResult with all verdicts
        """
        # Apply category filter (findings without CWE tags are always included)
        if category_filter and self._profile_manager:
            target_cwes = self._profile_manager.get_cwes_for_categories(category_filter)
            findings = [f for f in findings if not f.cwe_ids or target_cwes.intersection(f.cwe_ids)]

        if limit > 0:
            findings = findings[:limit]

        start_time = time.time()
        verdicts: list[Verdict] = []
        stats: dict[str, int] = {
            "True Positive": 0,
            "False Positive": 0,
            "Needs More Data": 0,
            "Error": 0,
        }

        total = len(findings)
        for i, finding in enumerate(findings, 1):
            if self._on_finding_start:
                self._on_finding_start(i, total, finding)

            verdict = self._verify_single_finding(finding)
            verdicts.append(verdict)

            stats[verdict.verdict] = stats.get(verdict.verdict, 0) + 1

            if self._on_finding_complete:
                self._on_finding_complete(i, total, verdict)

        total_time = time.time() - start_time

        return VerificationResult(
            verdicts=verdicts,
            stats=stats,
            model=self.config.llm.model,
            provider=self.config.llm.provider,
            total_time_seconds=total_time,
        )

    def verify_finding_iter(
        self,
        findings: list[Finding],
        limit: int = 0,
    ) -> Iterator[Verdict]:
        """
        Verify findings yielding each verdict as it completes.

        Useful for streaming results or progress updates.

        Args:
            findings: List of Finding objects to verify
            limit: Maximum findings to process (0 = all)

        Yields:
            Verdict for each finding
        """
        if limit > 0:
            findings = findings[:limit]

        total = len(findings)
        for i, finding in enumerate(findings, 1):
            if self._on_finding_start:
                self._on_finding_start(i, total, finding)

            verdict = self._verify_single_finding(finding)

            if self._on_finding_complete:
                self._on_finding_complete(i, total, verdict)

            yield verdict

    def _verify_single_finding(self, finding: Finding) -> Verdict:
        """Verify a single finding."""
        # Get questions (pass CWE IDs for Semgrep/OpenGrep CWE-based matching)
        questions = self.questions_loader.get_questions(
            finding.rule_id,
            cwe_ids=finding.cwe_ids,
            lang=finding.lang,
        )

        # Extract context
        context_result = self.context_extractor.get_context(
            finding.file,
            finding.start_line,
            finding.lang,
            repo_name=finding.repo_name,
        )

        # Pre-fetch additional context declared by guided questions
        prefetched_context: dict[str, str] = {}
        if questions.additional_context and self.context_provider:
            prefetch_requests = self._build_prefetch_requests(
                questions.additional_context,
                context_result.function_name,
            )
            if prefetch_requests:
                prefetched_context = self.context_provider.get_additional_context(
                    repo_name=finding.repo_name,
                    lang=finding.lang,
                    context_requests=prefetch_requests,
                )

        # Call LLM. When ``self_consistency_samples > 1`` we route through
        # the voting wrapper; otherwise we keep the single-pass fast path.
        sc_samples = getattr(self.config.verification, "self_consistency_samples", 1)
        if sc_samples > 1:
            verdict = self.llm_client.analyze_with_voting(
                finding=finding,
                context=context_result.code,
                questions=questions,
                func_name=context_result.function_name,
                samples=sc_samples,
                voting_temperature=getattr(
                    self.config.verification,
                    "self_consistency_temperature",
                    0.7,
                ),
                tie_break=getattr(
                    self.config.verification,
                    "self_consistency_tie_break",
                    "fp",
                ),
                context_provider=self.context_provider,
                max_iterations=self.config.verification.max_iterations,
                verbose=self.config.output.is_verbose,
                quiet=self.config.output.is_quiet,
                force_decision=self.config.verification.force_decision,
                prefetched_context=prefetched_context,
                log_file=self._log_fh,
            )
        else:
            verdict = self.llm_client.analyze(
                finding=finding,
                context=context_result.code,
                questions=questions,
                func_name=context_result.function_name,
                context_provider=self.context_provider,
                max_iterations=self.config.verification.max_iterations,
                verbose=self.config.output.is_verbose,
                quiet=self.config.output.is_quiet,
                force_decision=self.config.verification.force_decision,
                prefetched_context=prefetched_context,
                log_file=self._log_fh,
            )

        # Confidence-discipline post-processor: a TP verdict whose reasoning is
        # purely pattern-language ("clearly demonstrates", "constitutes a", ...)
        # without any specific file:line citation is the documented failure
        # mode for memory-safety classes (benchmarks/Conclusion.md, CWE-416
        # case study). Downgrade confidence to 'Low' so the verdict surfaces
        # to a human reviewer rather than being trusted at face value.
        verdict = _downgrade_unsupported_confidence(verdict)

        return verdict

    @staticmethod
    def _build_prefetch_requests(
        context_types: list[str],
        func_name: str,
    ) -> list[str]:
        """Build concrete context request strings from additional_context types.

        Only types that can be keyed off func_name are pre-fetched (caller,
        callees, all_callers). Types needing specific names (struct, global,
        macro, typedef, enum) remain reactive — the LLM requests them at runtime.
        """
        requests: list[str] = []
        if not func_name:
            return requests
        for ctx_type in context_types:
            ctx_type = ctx_type.lower().strip()
            if ctx_type == "caller":
                requests.append(f"caller:{func_name}")
            elif ctx_type == "callees":
                requests.append(f"callees:{func_name}")
            elif ctx_type == "all_callers":
                requests.append(f"all_callers:{func_name}")
        return requests

    def save_results(
        self,
        result: VerificationResult,
        output_dir: Path | None = None,
    ) -> tuple[Path, Path]:
        """
        Save verification results to files.

        Args:
            result: VerificationResult to save
            output_dir: Output directory (default: from config)

        Returns:
            Tuple of (summary_path, results_dir)
        """
        output_dir = output_dir or self.config.paths.output_dir
        # Save per-repo under output/<lang>/<repo_name>/verification_results/
        for verdict in result.verdicts:
            finding = verdict.finding
            repo_results_dir = (
                output_dir / finding.lang / finding.repo_name / "verification_results"
            )
            repo_results_dir.mkdir(parents=True, exist_ok=True)
            result_file = (
                repo_results_dir / f"{finding.rule_id.replace('/', '_')}_{finding.start_line}.json"
            )
            result_file.write_text(json.dumps(verdict.to_dict(), indent=2))

        # Summary: write to first repo's verification_results dir
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        repo_names = sorted(set(v.finding.repo_name for v in result.verdicts))
        repo_part = "_".join(repo_names) if repo_names else "unknown"
        if len(repo_part) > 50:
            repo_part = repo_part[:47] + "..."

        first_lang = result.verdicts[0].finding.lang if result.verdicts else "unknown"
        first_repo = result.verdicts[0].finding.repo_name if result.verdicts else "unknown"
        results_dir = output_dir / first_lang / first_repo / "verification_results"
        results_dir.mkdir(parents=True, exist_ok=True)
        summary_file = results_dir / f"summary_{repo_part}_{timestamp}.json"
        summary_file.write_text(json.dumps(result.to_dict(), indent=2))

        return summary_file, results_dir
