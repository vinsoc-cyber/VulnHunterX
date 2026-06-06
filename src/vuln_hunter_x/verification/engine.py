# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Verification engine orchestrating the LLM bug verification flow."""

from __future__ import annotations

import contextlib
import hashlib
import json
import re
import threading
import time
from collections.abc import Callable, Iterator
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Any

# Pattern that recognises a concrete code citation in reasoning text:
# "line 42", "line: 42", "at line 42", "(line 42)", or "file.c:42".
_CITATION_RE = re.compile(
    r"(?:line[:\s]+\d+|\bL\d+\b|[\w./-]+:\d+)",
    re.IGNORECASE,
)
# Recognises a called function/method name on a sink line — captures the
# identifier immediately before a "(", tolerating a generic argument list
# (e.g. `this.set<T>(...)`). Used to prefetch the sink callee's body, since the
# verdict for sink-implementation-dependent CWEs hinges on what that callee does.
_SINK_CALL_RE = re.compile(r"([A-Za-z_$][\w$]*)\s*(?:<[^<>()]*>)?\s*\(")
# Control-flow / language keywords that are never sink helpers — skip so they
# don't consume prefetch slots. Names absent from functions.csv resolve to a
# harmless "not found" anyway, so this list stays minimal.
_SINK_CALL_SKIP = frozenset(
    {"if", "for", "while", "switch", "catch", "return", "typeof", "await",
     "new", "function", "throw", "yield", "else", "do"}
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

# Languages whose taint-tracking findings tend to live in web-framework
# code where OWASP-style FP traps neutralise the taint (apostrophe
# guards, parameterised XPath, secure_filename, list/map reassignment).
# C-side findings don't share this pattern; gating the new
# second-opinion arm by language keeps the diversevul/CWE-264 results
# stable. See benchmarks/results/20260519_020920.
_FRAMEWORK_LANGS: frozenset[str] = frozenset({
    "python", "javascript", "java", "php", "go",
})

# Taint-tracking CWEs that need a forced flow-trace pass on framework
# languages. The 2026-05-19 owasp-python benchmark documented a 38pp
# accuracy gap between 1-iter and 2-iter verdicts on this class.
_TAINT_CWES: frozenset[str] = frozenset({
    "CWE-22",   # Path traversal
    "CWE-77",   # Command injection (generic)
    "CWE-78",   # OS command injection
    "CWE-79",   # XSS
    "CWE-80",   # Basic XSS
    "CWE-87",   # Alternate XSS syntax
    "CWE-89",   # SQL injection
    "CWE-90",   # LDAP injection
    "CWE-94",   # Code injection
    "CWE-95",   # Eval injection
    "CWE-113",  # Header injection
    "CWE-134",  # Uncontrolled format string
    "CWE-502",  # Deserialisation of untrusted data
    "CWE-611",  # XXE
    "CWE-643",  # XPath injection
    "CWE-917",  # SSTI
    "CWE-918",  # SSRF
    "CWE-1333", # ReDoS
})


def _downgrade_unsupported_confidence(verdict: Verdict) -> Verdict:
    """Demote High/Medium → Low when a TP or FP verdict lacks specific citations.

    Heuristic: if the verdict commits to TP or FP at High/Medium confidence,
    and the reasoning text contains pattern-matching language but NO concrete
    `file:line` or `line N` citation, downgrade confidence and append a marker
    so the post-processing layer can audit the change.

    Applied symmetrically to TP and FP — the 2026-05-15 benchmark showed that
    over-confident *FP* verdicts (FP/High with 26.4% accuracy) were the
    dominant calibration defect. Skipping the FP side biased the Low bucket
    toward FP and made High/Low accuracy indistinguishable.

    Needs-More-Data verdicts are not downgraded; they already signal
    uncertainty and the calibration data treats them separately.
    """
    if verdict.verdict not in ("True Positive", "TP", "False Positive", "FP"):
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


# Phrases signalling the verdict concerns only a single object instance's
# prototype, vs. the global Object.prototype that CWE-1321 (severity 8.2) is
# about. `Object.assign(new X(), {...dto})` and similar can at most change the
# new instance's [[Prototype]] — low impact — yet the model often ships it as
# TP/High. See output/.../js_prototype-pollution-ext_...287_*.json.
_LOCAL_POLLUTION_MARKERS = (
    "local prototype pollution",
    "instance prototype",
    "instance's prototype",
    "prototype of the instance",
    "local instance",
    "only this instance",
    "not global",
)
_GLOBAL_POLLUTION_MARKERS = (
    "object.prototype",
    "global prototype",
    "all objects",
    "globally pollut",
    "affects every",
)


def _downgrade_local_prototype_pollution(verdict: Verdict) -> Verdict:
    """Cap confidence on TP prototype-pollution verdicts that are only LOCAL.

    A genuine CWE-1321 finding pollutes the shared ``Object.prototype`` and
    affects all objects. A verdict whose own reasoning says the impact is
    confined to a single instance's prototype (the ``Object.assign(new X(),
    {...spread})`` shape) is low-impact and frequently a false alarm — it
    should not ride at TP/High. Only fires on prototype-pollution findings to
    avoid touching unrelated rules.
    """
    if verdict.verdict not in ("True Positive", "TP"):
        return verdict
    if verdict.confidence not in ("High", "Medium"):
        return verdict
    finding = getattr(verdict, "finding", None)
    rule_id = (getattr(finding, "rule_id", "") or "").lower()
    cwes = " ".join(getattr(finding, "cwe_ids", None) or []).lower()
    if "prototype" not in rule_id and "1321" not in cwes and "1321" not in rule_id:
        return verdict
    text = (verdict.reasoning or "").lower()
    is_local = any(m in text for m in _LOCAL_POLLUTION_MARKERS)
    is_global = any(m in text for m in _GLOBAL_POLLUTION_MARKERS)
    if is_local and not is_global:
        verdict.confidence = "Low"
        verdict.confidence_score = min(verdict.confidence_score, 0.3)
        verdict.reasoning = (
            (verdict.reasoning or "")
            + " [confidence downgraded: reasoning describes LOCAL instance "
            "prototype change, not global Object.prototype pollution (CWE-1321)]"
        )
    return verdict


from vuln_hunter_x.context.extractor import ContextExtractor
from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.context.snippet_provider import SnippetContextProvider
from vuln_hunter_x.core.config import Config, load_config
from vuln_hunter_x.core.types import Finding, Verdict, VerificationResult
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.questions.loader import QuestionsLoader
from vuln_hunter_x.sarif.parser import discover_sarif_files, parse_sarif_file


class _ThreadSafeLogFile:
    """Serializes write/flush on a shared log file handle so parallel
    verification workers cannot interleave bytes mid-write."""

    __slots__ = ("_fh", "_lock")

    def __init__(self, fh: Any, lock: threading.Lock) -> None:
        self._fh = fh
        self._lock = lock

    def write(self, data: str) -> int:
        with self._lock:
            return self._fh.write(data)

    def flush(self) -> None:
        with self._lock:
            self._fh.flush()


def _is_test_path(file_path: str) -> bool:
    """Return True if file_path is under a test/ or tests/ path segment."""
    if not file_path:
        return False
    normalized = file_path.replace("\\", "/").strip()
    if normalized.lower().startswith("file://"):
        normalized = normalized[7:].lstrip("/")
    parts = [p for p in normalized.split("/") if p]
    return any(part in ("test", "tests") for part in parts)


def _verdict_filename(finding: Finding) -> str:
    """Unique, filesystem-safe filename for a per-finding verdict JSON.

    Keyed on the finding's full identity (rule, path, span, message, dataflow) so
    distinct findings never collide; genuinely identical findings collapse to one
    file. The previous scheme keyed only on rule_id + start_line, which caused
    same-rule/same-line findings in different files to overwrite each other.
    """
    safe_rule = finding.rule_id.replace("/", "_") or "unknown-rule"
    safe_file = re.sub(r"[^A-Za-z0-9]+", "-", finding.file or "unknown").strip("-")
    identity = "|".join(
        [
            finding.rule_id,
            finding.file,
            str(finding.start_line),
            str(finding.end_line),
            finding.message,
            "\n".join(finding.dataflow_path),
        ]
    )
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:10]
    readable = f"{safe_rule}_{safe_file}_{finding.start_line}"
    # Bound the readable part well under the 255-char filename limit; the digest is
    # appended after truncation so it is never cut and uniqueness is preserved.
    return f"{readable[:150]}_{digest}.json"


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
        jobs: int | None = None,
    ):
        """Initialize the verification engine.

        Args:
            config: Application configuration.
            questions_loader: Custom questions loader (default: auto-created from config).
            context_extractor: Custom context extractor (default: auto-created from config).
            context_provider: Custom CSV context provider (default: auto-created from config).
            llm_client: Custom LLM client (default: auto-created from config).
            jobs: Concurrent findings to verify (ThreadPoolExecutor workers).
                When ``None``, falls back to ``config.verification.jobs`` (default 4).
                Set to 1 to disable parallelism and use the sequential code path.
        """
        self.config = config
        self._jobs = jobs if jobs is not None else getattr(config.verification, "jobs", 4)

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
            num_retries=config.llm.num_retries,
            ollama_api_keys=config.llm.ollama_api_keys,
            ollama_key_state_path=config.paths.output_dir / ".ollama_key_state.json",
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

        # Open log file if configured. Wrap in a thread-safe shim so concurrent
        # workers in parallel verification cannot interleave bytes mid-write.
        self._log_lock = threading.Lock()
        self._callback_lock = threading.Lock()
        raw_log_fh = (
            open(config.output.log_file, "w", encoding="utf-8")  # noqa: SIM115
            if config.output.log_file
            else None
        )
        self._raw_log_fh = raw_log_fh
        self._log_fh: _ThreadSafeLogFile | None = (
            _ThreadSafeLogFile(raw_log_fh, self._log_lock) if raw_log_fh is not None else None
        )

    def __del__(self) -> None:
        raw = getattr(self, "_raw_log_fh", None)
        if raw is not None:
            try:
                raw.close()
            except Exception:
                pass

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
        stats: dict[str, int] = {
            "True Positive": 0,
            "False Positive": 0,
            "Needs More Data": 0,
            "Error": 0,
        }

        total = len(findings)

        if self._jobs <= 1 or total <= 1:
            verdicts: list[Verdict] = []
            for i, finding in enumerate(findings, 1):
                verdicts.append(self._verify_one_with_callbacks(i, total, finding))
        else:
            verdicts_by_index: dict[int, Verdict] = {}
            pool = ThreadPoolExecutor(
                max_workers=self._jobs, thread_name_prefix="vhx-verify"
            )
            try:
                futures = {
                    pool.submit(
                        self._verify_one_with_callbacks, i, total, finding
                    ): i
                    for i, finding in enumerate(findings, 1)
                }
                try:
                    for future in as_completed(futures):
                        idx = futures[future]
                        verdicts_by_index[idx] = future.result()
                except BaseException:
                    # Drop queued work; let in-flight LLM calls finish so we
                    # don't leak partial network conversations.
                    pool.shutdown(cancel_futures=True, wait=True)
                    raise
            finally:
                pool.shutdown(wait=True)
            verdicts = [verdicts_by_index[i] for i in sorted(verdicts_by_index)]

        for v in verdicts:
            stats[v.verdict] = stats.get(v.verdict, 0) + 1

        total_time = time.time() - start_time

        return VerificationResult(
            verdicts=verdicts,
            stats=stats,
            model=self.config.llm.model,
            provider=self.config.llm.provider,
            total_time_seconds=total_time,
        )

    def _verify_one_with_callbacks(
        self, i: int, total: int, finding: Finding
    ) -> Verdict:
        """Run one finding's verification with progress callbacks under a lock.

        The callback lock ensures CLI progress prints from concurrent workers
        do not interleave.
        """
        with self._callback_lock:
            if self._on_finding_start:
                self._on_finding_start(i, total, finding)
        verdict = self._verify_single_finding(finding)
        with self._callback_lock:
            if self._on_finding_complete:
                self._on_finding_complete(i, total, verdict)
        return verdict

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

        if self._jobs <= 1 or total <= 1:
            for i, finding in enumerate(findings, 1):
                yield self._verify_one_with_callbacks(i, total, finding)
            return

        # Parallel: yield verdicts in finish order (not input order).
        pool = ThreadPoolExecutor(
            max_workers=self._jobs, thread_name_prefix="vhx-verify"
        )
        try:
            futures = [
                pool.submit(self._verify_one_with_callbacks, i, total, finding)
                for i, finding in enumerate(findings, 1)
            ]
            try:
                for future in as_completed(futures):
                    yield future.result()
            except BaseException:
                pool.shutdown(cancel_futures=True, wait=True)
                raise
        finally:
            pool.shutdown(wait=True)

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

        # Pick an effective ContextProvider for this finding. If the CSV-based
        # provider has no data for this repo (Stage-3 context extraction was
        # skipped, or the finding came from a synthetic source like a
        # benchmark snippet), fall back to a SnippetContextProvider so the
        # multi-turn loop still has *something* to serve. Returning empty
        # was the documented cause of the 2026-05-15 benchmark's 73% TP-loss
        # — the LLM defaulted to FP rather than asking for context.
        effective_provider: ContextProvider | SnippetContextProvider | None = (
            self.context_provider
        )
        if isinstance(self.context_provider, ContextProvider) and not (
            self.context_provider.has_context_for_repo(
                finding.repo_name, finding.lang
            )
        ):
            effective_provider = SnippetContextProvider(
                snippet=context_result.code,
                function_name=context_result.function_name,
            )

        # Pre-fetch additional context declared by guided questions
        prefetched_context: dict[str, str] = {}
        if questions.additional_context and effective_provider:
            prefetch_requests = self._build_prefetch_requests(
                questions.additional_context,
                context_result.function_name,
            )
            # For sink-implementation-dependent CWEs (the "callees" hint), also
            # prefetch the body of the function/method called AT the sink line —
            # resolved directly from functions.csv by name. This does not depend
            # on the call-graph (callers.csv) recording a caller→callee edge,
            # which is best-effort and was missing for the prototype-pollution
            # case that motivated this (the verifier guessed `set` did a bracket
            # write when it actually delegates to Redis).
            if any(
                c.lower().strip() in ("callees", "callee_bodies")
                for c in questions.additional_context
            ):
                for callee in self._extract_sink_callees(finding, context_result):
                    req = f"function:{callee}"
                    if req not in prefetch_requests:
                        prefetch_requests.append(req)
            # For DTO/request-sourced taint (prototype pollution,
            # mass-assignment) the decisive context is UPSTREAM: the declared
            # type of the source variable (e.g. `dto: CreateRescueDto`), whose
            # decorated fields reveal which keys are even allowed. Resolve the
            # type name from the function signature and prefetch its class def.
            if any(
                c.lower().strip() == "source_type"
                for c in questions.additional_context
            ):
                for type_name in self._extract_source_types(finding, context_result):
                    req = f"struct:{type_name}"
                    if req not in prefetch_requests:
                        prefetch_requests.append(req)
            if prefetch_requests:
                prefetched_context = effective_provider.get_additional_context(
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
                context_provider=effective_provider,
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
                context_provider=effective_provider,
                max_iterations=self.config.verification.max_iterations,
                verbose=self.config.output.is_verbose,
                quiet=self.config.output.is_quiet,
                force_decision=self.config.verification.force_decision,
                prefetched_context=prefetched_context,
                log_file=self._log_fh,
            )

        # Second-opinion pass: single-turn high-confidence FP verdicts had a
        # 79.7% false-negative rate on the 2026-05-15 benchmark (100% on
        # CWE-264). Re-prompt the LLM with an explicit audit checklist before
        # accepting such a verdict. Only fires for FP verdicts that committed
        # early without expanding context — the cheapest fix for the
        # documented failure mode. Skipped when self-consistency voting is on
        # (the voting already provides redundancy) and when the verdict came
        # from a parse-failed fallback (no real opinion to challenge).
        sc_samples = getattr(self.config.verification, "self_consistency_samples", 1)
        # Three trigger arms (any fires):
        #   A. Classic "1-iter / High-confidence FP" — the 2026-05-15 06:00
        #      diversevul benchmark documented this as the dominant
        #      under-recall failure mode.
        #   B. "Force-decision defaulted to FP" — the 2026-05-15 16:45
        #      follow-up showed CWE-264 cases truncating the verdict
        #      JSON, falling into _force_decision_turn, and defaulting
        #      to FP. These end at iter=2/Low (so arm A misses them) but
        #      the reasoning carries the "[Forced decision:" sentinel.
        #   C. "1-iter / High-confidence TP on framework taint CWE" —
        #      the 2026-05-19 owasp-python benchmark showed Python web
        #      taint-tracking findings sitting at 1-iter/High accuracy
        #      = 57.1% vs 2-iter/High = 95.8%. The LLM was pattern-
        #      matching "user input near sink" and shipping TP, missing
        #      framework-defense FP traps (apostrophe guards,
        #      parameterised XPath, secure_filename, list/map
        #      reassignment). Gated to framework languages so C-side
        #      verdicts are unchanged.
        reasoning_text = verdict.reasoning or ""
        is_fp = verdict.verdict in ("False Positive", "FP")
        is_tp = verdict.verdict in ("True Positive", "TP")
        arm_a = is_fp and verdict.confidence == "High" and verdict.iterations == 1
        arm_b = is_fp and "[Forced decision:" in reasoning_text
        arm_c = (
            is_tp
            and verdict.confidence == "High"
            and verdict.iterations == 1
            and finding.lang in _FRAMEWORK_LANGS
            and bool(set(finding.cwe_ids or []) & _TAINT_CWES)
        )
        if sc_samples <= 1 and (arm_a or arm_b or arm_c):
            # Post-processing must never crash a verdict; the original
            # verdict is preserved if the second-opinion call fails.
            with contextlib.suppress(Exception):
                verdict = self.llm_client.request_second_opinion(
                    finding=finding,
                    context=context_result.code,
                    questions=questions,
                    func_name=context_result.function_name,
                    previous_verdict=verdict,
                    verbose=self.config.output.is_verbose,
                    quiet=self.config.output.is_quiet,
                    log_file=self._log_fh,
                    prefetched_context=prefetched_context,
                )

        # Confidence-discipline post-processor: a TP or FP verdict whose
        # reasoning is purely pattern-language ("clearly demonstrates",
        # "constitutes a", ...) without any specific file:line citation is the
        # documented failure mode for memory-safety classes (benchmarks/
        # Conclusion.md, CWE-416 case study). Downgrade confidence to 'Low'
        # so the verdict surfaces to a human reviewer rather than being
        # trusted at face value.
        verdict = _downgrade_unsupported_confidence(verdict)
        # Local-vs-global prototype-pollution calibration: a TP verdict whose
        # reasoning confines impact to a single instance's prototype is not a
        # CWE-1321 (Object.prototype) finding and must not ride at TP/High.
        verdict = _downgrade_local_prototype_pollution(verdict)

        return verdict

    @staticmethod
    def _extract_sink_callees(
        finding: Finding,
        context_result: Any,
        max_callees: int = 3,
    ) -> list[str]:
        """Extract function/method names called on the finding's sink line(s).

        Reads the sink line(s) out of the enclosing-function snippet
        (``context_result.code`` starts at ``context_result.start_line``) and
        returns the distinct callee identifiers, so their bodies can be
        prefetched. Returns [] if the sink line cannot be located.
        """
        code = getattr(context_result, "code", "") or ""
        ctx_start = getattr(context_result, "start_line", 0) or 0
        if not code or ctx_start <= 0:
            return []
        lines = code.split("\n")
        # Map the finding's 1-based source lines into the snippet's 0-based index.
        first = max(0, finding.start_line - ctx_start)
        last = max(first, finding.end_line - ctx_start)
        if first >= len(lines):
            return []
        snippet = "\n".join(lines[first : min(len(lines), last + 1)])

        seen: set[str] = set()
        callees: list[str] = []
        for match in _SINK_CALL_RE.finditer(snippet):
            name = match.group(1)
            if name in _SINK_CALL_SKIP or name in seen:
                continue
            seen.add(name)
            callees.append(name)
            if len(callees) >= max_callees:
                break
        return callees

    # Type names that are language builtins / framework primitives, not
    # user-defined DTOs worth fetching a class definition for.
    _SOURCE_TYPE_SKIP = frozenset(
        {
            "string", "number", "boolean", "any", "object", "void", "unknown",
            "never", "null", "undefined", "Array", "Promise", "Date", "Object",
            "Record", "Map", "Set", "Buffer", "Request", "Response", "Express",
        }
    )
    _PARAM_TYPE_RE_TMPL = r"\b{var}\s*:\s*([A-Za-z_$][\w$]*)"

    @classmethod
    def _extract_source_types(
        cls,
        finding: Finding,
        context_result: Any,
        max_types: int = 2,
    ) -> list[str]:
        """Resolve the declared type(s) of the taint source variable.

        The dataflow path records the source expression (e.g. ``"line 75:
        dto"``); the enclosing-function signature declares its type (``dto:
        CreateRescueDto``). Returning that type name lets the engine prefetch
        the DTO's class definition so the model can see which keys are
        whitelisted — the upstream context that decides DTO-sourced taint.
        Builtins/framework primitives are skipped. Returns [] if nothing
        user-defined resolves.
        """
        code = getattr(context_result, "code", "") or ""
        if not code:
            return []
        # Candidate source variable names, in dataflow order.
        src_vars: list[str] = []
        seen_vars: set[str] = set()
        for step in getattr(finding, "dataflow_path", None) or []:
            expr = step.split(":", 1)[1].strip() if ":" in step else step.strip()
            m = re.match(r"([A-Za-z_$][\w$]*)", expr)
            if m and m.group(1) not in seen_vars:
                seen_vars.add(m.group(1))
                src_vars.append(m.group(1))

        types: list[str] = []
        tseen: set[str] = set()
        for var in src_vars:
            pat = cls._PARAM_TYPE_RE_TMPL.format(var=re.escape(var))
            m = re.search(pat, code)
            if not m:
                continue
            type_name = m.group(1)
            if (
                type_name
                and type_name not in cls._SOURCE_TYPE_SKIP
                and type_name[:1].isupper()
                and type_name not in tseen
            ):
                tseen.add(type_name)
                types.append(type_name)
            if len(types) >= max_types:
                break
        return types

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
            elif ctx_type in ("callees", "callee_bodies"):
                # Prefetch the SINK helper bodies, not just their names — the
                # verdict for sink-implementation-dependent CWEs (prototype
                # pollution, command/SQL injection via helpers) hinges on the
                # callee's implementation.
                requests.append(f"callee_bodies:{func_name}")
            elif ctx_type == "all_callers":
                requests.append(f"all_callers:{func_name}")
            elif ctx_type in ("framework_sanitizers", "framework_validation"):
                # Repo-wide grep for the global input-validation boundary
                # (NestJS ValidationPipe whitelist/forbidNonWhitelisted). The
                # name part is ignored by the provider — it scans the repo.
                requests.append("framework_sanitizers:repo")
            elif ctx_type in ("framework_guards", "framework_auth"):
                requests.append("framework_guards:repo")
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
            result_file = repo_results_dir / _verdict_filename(finding)
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
