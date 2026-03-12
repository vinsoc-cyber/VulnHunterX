"""Verification engine orchestrating the LLM bug verification flow."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from datetime import datetime
from pathlib import Path

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
        self.context_extractor = context_extractor or ContextExtractor(config.paths.repos_dir)
        
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
        
        # Callbacks for progress reporting
        self._on_finding_start: Callable[[int, int, Finding], None] | None = None
        self._on_finding_complete: Callable[[int, int, Verdict], None] | None = None
    
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
    ) -> VerificationResult:
        """
        Verify findings from a single SARIF file.
        
        Args:
            sarif_path: Path to the SARIF file
            lang: Language of the codebase
            repo_name: Name of the repository
            limit: Maximum findings to process (0 = all)
            exclude_test_paths: If True, skip findings under test/ or tests/
            
        Returns:
            VerificationResult with all verdicts
        """
        findings = parse_sarif_file(Path(sarif_path), lang, repo_name)
        if exclude_test_paths:
            findings = [f for f in findings if not _is_test_path(f.file)]
        return self.verify_findings(findings, limit)
    
    def verify_all_sarif(
        self,
        output_dir: Path | None = None,
        lang_filter: str | None = None,
        repo_filter: str | None = None,
        limit: int = 0,
        exclude_test_paths: bool = True,
    ) -> VerificationResult:
        """
        Verify findings from all SARIF files in output directory.
        
        Args:
            output_dir: Base output directory (default: from config)
            lang_filter: Only process this language
            repo_filter: Only process this repository
            limit: Maximum total findings to process (0 = all)
            exclude_test_paths: If True, skip findings under test/ or tests/
            
        Returns:
            VerificationResult with all verdicts
        """
        output_dir = output_dir or self.config.paths.output_dir
        sarif_files = discover_sarif_files(output_dir)
        
        if lang_filter:
            sarif_files = [(p, lang, n) for p, lang, n in sarif_files if lang == lang_filter]
        if repo_filter:
            sarif_files = [(p, lang, n) for p, lang, n in sarif_files 
                          if n.lower() == repo_filter.lower()]
        
        # Collect all findings
        all_findings: list[Finding] = []
        for sarif_path, lang, repo_name in sarif_files:
            findings = parse_sarif_file(sarif_path, lang, repo_name)
            if exclude_test_paths:
                findings = [f for f in findings if not _is_test_path(f.file)]
            all_findings.extend(findings)
        
        return self.verify_findings(all_findings, limit)
    
    def verify_findings(
        self,
        findings: list[Finding],
        limit: int = 0,
    ) -> VerificationResult:
        """
        Verify a list of findings.
        
        Args:
            findings: List of Finding objects to verify
            limit: Maximum findings to process (0 = all)
            
        Returns:
            VerificationResult with all verdicts
        """
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
        # Get questions
        questions = self.questions_loader.get_questions(finding.rule_id)
        
        # Extract context
        context_result = self.context_extractor.get_context(
            finding.file,
            finding.start_line,
            finding.lang,
        )
        
        # Call LLM
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
        )
        
        return verdict
    
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
            repo_results_dir = output_dir / finding.lang / finding.repo_name / "verification_results"
            repo_results_dir.mkdir(parents=True, exist_ok=True)
            result_file = repo_results_dir / f"{finding.rule_id.replace('/', '_')}_{finding.start_line}.json"
            result_file.write_text(json.dumps(verdict.to_dict(), indent=2))
        
        # Summary: write to first repo's verification_results dir
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
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
