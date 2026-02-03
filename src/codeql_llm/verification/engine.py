"""Verification engine orchestrating the LLM bug verification flow."""

from __future__ import annotations

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Callable, Iterator, Optional

from codeql_llm.core.config import Config, load_config
from codeql_llm.core.types import Finding, Verdict, VerificationResult
from codeql_llm.sarif.parser import parse_sarif_file, discover_sarif_files
from codeql_llm.context.extractor import ContextExtractor
from codeql_llm.context.provider import ContextProvider
from codeql_llm.questions.loader import QuestionsLoader
from codeql_llm.llm.client import LLMClient


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
        results = engine.verify_sarif("output/sarif/c/repo.sarif", lang="c", repo="repo")
        
        for verdict in results.verdicts:
            print(f"{verdict.finding.rule_id}: {verdict.verdict}")
    """
    
    def __init__(
        self,
        config: Config,
        questions_loader: Optional[QuestionsLoader] = None,
        context_extractor: Optional[ContextExtractor] = None,
        context_provider: Optional[ContextProvider] = None,
        llm_client: Optional[LLMClient] = None,
    ):
        self.config = config
        
        # Initialize components
        self.questions_loader = questions_loader or QuestionsLoader(config.paths.prompts_dir)
        self.context_extractor = context_extractor or ContextExtractor(config.paths.repos_dir)
        
        if config.verification.is_vulnhalla:
            self.context_provider = context_provider or ContextProvider(
                config.paths.context_dir,
                config.paths.repos_dir,
            )
        else:
            self.context_provider = None
        
        self.llm_client = llm_client or LLMClient(
            provider=config.llm.provider,
            model=config.llm.model,
            mode=config.verification.mode,
            temperature=config.llm.temperature,
            max_tokens=config.llm.max_tokens,
        )
        
        # Callbacks for progress reporting
        self._on_finding_start: Optional[Callable[[int, int, Finding], None]] = None
        self._on_finding_complete: Optional[Callable[[int, int, Verdict], None]] = None
    
    @classmethod
    def from_config(
        cls,
        config_path: Optional[Path] = None,
        base_path: Optional[Path] = None,
        **overrides,
    ) -> "VerificationEngine":
        """
        Create engine from configuration file.
        
        Args:
            config_path: Path to configuration YAML file
            base_path: Base path for resolving relative paths
            **overrides: Override config values
            
        Returns:
            Configured VerificationEngine
        """
        if config_path:
            config = load_config(Path(config_path), base_path)
        else:
            config = Config()
        
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
    ) -> VerificationResult:
        """
        Verify findings from a single SARIF file.
        
        Args:
            sarif_path: Path to the SARIF file
            lang: Language of the codebase
            repo_name: Name of the repository
            limit: Maximum findings to process (0 = all)
            
        Returns:
            VerificationResult with all verdicts
        """
        findings = parse_sarif_file(Path(sarif_path), lang, repo_name)
        return self.verify_findings(findings, limit)
    
    def verify_all_sarif(
        self,
        output_dir: Optional[Path] = None,
        lang_filter: Optional[str] = None,
        repo_filter: Optional[str] = None,
        limit: int = 0,
    ) -> VerificationResult:
        """
        Verify findings from all SARIF files in output directory.
        
        Args:
            output_dir: Base output directory (default: from config)
            lang_filter: Only process this language
            repo_filter: Only process this repository
            limit: Maximum total findings to process (0 = all)
            
        Returns:
            VerificationResult with all verdicts
        """
        output_dir = output_dir or self.config.paths.output_dir
        sarif_files = discover_sarif_files(output_dir)
        
        if lang_filter:
            sarif_files = [(p, l, n) for p, l, n in sarif_files if l == lang_filter]
        if repo_filter:
            sarif_files = [(p, l, n) for p, l, n in sarif_files 
                          if n.lower() == repo_filter.lower()]
        
        # Collect all findings
        all_findings: list[Finding] = []
        for sarif_path, lang, repo_name in sarif_files:
            findings = parse_sarif_file(sarif_path, lang, repo_name)
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
            mode=self.config.verification.mode,
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
        )
        
        return verdict
    
    def save_results(
        self,
        result: VerificationResult,
        output_dir: Optional[Path] = None,
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
        results_dir = output_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Save individual results
        for verdict in result.verdicts:
            finding = verdict.finding
            result_file = (
                results_dir / finding.lang / finding.repo_name /
                f"{finding.rule_id.replace('/', '_')}_{finding.start_line}.json"
            )
            result_file.parent.mkdir(parents=True, exist_ok=True)
            result_file.write_text(json.dumps(verdict.to_dict(), indent=2))
        
        # Save summary
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        summary_file = results_dir / f"summary_{result.mode}_{timestamp}.json"
        summary_file.write_text(json.dumps(result.to_dict(), indent=2))
        
        return summary_file, results_dir
