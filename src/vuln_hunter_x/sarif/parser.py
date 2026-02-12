"""SARIF file parsing and finding extraction."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from vuln_hunter_x.core.types import Finding


class SarifParser:
    """Parser for SARIF (Static Analysis Results Interchange Format) files."""
    
    def __init__(self, sarif_path: Path):
        self.sarif_path = Path(sarif_path)
        self._data: dict | None = None
    
    @property
    def data(self) -> dict:
        """Lazy load SARIF data."""
        if self._data is None:
            self._data = self._load()
        return self._data
    
    def _load(self) -> dict[str, Any]:
        """Load SARIF file."""
        if not self.sarif_path.is_file():
            raise FileNotFoundError(f"SARIF file not found: {self.sarif_path}")
        
        with open(self.sarif_path, encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    
    def get_runs(self) -> list[dict[str, Any]]:
        """Get all runs from SARIF data."""
        runs = self.data.get("runs", [])
        return runs if isinstance(runs, list) else []
    
    def get_results(self, run_index: int = 0) -> list[dict[str, Any]]:
        """Get results from a specific run."""
        runs = self.get_runs()
        if run_index >= len(runs):
            return []
        results = runs[run_index].get("results", [])
        return results if isinstance(results, list) else []
    
    def get_artifacts(self, run_index: int = 0) -> dict[int, dict]:
        """Get artifacts (file info) from a specific run, indexed by index."""
        runs = self.get_runs()
        if run_index >= len(runs):
            return {}
        
        artifacts = runs[run_index].get("artifacts", [])
        return {i: art for i, art in enumerate(artifacts)}
    
    def parse_findings(
        self,
        lang: str,
        repo_name: str,
    ) -> list[Finding]:
        """
        Parse all findings from the SARIF file.
        
        Args:
            lang: Language of the codebase (c, cpp, python, javascript)
            repo_name: Name of the repository
            
        Returns:
            List of Finding objects
        """
        findings: list[Finding] = []
        
        for run in self.get_runs():
            artifacts = {i: art for i, art in enumerate(run.get("artifacts", []))}
            
            for result in run.get("results", []):
                rule_id = result.get("ruleId") or ""
                message = (result.get("message") or {}).get("text") or ""
                
                locations = result.get("locations") or []
                
                for loc in locations:
                    phys = (loc.get("physicalLocation") or {})
                    art_ref = phys.get("artifactLocation") or {}
                    
                    # Get file URI
                    uri = art_ref.get("uri") or ""
                    art_index = art_ref.get("index")
                    if art_index is not None and art_index in artifacts:
                        uri = artifacts[art_index].get("location", {}).get("uri") or uri
                    
                    # Get line numbers
                    region = phys.get("region") or {}
                    start_line = region.get("startLine") or 0
                    end_line = region.get("endLine") or start_line
                    
                    findings.append(Finding(
                        rule_id=rule_id,
                        message=message,
                        file=uri,
                        start_line=start_line,
                        end_line=end_line,
                        repo_name=repo_name,
                        lang=lang,
                        sarif_path=str(self.sarif_path),
                    ))
                
                # Handle results without locations
                if not locations:
                    findings.append(Finding(
                        rule_id=rule_id,
                        message=message,
                        file="",
                        start_line=0,
                        end_line=0,
                        repo_name=repo_name,
                        lang=lang,
                        sarif_path=str(self.sarif_path),
                    ))
        
        return findings
    
    def __iter__(self) -> Iterator[dict]:
        """Iterate over all results."""
        for run in self.get_runs():
            yield from run.get("results", [])


def parse_sarif_file(
    sarif_path: Path,
    lang: str,
    repo_name: str,
) -> list[Finding]:
    """
    Convenience function to parse a SARIF file.
    
    Args:
        sarif_path: Path to the SARIF file
        lang: Language of the codebase
        repo_name: Name of the repository
        
    Returns:
        List of Finding objects
    """
    parser = SarifParser(sarif_path)
    return parser.parse_findings(lang, repo_name)


def discover_sarif_files(output_dir: Path) -> list[tuple[Path, str, str]]:
    """
    Discover SARIF files under output/<lang>/<repo_name>/<repo_name>.sarif.
    
    Args:
        output_dir: Base output directory
        
    Returns:
        List of (sarif_path, lang, repo_name) tuples
    """
    if not output_dir.is_dir():
        return []
    
    results: list[tuple[Path, str, str]] = []
    
    for lang_dir in output_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        lang = lang_dir.name
        
        for repo_dir in lang_dir.iterdir():
            if not repo_dir.is_dir():
                continue
            repo_name = repo_dir.name
            sarif_file = repo_dir / f"{repo_name}.sarif"
            if sarif_file.is_file():
                results.append((sarif_file, lang, repo_name))
    
    return results
