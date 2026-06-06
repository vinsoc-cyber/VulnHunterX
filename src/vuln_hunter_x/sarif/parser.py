# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""SARIF file parsing and finding extraction."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from vuln_hunter_x.core.types import Finding

# Canonical tool name labels keyed by lowercase binary/driver name.
# Applied after extracting tool.driver.name to ensure consistent naming
# regardless of how the SARIF producer emits the driver name.
_TOOL_NAME_MAP: dict[str, str] = {
    "codeql": "CodeQL",
    "semgrep": "Semgrep",
    "opengrep": "OpenGrep",
}

# Code-quality / maintainability rules that the CodeQL security suites pull in
# but which are NOT vulnerabilities. Verifying them as "findings" is pure noise
# (on dealer-portal-api: js/unused-local-variable = 63 findings / 0 True
# Positives, js/trivial-conditional similar) and burns LLM tokens before the
# verifier can dismiss them. Dropped at parse time so they never reach
# verification. Matched case-insensitively against the rule's short id (the
# segment after the last '/'), so language prefixes (js/, py/, cpp/) are covered.
_NON_SECURITY_RULE_SUFFIXES: frozenset[str] = frozenset(
    {
        "unused-local-variable",
        "trivial-conditional",
        "unused-variable",
        "unreachable-statement",
        "dead-store",
        "useless-assignment",
        "useless-assignment-to-local",
        "useless-assignment-to-property",
        "duplicate-condition",
        "comparison-of-identical-expressions",
        # Code-quality lint observed flooding SPA scans (eoffice-superweb):
        # maintainability smells, not vulnerabilities.
        "redundant-operation",
        "unneeded-defensive-code",
        "useless-expression",
        "useless-comparison-test",
        "inconsistent-use-of-new",
        "duplicate-property",
    }
)


def _is_non_security_rule(rule_id: str) -> bool:
    """True if *rule_id* is a code-quality lint, not a security finding."""
    if not rule_id:
        return False
    short = rule_id.rsplit("/", 1)[-1].lower()
    return short in _NON_SECURITY_RULE_SUFFIXES


def _normalize_tool_name(raw: str) -> str:
    """Return the canonical tool label for *raw*, or *raw* unchanged if unknown."""
    return _TOOL_NAME_MAP.get(raw.lower(), raw)


def _extract_thread_flow_locations(thread_flow: dict) -> list[str]:
    """Extract location entries from a single thread flow."""
    path: list[str] = []
    for loc in thread_flow.get("locations", []):
        phys = (loc.get("location") or {}).get("physicalLocation") or {}
        line = (phys.get("region") or {}).get("startLine", 0)
        msg = ((loc.get("location") or {}).get("message") or {}).get("text", "")
        if line:
            path.append(f"line {line}: {msg}" if msg else f"line {line}")
    return path


def _extract_dataflow_path(code_flows: list) -> list[str]:
    """Extract dataflow path from SARIF codeFlows.

    Iterates ALL code flows and ALL thread flows to capture every
    dataflow path the analysis found.  Multiple flows are separated
    by ``--- Flow N ---`` markers.

    Returns a list of strings like "line 12: message text".
    """
    if not code_flows:
        return []
    try:
        all_paths: list[list[str]] = []
        seen: set[tuple[str, ...]] = set()

        for cf in code_flows:
            for tf in cf.get("threadFlows", []):
                path = _extract_thread_flow_locations(tf)
                if not path:
                    continue
                key = tuple(path)
                if key not in seen:
                    seen.add(key)
                    all_paths.append(path)

        if not all_paths:
            return []

        # Single flow — return as flat list (backward compatible)
        if len(all_paths) == 1:
            return all_paths[0]

        # Multiple flows — separate with markers
        result: list[str] = []
        for i, path in enumerate(all_paths):
            result.append(f"--- Flow {i + 1} ---")
            result.extend(path)
        return result
    except (IndexError, AttributeError, TypeError):
        return []


def _build_rule_lookup(run: dict) -> dict[str, dict]:
    """Build a lookup dict of rule_id -> {precision, security_severity, tags} from run.tool.driver.rules."""
    lookup: dict[str, dict] = {}
    driver = (run.get("tool") or {}).get("driver") or {}
    rules = driver.get("rules") or []
    for rule in rules:
        rule_id = rule.get("id") or ""
        if not rule_id:
            continue
        props = rule.get("properties") or {}
        tags = [t for t in (props.get("tags") or []) if isinstance(t, str)]
        lookup[rule_id] = {
            "precision": props.get("precision") or "",
            "security_severity": props.get("security-severity") or "",
            "tags": tags,
        }
    return lookup


def _extract_related_locations(related_locs: list) -> list[str]:
    """Format relatedLocations as 'file.c:42: message text'."""
    formatted = []
    for rl in related_locs or []:
        loc = rl.get("location") or {}
        phys = loc.get("physicalLocation") or {}
        uri = (phys.get("artifactLocation") or {}).get("uri") or ""
        line = (phys.get("region") or {}).get("startLine") or 0
        msg = (loc.get("message") or {}).get("text") or ""
        if uri or line:
            parts = []
            if uri:
                parts.append(uri)
            if line:
                if parts:
                    parts[-1] = f"{parts[-1]}:{line}"
                else:
                    parts.append(str(line))
            entry = parts[0] if parts else ""
            if msg:
                entry = f"{entry}: {msg}" if entry else msg
            if entry:
                formatted.append(entry)
    return formatted


class SarifParser:
    """Parser for SARIF (Static Analysis Results Interchange Format) files."""

    def __init__(self, sarif_path: Path):
        """Initialize the SARIF parser.

        Args:
            sarif_path: Path to the SARIF file to parse.
        """
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
            rule_lookup = _build_rule_lookup(run)

            # Extract tool name from SARIF standard field
            tool_name = (run.get("tool") or {}).get("driver", {}).get("name", "")
            if tool_name:
                # Normalize known binary/driver names to canonical labels
                # (e.g. "opengrep" -> "OpenGrep", "semgrep" -> "Semgrep")
                tool_name = _normalize_tool_name(tool_name)
            else:
                # Fallback: infer from file name
                fname = self.sarif_path.name
                if fname.endswith("_semgrep.sarif"):
                    tool_name = "Semgrep"
                elif fname.endswith("_opengrep.sarif"):
                    tool_name = "OpenGrep"
                else:
                    tool_name = "CodeQL"

            for result in run.get("results", []):
                rule_id = result.get("ruleId") or ""
                # Drop code-quality lint that the security suite drags in — it
                # is never a vulnerability and only adds verification noise/cost.
                if _is_non_security_rule(rule_id):
                    continue
                message = (result.get("message") or {}).get("text") or ""
                dataflow_path = _extract_dataflow_path(result.get("codeFlows", []))
                related_locations = _extract_related_locations(result.get("relatedLocations") or [])

                # Extract metadata from rule lookup
                rule_meta = rule_lookup.get(rule_id) or {}
                precision = rule_meta.get("precision") or ""
                all_tags = rule_meta.get("tags") or []
                cwe_ids = [t for t in all_tags if t.startswith("CWE-")]
                non_cwe_tags = [t for t in all_tags if not t.startswith("CWE-")]
                security_severity = rule_meta.get("security_severity") or ""

                # Severity: prefer security-severity score, fallback to result level
                severity = security_severity or result.get("level") or ""

                locations = result.get("locations") or []

                for loc in locations:
                    phys = loc.get("physicalLocation") or {}
                    art_ref = phys.get("artifactLocation") or {}

                    # Get file URI
                    uri = art_ref.get("uri") or ""
                    art_index = art_ref.get("index")
                    if art_index is not None and art_index in artifacts:
                        uri = artifacts[art_index].get("location", {}).get("uri") or uri

                    # Get line numbers (SARIF line numbers are 1-indexed)
                    region = phys.get("region") or {}
                    start_line = region.get("startLine") or 1
                    end_line = region.get("endLine") or start_line

                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            message=message,
                            file=uri,
                            start_line=start_line,
                            end_line=end_line,
                            repo_name=repo_name,
                            lang=lang,
                            sarif_path=str(self.sarif_path),
                            tool=tool_name,
                            dataflow_path=dataflow_path,
                            severity=severity,
                            precision=precision,
                            cwe_ids=cwe_ids,
                            tags=non_cwe_tags,
                            related_locations=related_locations,
                        )
                    )

                # Handle results without locations
                if not locations:
                    findings.append(
                        Finding(
                            rule_id=rule_id,
                            message=message,
                            file="",
                            start_line=0,
                            end_line=0,
                            repo_name=repo_name,
                            lang=lang,
                            sarif_path=str(self.sarif_path),
                            tool=tool_name,
                            dataflow_path=dataflow_path,
                            severity=severity,
                            precision=precision,
                            cwe_ids=cwe_ids,
                            tags=non_cwe_tags,
                            related_locations=related_locations,
                        )
                    )

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
    Discover SARIF files under output/<lang>/<repo_name>/.

    All *.sarif files in each repo directory are included (CodeQL and Semgrep).
    repo_name is taken from the directory name for context lookup.

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
            for sarif_file in sorted(repo_dir.glob("*.sarif")):
                results.append((sarif_file, lang, repo_name))

    return results
