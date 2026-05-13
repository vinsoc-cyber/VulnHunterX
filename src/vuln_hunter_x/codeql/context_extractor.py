# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Extract context information from CodeQL databases to CSV files."""

from __future__ import annotations

import subprocess
from pathlib import Path

# Query files by language
QUERIES_BY_LANG: dict[str, list[str]] = {
    "c": ["functions", "callers", "structs", "globals", "macros", "free_sites", "destructors", "field_writes"],
    "cpp": ["functions", "callers", "structs", "globals", "macros", "free_sites", "destructors", "field_writes"],
    "python": ["functions", "callers", "classes"],
    "javascript": ["functions", "callers", "classes"],
    "php": ["functions", "callers", "classes"],
    "java": ["functions", "callers", "classes"],
    "go": ["functions", "callers", "classes"],
}

# Map language to CodeQL library folder
LANG_TO_QL_DIR: dict[str, str] = {
    "c": "cpp",
    "cpp": "cpp",
    "python": "python",
    "javascript": "javascript",
    "php": "php",
    "java": "java",
    "go": "go",
}


def _clean_codeql_stderr(stderr: str, max_len: int = 400) -> str:
    """Extract the meaningful error from CodeQL stderr.

    CodeQL prepends a perf warning when its distribution lives under $HOME
    ("This CodeQL Distribution is installed in '...', which is the home directory.
    This could cause performance issues..."). That warning is ~220 chars and would
    otherwise swallow the entire error budget, hiding the real failure that lands
    at the tail of stderr. Strip the known noise and keep the tail.
    """
    if not stderr:
        return ""
    lines = [
        ln for ln in stderr.splitlines()
        if "is the home directory" not in ln
        and "performance issues" not in ln
        and "Consider moving to a new location" not in ln
    ]
    cleaned = "\n".join(lines).strip()
    if len(cleaned) <= max_len:
        return cleaned
    return "... " + cleaned[-max_len:]


def discover_databases(output_dir: Path) -> list[tuple[Path, str, str]]:
    """
    Discover CodeQL databases under output_dir/<lang>/<repo_name>/database.

    Args:
        output_dir: Base output directory (output/<lang>/<repo_name>/database)

    Returns:
        List of (db_path, lang, repo_name) tuples
    """
    results: list[tuple[Path, str, str]] = []

    if not output_dir.is_dir():
        return results

    for lang_dir in output_dir.iterdir():
        if not lang_dir.is_dir():
            continue

        lang = lang_dir.name.lower()
        if lang not in QUERIES_BY_LANG:
            continue

        for repo_dir in lang_dir.iterdir():
            if not repo_dir.is_dir():
                continue

            repo_name = repo_dir.name
            db_dir = repo_dir / "database"
            if (db_dir / "codeql-database.yml").exists() or (db_dir / "log").exists():
                results.append((db_dir, lang, repo_name))

    return results


class ContextExtractorDB:
    """Extracts context from CodeQL databases to CSV files."""

    def __init__(
        self,
        codeql_path: str = "codeql",
        queries_dir: Path | None = None,
        output_dir: Path | None = None,
    ):
        self.codeql_path = codeql_path
        self.queries_dir = queries_dir or Path("config/queries/tools")
        self.output_dir = output_dir or Path("output")

    def run_query(
        self,
        db_path: Path,
        query_path: Path,
        output_csv: Path,
        dry_run: bool = False,
    ) -> tuple[bool, str]:
        """
        Run a CodeQL query and output to CSV.

        Args:
            db_path: Path to CodeQL database
            query_path: Path to .ql file
            output_csv: Output CSV path
            dry_run: Only print actions

        Returns:
            Tuple of (success, message)
        """
        if dry_run:
            return True, f"[dry-run] {query_path.name} -> {output_csv.name}"

        output_csv.parent.mkdir(parents=True, exist_ok=True)
        bqrs_path = output_csv.with_suffix(".bqrs")

        try:
            # Run query to BQRS
            result = subprocess.run(
                [
                    self.codeql_path,
                    "query",
                    "run",
                    "--database",
                    str(db_path),
                    "--output",
                    str(bqrs_path),
                    "--",
                    str(query_path),
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode != 0:
                return False, f"Query failed: {_clean_codeql_stderr(result.stderr)}"

            # Convert BQRS to CSV
            result = subprocess.run(
                [
                    self.codeql_path,
                    "bqrs",
                    "decode",
                    "--format=csv",
                    "--output",
                    str(output_csv),
                    str(bqrs_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )

            if result.returncode != 0:
                return False, f"Decode failed: {_clean_codeql_stderr(result.stderr)}"

            # Clean up
            bqrs_path.unlink(missing_ok=True)
            return True, f"Created {output_csv.name}"

        except subprocess.TimeoutExpired:
            return False, "Query timed out"
        except Exception as e:
            return False, str(e)

    def extract_for_database(
        self,
        db_path: Path,
        lang: str,
        repo_name: str,
        dry_run: bool = False,
    ) -> dict[str, tuple[bool, str]]:
        """
        Extract all context CSVs for a single database.

        Args:
            db_path: Path to CodeQL database
            lang: Programming language
            repo_name: Repository name
            dry_run: Only print actions

        Returns:
            Dict mapping query name to (success, message)
        """
        results: dict[str, tuple[bool, str]] = {}

        ql_lang = LANG_TO_QL_DIR.get(lang, lang)
        lang_queries_dir = self.queries_dir / ql_lang

        if not lang_queries_dir.is_dir():
            return {"error": (False, f"No queries at {lang_queries_dir}")}

        repo_output_dir = self.output_dir / lang / repo_name / "context"

        for query_name in QUERIES_BY_LANG.get(lang, []):
            query_path = lang_queries_dir / f"{query_name}.ql"

            if not query_path.is_file():
                results[query_name] = (False, "Query file not found")
                continue

            output_csv = repo_output_dir / f"{query_name}.csv"
            ok, msg = self.run_query(db_path, query_path, output_csv, dry_run)
            results[query_name] = (ok, msg)

        return results

    def extract_all(
        self,
        output_dir: Path,
        lang_filter: str | None = None,
        repo_filter: str | None = None,
        dry_run: bool = False,
    ) -> list[tuple[str, str, dict[str, tuple[bool, str]]]]:
        """
        Extract context for all databases under output_dir/<lang>/<repo>/database.

        Args:
            output_dir: Base output directory
            lang_filter: Only process this language
            repo_filter: Only process this repository
            dry_run: Only print actions

        Returns:
            List of (repo_name, lang, results_dict) tuples
        """
        dbs = discover_databases(output_dir)

        if lang_filter:
            dbs = [(p, lang, n) for p, lang, n in dbs if lang == lang_filter]
        if repo_filter:
            dbs = [(p, lang, n) for p, lang, n in dbs if n.lower() == repo_filter.lower()]

        all_results: list[tuple[str, str, dict[str, tuple[bool, str]]]] = []

        for db_path, lang, repo_name in dbs:
            results = self.extract_for_database(db_path, lang, repo_name, dry_run)
            all_results.append((repo_name, lang, results))

        return all_results
