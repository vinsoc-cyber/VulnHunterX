"""Extract context information from CodeQL databases to CSV files."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Optional


# Query files by language
QUERIES_BY_LANG: dict[str, list[str]] = {
    "c": ["functions", "callers", "structs", "globals", "macros"],
    "cpp": ["functions", "callers", "structs", "globals", "macros"],
    "python": ["functions", "callers", "classes"],
    "javascript": ["functions", "callers", "classes"],
}

# Map language to CodeQL library folder
LANG_TO_QL_DIR: dict[str, str] = {
    "c": "cpp",
    "cpp": "cpp",
    "python": "python",
    "javascript": "javascript",
}


def discover_databases(databases_dir: Path) -> list[tuple[Path, str, str]]:
    """
    Discover CodeQL databases.
    
    Args:
        databases_dir: Base directory containing databases
        
    Returns:
        List of (db_path, lang, name) tuples
    """
    results: list[tuple[Path, str, str]] = []
    
    if not databases_dir.is_dir():
        return results
    
    for lang_dir in databases_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        
        lang = lang_dir.name.lower()
        if lang not in QUERIES_BY_LANG:
            continue
        
        for name_dir in lang_dir.iterdir():
            if not name_dir.is_dir():
                continue
            
            # Check for CodeQL database markers
            if (name_dir / "codeql-database.yml").exists():
                results.append((name_dir, lang, name_dir.name))
            elif (name_dir / "log").exists():
                results.append((name_dir, lang, name_dir.name))
    
    return results


class ContextExtractorDB:
    """Extracts context from CodeQL databases to CSV files."""
    
    def __init__(
        self,
        codeql_path: str = "codeql",
        queries_dir: Optional[Path] = None,
        output_dir: Optional[Path] = None,
    ):
        self.codeql_path = codeql_path
        self.queries_dir = queries_dir or Path("config/queries/tools")
        self.output_dir = output_dir or Path("config/context")
    
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
                    "--database", str(db_path),
                    "--output", str(bqrs_path),
                    "--",
                    str(query_path),
                ],
                capture_output=True,
                text=True,
                timeout=600,
            )
            
            if result.returncode != 0:
                return False, f"Query failed: {result.stderr[:200]}"
            
            # Convert BQRS to CSV
            result = subprocess.run(
                [
                    self.codeql_path,
                    "bqrs",
                    "decode",
                    "--format=csv",
                    "--output", str(output_csv),
                    str(bqrs_path),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            
            if result.returncode != 0:
                return False, f"Decode failed: {result.stderr[:200]}"
            
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
        
        repo_output_dir = self.output_dir / repo_name
        
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
        databases_dir: Path,
        lang_filter: Optional[str] = None,
        repo_filter: Optional[str] = None,
        dry_run: bool = False,
    ) -> list[tuple[str, str, dict[str, tuple[bool, str]]]]:
        """
        Extract context for all databases.
        
        Args:
            databases_dir: Directory containing CodeQL databases
            lang_filter: Only process this language
            repo_filter: Only process this repository
            dry_run: Only print actions
            
        Returns:
            List of (repo_name, lang, results_dict) tuples
        """
        dbs = discover_databases(databases_dir)
        
        if lang_filter:
            dbs = [(p, l, n) for p, l, n in dbs if l == lang_filter]
        if repo_filter:
            dbs = [(p, l, n) for p, l, n in dbs if n.lower() == repo_filter.lower()]
        
        all_results: list[tuple[str, str, dict[str, tuple[bool, str]]]] = []
        
        for db_path, lang, repo_name in dbs:
            results = self.extract_for_database(db_path, lang, repo_name, dry_run)
            all_results.append((repo_name, lang, results))
        
        return all_results
