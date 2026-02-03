#!/usr/bin/env python3
"""
Extract context information from CodeQL databases to CSV files.

This script runs CodeQL tool queries on databases to extract:
- Function boundaries (name, file, start_line, end_line)
- Caller relationships (which functions call which)
- Struct/class definitions
- Global variables
- Macro definitions

The output CSV files enable fast context lookup (~3 seconds) instead of
running dynamic CodeQL queries (which take ~2.5 minutes each).

Usage:
  python scripts/extract_context.py [--db-dir PATH] [--output-dir PATH]
                                    [--lang LANG] [--repo NAME] [--dry-run]

Output:
  config/context/<repo>/
    functions.csv    # name, file, start_line, end_line
    callers.csv      # callee_name, callee_file, caller_name, caller_file, ...
    structs.csv      # name, file, start_line, end_line (C/C++ only)
    globals.csv      # name, file, line, type (C/C++ only)
    macros.csv       # name, file, line, body (C/C++ only)
    classes.csv      # name, file, start_line, end_line (Python/JS)
"""

from __future__ import annotations

import argparse
import csv
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Load .env from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
if _REPO_ROOT.joinpath(".env").exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_REPO_ROOT / ".env")
    except ImportError:
        pass

# Query files by language
_QUERIES: dict[str, list[str]] = {
    "c": ["functions", "callers", "structs", "globals", "macros"],
    "cpp": ["functions", "callers", "structs", "globals", "macros"],
    "python": ["functions", "callers", "classes"],
    "javascript": ["functions", "callers", "classes"],
}

# Map language to CodeQL library folder
_LANG_TO_QL_DIR: dict[str, str] = {
    "c": "cpp",
    "cpp": "cpp",
    "python": "python",
    "javascript": "javascript",
}


def discover_dbs(databases_dir: Path) -> list[tuple[Path, str, str]]:
    """Discover CodeQL DBs under databases/<lang>/<name>/. Returns [(db_path, lang, name), ...]."""
    out: list[tuple[Path, str, str]] = []
    if not databases_dir.is_dir():
        return out
    for lang_dir in databases_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        lang = lang_dir.name.lower()
        if lang not in _QUERIES:
            continue
        for name_dir in lang_dir.iterdir():
            if not name_dir.is_dir():
                continue
            # CodeQL 2.x: DB root has codeql-database.yml
            if (name_dir / "codeql-database.yml").exists():
                out.append((name_dir, lang, name_dir.name))
            elif (name_dir / "log").exists():
                # Older layout: log dir indicates DB root
                out.append((name_dir, lang, name_dir.name))
    return out


def run_query(
    db_path: Path,
    query_path: Path,
    output_csv: Path,
    codeql_path: str,
    dry_run: bool,
) -> bool:
    """Run a CodeQL query and output to CSV."""
    if dry_run:
        print(f"    [dry-run] codeql query run {query_path} -> {output_csv}")
        return True

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    # Use codeql query run with CSV output
    bqrs_path = output_csv.with_suffix(".bqrs")

    try:
        # Run query to BQRS
        result = subprocess.run(
            [
                codeql_path,
                "query",
                "run",
                "--database", str(db_path),
                "--output", str(bqrs_path),
                "--",
                str(query_path),
            ],
            capture_output=True,
            text=True,
            timeout=600,  # 10 minute timeout
            cwd=_REPO_ROOT,
        )

        if result.returncode != 0:
            print(f"    query failed: {result.stderr[:200]}", file=sys.stderr)
            return False

        # Convert BQRS to CSV
        result = subprocess.run(
            [
                codeql_path,
                "bqrs",
                "decode",
                "--format=csv",
                "--output", str(output_csv),
                str(bqrs_path),
            ],
            capture_output=True,
            text=True,
            timeout=60,
            cwd=_REPO_ROOT,
        )

        if result.returncode != 0:
            print(f"    decode failed: {result.stderr[:200]}", file=sys.stderr)
            return False

        # Clean up BQRS file
        bqrs_path.unlink(missing_ok=True)
        return True

    except subprocess.TimeoutExpired:
        print("    query timed out", file=sys.stderr)
        return False
    except Exception as e:
        print(f"    error: {e}", file=sys.stderr)
        return False


def extract_context_for_db(
    db_path: Path,
    lang: str,
    repo_name: str,
    queries_dir: Path,
    output_dir: Path,
    codeql_path: str,
    dry_run: bool,
) -> dict[str, bool]:
    """Extract all context CSVs for a single database."""
    results: dict[str, bool] = {}

    ql_lang = _LANG_TO_QL_DIR.get(lang, lang)
    lang_queries_dir = queries_dir / ql_lang

    if not lang_queries_dir.is_dir():
        print(f"  Warning: No queries found at {lang_queries_dir}", file=sys.stderr)
        return results

    repo_output_dir = output_dir / repo_name

    for query_name in _QUERIES.get(lang, []):
        query_path = lang_queries_dir / f"{query_name}.ql"
        if not query_path.is_file():
            print(f"    {query_name}: query file not found", file=sys.stderr)
            results[query_name] = False
            continue

        output_csv = repo_output_dir / f"{query_name}.csv"
        print(f"    {query_name} -> {output_csv.name}")

        success = run_query(db_path, query_path, output_csv, codeql_path, dry_run)
        results[query_name] = success

    return results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Extract context information from CodeQL databases to CSV files.",
    )
    parser.add_argument(
        "--db-dir",
        type=Path,
        default=_REPO_ROOT / "databases",
        help="Directory containing CodeQL databases",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "data" / "context",
        help="Output directory for context CSVs",
    )
    parser.add_argument(
        "--queries-dir",
        type=Path,
        default=_REPO_ROOT / "data" / "queries" / "tools",
        help="Directory containing CodeQL tool queries",
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript"],
        help="Only process databases of this language",
    )
    parser.add_argument(
        "--repo",
        metavar="NAME",
        help="Only process database for this repo",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")
    args = parser.parse_args()

    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    if not args.dry_run and not shutil.which(codeql_path):
        print(f"CodeQL not found: {codeql_path}. Set CODEQL_PATH or install CodeQL CLI.", file=sys.stderr)
        return 1

    dbs = discover_dbs(args.db_dir)
    if args.lang:
        dbs = [(p, lang, name) for p, lang, name in dbs if lang == args.lang]
    if args.repo:
        dbs = [(p, lang, name) for p, lang, name in dbs if name.lower() == args.repo.lower()]

    if not dbs:
        print("No CodeQL databases found. Run Phase 2 first (clone_and_db.py).", file=sys.stderr)
        return 1

    print(f"Extracting context from {len(dbs)} database(s)...\n")

    total_queries = 0
    successful_queries = 0

    for db_path, lang, repo_name in dbs:
        print(f"[{repo_name}] {lang}")
        results = extract_context_for_db(
            db_path=db_path,
            lang=lang,
            repo_name=repo_name,
            queries_dir=args.queries_dir,
            output_dir=args.output_dir,
            codeql_path=codeql_path,
            dry_run=args.dry_run,
        )
        total_queries += len(results)
        successful_queries += sum(1 for v in results.values() if v)

    print(f"\nDone. Extracted {successful_queries}/{total_queries} context files.")
    return 0 if successful_queries == total_queries else 1


if __name__ == "__main__":
    sys.exit(main())
