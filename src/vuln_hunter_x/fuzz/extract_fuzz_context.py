# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""
Stage 6: Extract fuzz-oriented context (sub-stages 6.1–6.3).

Runs CodeQL queries function_signatures.ql and includes.ql,
writes function_signatures.csv and includes.csv for harness generation.
"""

from __future__ import annotations

from pathlib import Path

from vuln_hunter_x.codeql.context_extractor import (
    ContextExtractorDB,
    discover_databases,
)

# Fuzz-specific queries (C/C++ only)
FUZZ_QUERIES = ["function_signatures", "includes"]


def extract_fuzz_context_for_db(
    db_path: Path,
    lang: str,
    repo_name: str,
    repo_context_dir: Path,
    queries_dir: Path,
    codeql_path: str = "codeql",
    dry_run: bool = False,
) -> dict[str, tuple[bool, str]]:
    """
    Sub-stages 6.2–6.3: Run fuzz context queries and write CSVs.

    Args:
        db_path: CodeQL database path
        lang: Language (c or cpp)
        repo_name: Repository name
        repo_context_dir: Repo context dir (e.g. output/<lang>/<repo_name>/context)
        queries_dir: Queries base (e.g. config/queries/tools); cpp/*.ql live under it
        codeql_path: CodeQL CLI path
        dry_run: Only print actions

    Returns:
        Dict mapping query name to (success, message)
    """
    if lang not in ("c", "cpp"):
        return {"error": (False, f"Fuzz context only for c/cpp, got {lang}")}

    extractor = ContextExtractorDB(
        codeql_path=codeql_path,
        queries_dir=queries_dir,
        output_dir=repo_context_dir.parent.parent.parent,  # output_dir for discover; we write to repo_context_dir
    )
    repo_output = repo_context_dir
    repo_output.mkdir(parents=True, exist_ok=True)
    ql_dir = queries_dir / "cpp"
    results: dict[str, tuple[bool, str]] = {}

    for query_name in FUZZ_QUERIES:
        query_path = ql_dir / f"{query_name}.ql"
        if not query_path.is_file():
            results[query_name] = (False, f"Query not found: {query_path}")
            continue
        out_csv = repo_output / f"{query_name}.csv"
        ok, msg = extractor.run_query(db_path, query_path, out_csv, dry_run=dry_run)
        results[query_name] = (ok, msg)

    return results


def extract_fuzz_context_all(
    output_dir: Path,
    queries_dir: Path,
    codeql_path: str = "codeql",
    lang_filter: str | None = None,
    repo_filter: str | None = None,
    dry_run: bool = False,
) -> list[tuple[str, str, dict[str, tuple[bool, str]]]]:
    """
    Extract fuzz context for all C/C++ databases under output_dir.
    Writes to output_dir/<lang>/<repo_name>/context/.

    Returns:
        List of (repo_name, lang, results_dict)
    """
    dbs = discover_databases(output_dir)
    dbs = [(p, lang, n) for p, lang, n in dbs if lang in ("c", "cpp")]
    if lang_filter:
        dbs = [(p, lang, n) for p, lang, n in dbs if lang == lang_filter]
    if repo_filter:
        dbs = [(p, lang, n) for p, lang, n in dbs if n.lower() == repo_filter.lower()]

    out: list[tuple[str, str, dict[str, tuple[bool, str]]]] = []
    for db_path, lang, repo_name in dbs:
        repo_context_dir = output_dir / lang / repo_name / "context"
        res = extract_fuzz_context_for_db(
            db_path,
            lang,
            repo_name,
            repo_context_dir,
            queries_dir,
            codeql_path,
            dry_run,
        )
        out.append((repo_name, lang, res))
    return out
