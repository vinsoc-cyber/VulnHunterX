"""CLI command implementations for vuln-hunter-x."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from vuln_hunter_x import __version__
from vuln_hunter_x.core.config import Config, load_config
from vuln_hunter_x.core.types import Finding, Verdict


def cmd_check_env(args: argparse.Namespace) -> int:
    """Execute check-env command."""
    from vuln_hunter_x.cli.env import run_env_check

    results = run_env_check()

    # Check if CodeQL is available (required)
    codeql_ok = results.get("codeql", (False, ""))[0]

    if codeql_ok:
        print("Environment check passed. CodeQL is available.")
        return 0
    else:
        print("Environment check failed. CodeQL is required for analysis.")
        return 1


def cmd_clone(args: argparse.Namespace) -> int:
    """Execute clone command."""
    from vuln_hunter_x.codeql.repository import RepositoryManager

    base_path = Path.cwd()
    config_path = args.config or base_path / "config" / "repos.yaml"

    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    codeql_path = os.environ.get("CODEQL_PATH", "codeql")

    manager = RepositoryManager(
        repos_dir=base_path / "repos",
        output_dir=base_path / "output",
        codeql_path=codeql_path,
    )

    print("Clone repos and create CodeQL databases\n")

    results = manager.process_repos_config(
        config_path,
        lang_filter=args.lang,
        repo_filter=args.repo,
        skip_clone=args.skip_clone,
        skip_db=args.skip_db,
        dry_run=args.dry_run,
        ask_llm=args.ask_llm,
    )

    ok_count = sum(1 for _, ok, _ in results if ok)

    for name, ok, msg in results:
        status = "OK" if ok else "FAIL"
        print(f"[{name}] [{status}] {msg[:100]}")

    print(f"\nDone. {ok_count}/{len(results)} succeeded.")
    return 0 if ok_count == len(results) else 1


def cmd_analyze(args: argparse.Namespace) -> int:
    """Execute analyze command."""
    from vuln_hunter_x.codeql.analysis import CodeQLAnalyzer
    from vuln_hunter_x.codeql.context_extractor import discover_databases

    base_path = Path.cwd()
    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    verbose = getattr(args, "verbose", False)
    force = getattr(args, "force", False)

    analyzer = CodeQLAnalyzer(
        codeql_path=codeql_path,
        output_dir=base_path / "output",
        verbose=verbose,
    )

    # Set up verbose logging
    if verbose:
        analyzer.set_logger(lambda msg: print(msg))

    output_dir = base_path / "output"
    dbs = discover_databases(output_dir)

    if verbose:
        print(f"Found {len(dbs)} database(s) under {output_dir}")
        for db_path, lang, name in dbs:
            print(f"  - {lang}/{name}: {db_path}")
        print()

    if args.lang:
        dbs = [(p, lang, n) for p, lang, n in dbs if lang == args.lang]
    if args.repo:
        dbs = [(p, lang, n) for p, lang, n in dbs if n.lower() == args.repo.lower()]

    if not dbs:
        print("No CodeQL databases found.", file=sys.stderr)
        if args.lang or args.repo:
            print(f"  Filter: lang={args.lang}, repo={args.repo}", file=sys.stderr)
        return 1

    print(f"Running CodeQL analysis on {len(dbs)} database(s)\n")

    ok_count = 0
    skip_count = 0
    for db_path, lang, name in dbs:
        print(f"[{name}] {lang}")

        # Check if SARIF already exists (skip unless --force)
        sarif_path = base_path / "output" / lang / name / f"{name}.sarif"
        if sarif_path.exists() and not force:
            # Count findings in existing SARIF
            try:
                import json

                with open(sarif_path) as f:
                    sarif_data = json.load(f)
                findings_count = sum(
                    len(run.get("results", []))
                    for run in sarif_data.get("runs", [])
                )
                print(f"  [SKIP] SARIF already exists ({findings_count} findings)")
            except Exception:
                print(f"  [SKIP] SARIF already exists")
            skip_count += 1
            ok_count += 1
            continue

        if args.dry_run:
            suite = analyzer.DEFAULT_SUITES.get(
                "cpp" if lang in ("c", "cpp") else lang
            )
            print(f"  [dry-run] Would analyze {db_path}")
            print(f"  [dry-run] Suite: {suite}")
            print(f"  [dry-run] Output: {sarif_path}")
            ok_count += 1
            continue

        ok, result_path, msg = analyzer.run_analysis(db_path, lang, name)

        if ok:
            ok_count += 1
            print(f"  -> {result_path}")
            print(f"  {msg}")
        else:
            print(f"  FAILED: {msg}", file=sys.stderr)

    if skip_count > 0:
        print(
            f"\nDone. {ok_count}/{len(dbs)} succeeded ({skip_count} skipped, use --force to re-analyze)."
        )
    else:
        print(f"\nDone. {ok_count}/{len(dbs)} succeeded.")
    return 0 if ok_count == len(dbs) else 1


def cmd_extract_context(args: argparse.Namespace) -> int:
    """Execute extract-context command."""
    from vuln_hunter_x.codeql.context_extractor import (
        ContextExtractorDB,
        discover_databases,
    )

    base_path = Path.cwd()
    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    force = getattr(args, "force", False)
    output_dir = base_path / "output"

    # Discover databases first to check for existing context
    dbs = discover_databases(output_dir)

    if args.lang:
        dbs = [(p, lang, n) for p, lang, n in dbs if lang == args.lang]
    if args.repo:
        dbs = [(p, lang, n) for p, lang, n in dbs if n.lower() == args.repo.lower()]

    if not dbs:
        print("No databases found.", file=sys.stderr)
        return 1

    print(f"Extracting context from {len(dbs)} database(s)\n")

    # Check which repos already have context and can be skipped
    repos_to_process = []
    skip_count = 0

    for db_path, lang, name in dbs:
        repo_context_dir = output_dir / lang / name / "context"
        csv_files = (
            list(repo_context_dir.glob("*.csv"))
            if repo_context_dir.exists()
            else []
        )

        if csv_files and not force:
            print(f"[{name}] {lang}")
            print(f"  [SKIP] Context already exists ({len(csv_files)} CSV files)")
            skip_count += 1
        else:
            repos_to_process.append((db_path, lang, name))

    if not repos_to_process:
        print(f"\nDone. All {len(dbs)} repos skipped (use --force to re-extract).")
        return 0

    extractor = ContextExtractorDB(
        codeql_path=codeql_path,
        queries_dir=base_path / "config" / "queries" / "tools",
        output_dir=output_dir,
    )

    # Filter to only process repos that need extraction
    results = extractor.extract_all(
        output_dir=output_dir,
        lang_filter=args.lang,
        repo_filter=args.repo if len(repos_to_process) == len(dbs) else None,
        dry_run=args.dry_run,
    )

    # Filter results to only show repos we're actually processing
    process_names = {name for _, _, name in repos_to_process}
    results = [(name, lang, qr) for name, lang, qr in results if name in process_names]

    total_ok = 0
    total_queries = 0

    for repo_name, lang, query_results in results:
        print(f"[{repo_name}] {lang}")
        for query_name, (ok, msg) in query_results.items():
            status = "OK" if ok else "FAIL"
            print(f"  {query_name}: [{status}] {msg}")
            total_queries += 1
            if ok:
                total_ok += 1

    if skip_count > 0:
        print(
            f"\nDone. {total_ok}/{total_queries} queries succeeded ({skip_count} repos skipped, use --force to re-extract)."
        )
    else:
        print(f"\nDone. {total_ok}/{total_queries} queries succeeded.")
    return 0 if total_ok == total_queries else 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Execute the verify command."""
    from vuln_hunter_x.verification.engine import VerificationEngine

    base_path = Path.cwd()

    # Load config
    if args.config:
        config = load_config(args.config, base_path)
    else:
        default_config = base_path / "config" / "confirm_findings.yaml"
        config = (
            load_config(default_config, base_path)
            if default_config.exists()
            else Config()
        )

    # Build overrides from args
    overrides = {}
    if args.provider:
        overrides["provider"] = args.provider
    if args.model:
        overrides["model"] = args.model
    if args.max_iterations:
        overrides["max_iterations"] = args.max_iterations
    if args.temperature:
        overrides["temperature"] = args.temperature
    if args.max_tokens:
        overrides["max_tokens"] = args.max_tokens
    if args.limit:
        overrides["limit"] = args.limit
    if args.quiet:
        overrides["verbosity"] = "quiet"
    if args.verbose:
        overrides["verbosity"] = "verbose"
    if args.log_file:
        overrides["log_file"] = args.log_file

    if overrides:
        config = config.merge_with_args(**overrides)

    quiet = config.output.is_quiet

    # Print header
    if not quiet:
        print(f"CodeQL + LLM Bug Verification v{__version__}")
        print(f"Provider: {config.llm.provider}, Model: {config.llm.model}")
        print()

    # Handle dry-run
    if args.dry_run:
        from vuln_hunter_x.sarif.parser import discover_sarif_files, parse_sarif_file
        from vuln_hunter_x.verification.engine import _is_test_path

        sarif_files = discover_sarif_files(config.paths.output_dir)
        if args.lang:
            sarif_files = [
                (p, lang, n) for p, lang, n in sarif_files if lang == args.lang
            ]
        if args.repo:
            sarif_files = [
                (p, lang, n)
                for p, lang, n in sarif_files
                if n.lower() == args.repo.lower()
            ]

        all_findings = []
        for sarif_path, lang, repo_name in sarif_files:
            findings = parse_sarif_file(sarif_path, lang, repo_name)
            if not getattr(args, "include_tests", False):
                findings = [f for f in findings if not _is_test_path(f.file)]
            all_findings.extend(findings)

        if args.limit:
            all_findings = all_findings[: args.limit]

        print("[DRY RUN] Would process these findings:")
        for i, f in enumerate(all_findings[:10], 1):
            print(f"  {i}. {f.rule_id} @ {f.file}:{f.start_line}")
        if len(all_findings) > 10:
            print(f"  ... and {len(all_findings) - 10} more")
        return 0

    # Create engine
    engine = VerificationEngine(config)

    if not quiet:
        print(f"Loaded {engine.questions_loader.rule_count} guided question templates")

    # Set up progress callbacks
    def on_start(i: int, total: int, finding: Finding) -> None:
        if quiet:
            print(
                f"[{i}/{total}] {finding.rule_id} @ {finding.location}",
                end="",
                flush=True,
            )
        else:
            print(f"\n[{i}/{total}] {finding.rule_id}")
            print(f"  File: {finding.location}")

    def on_complete(i: int, total: int, verdict: Verdict) -> None:
        if quiet:
            print(f" -> {verdict.verdict} ({verdict.confidence})")
        else:
            print(f"  Verdict: {verdict.verdict} ({verdict.confidence})")
            print(f"  Reasoning: {verdict.reasoning[:100]}...")

    engine.on_finding_start(on_start)
    engine.on_finding_complete(on_complete)

    exclude_test_paths = not getattr(args, "include_tests", False)
    # Determine what to verify
    if args.sarif:
        result = engine.verify_sarif(
            args.sarif,
            lang=args.lang or "c",
            repo_name=args.sarif.stem,
            limit=args.limit or 0,
            exclude_test_paths=exclude_test_paths,
        )
    else:
        result = engine.verify_all_sarif(
            lang_filter=args.lang,
            repo_filter=args.repo,
            limit=args.limit or 0,
            exclude_test_paths=exclude_test_paths,
        )

    # Print summary
    print()
    print("=" * 60)
    print("Summary:")
    print(f"  Total: {result.total_findings}")
    for verdict_type, count in result.stats.items():
        if count > 0:
            pct = (
                count / result.total_findings * 100
                if result.total_findings
                else 0
            )
            print(f"  {verdict_type}: {count} ({pct:.1f}%)")
    print(f"  Time: {result.total_time_seconds:.2f}s")

    # Save results
    summary_path, results_dir = engine.save_results(result)
    print(f"\nResults saved to: {results_dir}")
    print(f"Summary: {summary_path}")

    return 0


def cmd_build_sanitized(args: argparse.Namespace) -> int:
    """Execute build-sanitized command (Stage 5: fuzz)."""
    from vuln_hunter_x.codeql.repository import load_repos_config
    from vuln_hunter_x.fuzz.build_sanitized import build_sanitized

    base_path = Path.cwd()
    config_path = args.config or base_path / "config" / "repos.yaml"
    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    repos = load_repos_config(config_path)
    if args.lang:
        repos = [r for r in repos if (r.get("language") or "").lower() == args.lang]
    if args.repo:
        repos = [
            r for r in repos if (r.get("name") or "").lower() == args.repo.lower()
        ]

    if not repos:
        print("No C/C++ repositories to build.", file=sys.stderr)
        return 1

    repos_dir = base_path / "repos"
    output_dir = base_path / "output"

    print("Build sanitized (C/C++)\n")
    ok_count = 0
    for repo in repos:
        name = repo.get("name", "unknown")
        lang = (repo.get("language") or "c").lower()
        if lang not in ("c", "cpp"):
            print(f"[{name}] SKIP (not C/C++)")
            continue
        if args.dry_run:
            print(f"[{name}] [dry-run] Would run sanitized build")
            ok_count += 1
            continue
        sanitized_build_dir = output_dir / lang / name / "sanitized_build"
        ok, msg, manifest_path = build_sanitized(
            name=name,
            lang=lang,
            repo_config=repo,
            repos_dir=repos_dir,
            sanitized_build_dir=sanitized_build_dir,
            force=args.force,
        )
        status = "OK" if ok else "FAIL"
        print(f"[{name}] [{status}] {msg[:80]}")
        if ok and manifest_path:
            print(f"  -> {manifest_path}")
        if ok:
            ok_count += 1
    print(f"\nDone. {ok_count}/{len(repos)} succeeded.")
    return 0 if ok_count == len(repos) else 1


def cmd_extract_fuzz_context(args: argparse.Namespace) -> int:
    """Execute extract-fuzz-context command (Stage 6: fuzz)."""
    from vuln_hunter_x.fuzz.extract_fuzz_context import extract_fuzz_context_all

    base_path = Path.cwd()
    output_dir = base_path / "output"
    queries_dir = base_path / "config" / "queries" / "tools"

    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    results = extract_fuzz_context_all(
        output_dir=output_dir,
        queries_dir=queries_dir,
        codeql_path=codeql_path,
        lang_filter=args.lang,
        repo_filter=args.repo,
        dry_run=args.dry_run,
    )

    if not results:
        print("No C/C++ databases found.")
        return 0

    print("Extract fuzz context (C/C++)\n")
    ok_count = 0
    for repo_name, lang, res in results:
        all_ok = all(v[0] for v in res.values())
        status = "OK" if all_ok else "FAIL"
        print(f"[{repo_name}] [{lang}] [{status}]")
        for q, (ok, msg) in res.items():
            print(f"  {q}: {msg}")
        if all_ok:
            ok_count += 1
    print(f"\nDone. {ok_count}/{len(results)} repos succeeded.")
    return 0 if ok_count == len(results) else 1


def cmd_generate_fuzz_drivers(args: argparse.Namespace) -> int:
    """Execute generate-fuzz-drivers command (Stage 7.1–7.6: fuzz)."""
    from vuln_hunter_x.fuzz.generate_drivers import (
        build_and_record,
        generate_fuzz_drivers,
    )

    base_path = Path.cwd()
    output_dir = base_path / "output"
    config_path = args.config or base_path / "config" / "confirm_findings.yaml"
    config = load_config(config_path, base_path) if config_path.exists() else None

    results = generate_fuzz_drivers(
        output_dir=output_dir,
        repo_filter=args.repo,
        lang_filter=args.lang,
        verdict_filter=args.verdict,
        use_verification=True,
        dry_run=args.dry_run,
    )

    if not results:
        print(
            "No targets selected (run verify first and/or check --verdict, --repo, --lang)."
        )
        return 0

    print("Generate fuzz drivers (Stage 7.1–7.3)\n")
    for finding, target_info, cc_path in results:
        fn = target_info.get("name", "?")
        if cc_path:
            print(
                f"  {finding.repo_name} {finding.rule_id} {finding.file}:{finding.start_line} -> {fn} -> {cc_path}"
            )
        else:
            print(
                f"  [dry-run] {finding.repo_name} {finding.rule_id} {finding.file}:{finding.start_line} -> {fn}"
            )
    print(f"\nDone. {len(results)} harness(es) generated.")

    if args.build and not args.dry_run and any(
        p for _, _, p in results if p is not None
    ):
        print("\nBuild harnesses (Stage 7.4–7.6)\n")
        build_results = build_and_record(
            results,
            output_dir=output_dir,
            llm_fix=args.llm_fix,
            max_fix_iterations=args.max_fix_iterations,
            llm_provider=config.llm.provider if config else "openai",
            llm_model=config.llm.model if config else "gpt-4o",
            llm_max_tokens=config.llm.max_tokens if config else 4000,
        )
        for repo_name, entries in build_results:
            for e in entries:
                print(f"  [{repo_name}] {e['harness']}: {e['status']}")
            print(
                f"  -> output/<lang>/{repo_name}/fuzz_targets/status.json"
            )
    return 0


def cmd_fuzz_run(args: argparse.Namespace) -> int:
    """Execute fuzz-run command (Stage 8: run libFuzzer, collect crashes)."""
    from vuln_hunter_x.fuzz.runner import run_all_fuzzers

    base_path = Path.cwd()
    output_dir = base_path / "output"

    results = run_all_fuzzers(
        output_dir=output_dir,
        repo_filter=args.repo,
        timeout_per_harness=args.timeout,
        max_total_time=args.max_fuzz_time,
        dry_run=args.dry_run,
    )

    if not results:
        print(
            "No repos with status.json (run generate-fuzz-drivers --build first)."
        )
        return 0

    print("Fuzz run (Stage 8)\n")
    for repo_name, harness_results, summary_path in results:
        print(f"[{repo_name}]")
        for r in harness_results:
            status = r.get("status", "?")
            if status != "compiled":
                print(f"  {r.get('harness', '?')}: skip ({status})")
                continue
            crashed = r.get("crashed", False)
            count = r.get("crash_count", 0)
            elapsed = r.get("time_sec", 0)
            print(
                f"  {r.get('harness', '?')}: {'CRASH' if crashed else 'ok'} (crashes={count}, time={elapsed}s)"
            )
        print(f"  -> {summary_path}")
    print("\nDone.")
    return 0


def cmd_info(args: argparse.Namespace) -> int:
    """Execute the info command."""
    print(f"CodeQL + LLM Bug Verification v{__version__}")
    print()

    base_path = Path.cwd()
    if args.config:
        config = load_config(args.config, base_path)
        print(f"Config file: {args.config}")
    else:
        default_config = base_path / "config" / "confirm_findings.yaml"
        if default_config.exists():
            config = load_config(default_config, base_path)
            print(f"Config file: {default_config}")
        else:
            config = Config()
            print("Config file: (using defaults)")

    print()
    print("LLM Settings:")
    print(f"  Provider: {config.llm.provider}")
    print(f"  Model: {config.llm.model}")
    print(f"  Temperature: {config.llm.temperature}")
    print(f"  Max tokens: {config.llm.max_tokens}")

    print()
    print("Verification Settings:")
    print(f"  Verification: LLM (multi-turn)")
    print(f"  Max iterations: {config.verification.max_iterations}")

    print()
    print("Paths:")
    print(f"  Repos: {config.paths.repos_dir}")
    print(f"  Output: {config.paths.output_dir}")

    return 0
