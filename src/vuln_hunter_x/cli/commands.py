# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""CLI command implementations for vuln-hunter-x."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from vuln_hunter_x import __version__
from vuln_hunter_x.core.config import Config, load_config
from vuln_hunter_x.core.types import Finding, Verdict


_SUPPORTED_LANGS = {"c", "cpp", "python", "javascript", "php", "java", "go", "csharp"}

# Bundled assets ship with the installed VulnHunterX package, so resolve them
# from __file__ rather than cwd — the CLI must work when invoked from a target
# project directory. Mirrors llm/prompts.py:140. parents[3] of
# src/vuln_hunter_x/cli/commands.py is the repo root.
_BUNDLED_CONFIG = Path(__file__).resolve().parents[3] / "config"


def _int_env(name: str) -> int | None:
    """Return the value of env var ``name`` as an int, or None if unset/invalid."""
    raw = os.environ.get(name)
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _find_db_name_by_source_root(
    local_path: Path, lang: str, output_dir: Path
) -> str | None:
    """Look up an existing CodeQL DB whose source-root matches ``local_path``.

    Scans ``output/<lang>/*/database/codeql-database.yml`` for a
    ``sourceLocationPrefix`` entry equal to the resolved local_path.
    Resolves the prepare/analyze name-mismatch: a user can `prepare --name X`
    then `analyze` without repeating `--name` and still hit the right DB.

    Returns the DB's parent-directory name on a unique match, else None
    (no match or ambiguous — caller should fall back to basename).
    """
    lang_dir = output_dir / lang
    if not lang_dir.is_dir():
        return None

    target = str(Path(local_path).resolve())
    matches: list[str] = []

    for repo_dir in lang_dir.iterdir():
        yml = repo_dir / "database" / "codeql-database.yml"
        if not yml.is_file():
            continue
        try:
            for line in yml.read_text(encoding="utf-8").splitlines():
                if line.startswith("sourceLocationPrefix:"):
                    src = line.split(":", 1)[1].strip()
                    if src == target:
                        matches.append(repo_dir.name)
                    break
        except OSError:
            continue

    return matches[0] if len(matches) == 1 else None


def _discover_repos_from_filesystem(
    repos_dir: Path,
    lang_filter: str | None = None,
    repo_filter: str | None = None,
) -> list[tuple[str, str]]:
    """Discover (lang, name) pairs by scanning repos/<lang>/<name>/ on disk.

    Used as a fallback when repos.yaml is not available (e.g. after clone --url).
    """
    repo_list: list[tuple[str, str]] = []
    if not repos_dir.is_dir():
        return repo_list
    for lang_dir in sorted(repos_dir.iterdir()):
        if not lang_dir.is_dir():
            continue
        lang = lang_dir.name
        if lang not in _SUPPORTED_LANGS:
            continue
        if lang_filter and lang != lang_filter:
            continue
        for repo_dir in sorted(lang_dir.iterdir()):
            if not repo_dir.is_dir():
                continue
            name = repo_dir.name
            if repo_filter and name.lower() != repo_filter.lower():
                continue
            repo_list.append((lang, name))
    return repo_list


def cmd_check_env(args: argparse.Namespace) -> int:
    """Execute check-env command."""
    from vuln_hunter_x.cli.env import load_config_for_check, run_env_check

    results = run_env_check()

    # Check if CodeQL is available (required)
    codeql_ok = results.get("codeql", (False, ""))[0]
    config = load_config_for_check()
    provider = (os.environ.get("LLM_PROVIDER") or config.get("provider", "openai")).lower()
    provider_ok = results.get(provider, (False, "Not configured"))[0]

    if codeql_ok and provider_ok:
        print(f"Environment check passed. CodeQL and {provider} are available.")
        return 0

    if not codeql_ok:
        print("Environment check failed. CodeQL is required for analysis.")
        return 1

    print(f"Environment check failed. Configured provider '{provider}' is not ready.")
    return 1


def _derive_repo_name(url: str | None, local_path: Path | None) -> str | None:
    """Derive repository name from URL or local path."""
    if url:
        # Extract last path component, strip .git suffix
        name = url.rstrip("/").rsplit("/", 1)[-1]
        if name.endswith(".git"):
            name = name[:-4]
        return name or None
    if local_path:
        return local_path.resolve().name or None
    return None


def cmd_prepare(args: argparse.Namespace) -> int:
    """Execute prepare (clone) command."""
    from vuln_hunter_x.codeql.repository import RepositoryManager
    from vuln_hunter_x.core.constants import TIMEOUT_CODEQL_DB_CREATE

    base_path = Path.cwd()
    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    url = getattr(args, "url", None)
    local_path = getattr(args, "local_path", None)

    # DB-creation timeout precedence: CLI flag > env var > constant default.
    db_timeout = (
        getattr(args, "db_timeout", None)
        or _int_env("CODEQL_DB_CREATE_TIMEOUT")
        or TIMEOUT_CODEQL_DB_CREATE
    )

    # Validate mutually exclusive options
    if url and local_path:
        print("Error: --url and --local-path are mutually exclusive.", file=sys.stderr)
        return 1

    manager = RepositoryManager(
        repos_dir=base_path / "repos",
        output_dir=base_path / "output",
        codeql_path=codeql_path,
    )

    # ── Direct mode: --url or --local-path ──
    if url or local_path:
        if not args.lang:
            print("Error: --lang is required when using --url or --local-path.", file=sys.stderr)
            return 1

        name = getattr(args, "name", None) or _derive_repo_name(url, local_path)
        if not name:
            print("Error: could not derive repo name; use --name.", file=sys.stderr)
            return 1

        build_command = getattr(args, "build_command", None)

        if local_path:
            local_path = Path(local_path).resolve()
            if not local_path.is_dir():
                print(f"Error: local path not found: {local_path}", file=sys.stderr)
                return 1

        if local_path:
            print(f"Use local repo {local_path} and create CodeQL database\n")
        else:
            print("Clone repo and create CodeQL database\n")

        ok, msg = manager.clone_and_create_db(
            name=name,
            url=url or "",
            language=args.lang,
            build_command=build_command,
            local_path=local_path,
            skip_clone=bool(local_path) or args.skip_clone,
            skip_db=args.skip_db,
            dry_run=args.dry_run,
            ask_llm=args.ask_llm,
            timeout=db_timeout,
        )

        status = "OK" if ok else "FAIL"
        detail = msg[:100] if ok else msg if len(msg) <= 1200 else msg[:1200] + "... (truncated)"
        print(f"[{name}] [{status}] {detail}")

        # ── Context extraction (automatic unless --skip-context) ──
        if ok and not getattr(args, "skip_context", False):
            print("\n--- Context extraction ---\n")
            ctx_rc = _run_context_extraction(
                lang_filter=args.lang,
                repo_filter=name,
                backend=getattr(args, "backend", "auto"),
                force=getattr(args, "force", False),
                dry_run=args.dry_run,
                local_path=local_path,
                name=name,
            )
            if ctx_rc != 0:
                print(f"[{name}] [WARN] Context extraction had failures (non-fatal)")

        return 0 if ok else 1

    # ── Config mode (default) ──
    config_path = args.config or _BUNDLED_CONFIG / "repos.yaml"

    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1

    print("Clone repos and create CodeQL databases\n")

    results = manager.process_repos_config(
        config_path,
        lang_filter=args.lang,
        repo_filter=args.repo,
        skip_clone=args.skip_clone,
        skip_db=args.skip_db,
        dry_run=args.dry_run,
        ask_llm=args.ask_llm,
        timeout=db_timeout,
    )

    ok_count = sum(1 for _, ok, _ in results if ok)

    for name, ok, msg in results:
        status = "OK" if ok else "FAIL"
        detail = msg[:100] if ok else msg if len(msg) <= 1200 else msg[:1200] + "... (truncated)"
        print(f"[{name}] [{status}] {detail}")

    print(f"\nDone. {ok_count}/{len(results)} succeeded.")

    # ── Context extraction (automatic unless --skip-context) ──
    if ok_count > 0 and not getattr(args, "skip_context", False):
        print("\n--- Context extraction ---\n")
        ctx_rc = _run_context_extraction(
            lang_filter=args.lang,
            repo_filter=args.repo,
            backend=getattr(args, "backend", "auto"),
            force=getattr(args, "force", False),
            dry_run=args.dry_run,
        )
        if ctx_rc != 0:
            print("[WARN] Some context extraction failed (non-fatal)")

    return 0 if ok_count == len(results) else 1


def _run_codeql_analyze(
    args: argparse.Namespace,
    base_path: Path,
    output_dir: Path,
    verbose: bool,
    force: bool,
) -> int:
    """Run CodeQL analysis on discovered databases. Returns exit code."""
    import json
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from vuln_hunter_x.codeql.analysis import CodeQLAnalyzer
    from vuln_hunter_x.codeql.context_extractor import discover_databases
    from vuln_hunter_x.core.constants import CODEQL_PARALLEL_JOBS

    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    suite = getattr(args, "codeql_suite", None)
    # If a rule profile was set but no explicit suite, resolve per-language below
    profile_suffix = getattr(args, "_profile_codeql_suffix", None)
    jobs = getattr(args, "jobs", None) or CODEQL_PARALLEL_JOBS

    dbs = discover_databases(output_dir)
    if args.lang:
        dbs = [(p, lang, n) for p, lang, n in dbs if lang == args.lang]
    if args.repo:
        dbs = [(p, lang, n) for p, lang, n in dbs if n.lower() == args.repo.lower()]

    # Deduplicate by db_path to prevent concurrent access to same database
    seen_paths: set[Path] = set()
    unique_dbs = []
    for db_path, lang, name in dbs:
        resolved = db_path.resolve()
        if resolved not in seen_paths:
            seen_paths.add(resolved)
            unique_dbs.append((db_path, lang, name))
    dbs = unique_dbs

    if not dbs:
        print("No CodeQL databases found.", file=sys.stderr)
        if args.lang or args.repo:
            print(f"  Filter: lang={args.lang}, repo={args.repo}", file=sys.stderr)
        # List what IS available so the user can spot a name mismatch immediately.
        all_dbs = discover_databases(output_dir)
        if args.lang:
            all_dbs = [d for d in all_dbs if d[1] == args.lang]
        if all_dbs:
            print("  Available databases:", file=sys.stderr)
            for _, lang, name in all_dbs:
                print(f"    - {lang}/{name}", file=sys.stderr)
        print(
            "  Hint: run 'vuln-hunter-x prepare' first, or use '--tool semgrep' for source-only analysis.",
            file=sys.stderr,
        )
        return 1

    if verbose:
        print(f"Found {len(dbs)} database(s) under {output_dir}")
        for db_path, lang, name in dbs:
            print(f"  - {lang}/{name}: {db_path}")
        print()

    print(f"Running CodeQL analysis on {len(dbs)} database(s) (--jobs {jobs})\n")

    def _analyze_one(
        db_path: Path, lang: str, name: str
    ) -> tuple[str, bool, Path | None, str, bool]:
        """Analyze one database. Returns (name, ok, result_path, msg, skipped)."""
        sarif_path = output_dir / lang / name / f"{name}.sarif"
        if sarif_path.exists() and not force:
            try:
                with open(sarif_path) as f:
                    sarif_data = json.load(f)
                findings_count = sum(
                    len(run.get("results", [])) for run in sarif_data.get("runs", [])
                )
                return (
                    name,
                    True,
                    sarif_path,
                    f"[SKIP] SARIF already exists ({findings_count} findings)",
                    True,
                )
            except Exception:
                return name, True, sarif_path, "[SKIP] SARIF already exists", True
        if getattr(args, "dry_run", False):
            analyzer = CodeQLAnalyzer(codeql_path=codeql_path, output_dir=output_dir)
            default_suite = analyzer.DEFAULT_SUITES.get("cpp" if lang in ("c", "cpp") else lang)
            lines = [
                f"  [dry-run] Would analyze {db_path}",
                f"  [dry-run] Suite: {suite or default_suite}",
                f"  [dry-run] Output: {sarif_path}",
            ]
            return name, True, sarif_path, "\n".join(lines), False
        analyzer = CodeQLAnalyzer(
            codeql_path=codeql_path,
            output_dir=output_dir,
            verbose=verbose,
        )
        if verbose:
            lines: list[str] = []
            analyzer.set_logger(lambda msg, _lines=lines: _lines.append(msg))
        # Resolve suite: explicit CLI > profile-based (per-language) > default
        effective_suite = suite
        if not effective_suite and profile_suffix:
            effective_suite = CodeQLAnalyzer.suite_for_language(lang, profile_suffix)
        # Stack custom suite when the active profile sets include_custom_codeql.
        extra_suites: list[str] = []
        if getattr(args, "_profile_include_custom_codeql", False):
            codeql_lang = "cpp" if lang in ("c", "cpp") else lang
            custom_suite = _BUNDLED_CONFIG / "codeql-custom" / codeql_lang / "suite.qls"
            if custom_suite.is_file():
                # Skip empty custom packs to avoid CodeQL "no queries" failures.
                src_dir = custom_suite.parent / "src"
                if src_dir.is_dir() and any(src_dir.glob("*.ql")):
                    extra_suites.append(str(custom_suite))
        ok, result_path, msg = analyzer.run_analysis(
            db_path, lang, name, suite=effective_suite, extra_suites=extra_suites,
        )
        if verbose and lines:
            msg = "\n".join(lines) + "\n" + msg
        return name, ok, result_path, msg, False

    ok_count = 0
    skip_count = 0
    results: list[tuple[str, bool, Path | None, str, bool]] = []

    with ThreadPoolExecutor(max_workers=jobs) as pool:
        future_to_name = {
            pool.submit(_analyze_one, db_path, lang, name): name for db_path, lang, name in dbs
        }
        for fut in as_completed(future_to_name):
            results.append(fut.result())

    # Sort output by original db order for deterministic display
    db_order = [name for _, _, name in dbs]
    results.sort(key=lambda r: db_order.index(r[0]) if r[0] in db_order else 0)

    for name, ok, result_path, msg, skipped in results:
        print(f"[{name}]")
        if skipped:
            print(f"  {msg}")
            skip_count += 1
            ok_count += 1
        elif ok:
            ok_count += 1
            if result_path:
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


def _expand_per_repo_configs(
    args: argparse.Namespace, configs: list[str], lang: str,
) -> list[str]:
    """Resolve final Semgrep/OpenGrep configs for one repo at one language.

    The transformation pipeline is:

    1. Expand ``${LANG}`` placeholders in the input list. For *local file*
       paths the resolved path must exist (otherwise the entry is dropped);
       *registry refs* (containing ``:`` or starting with ``p/``/``r/``) are
       always kept.
    2. Append per-language packs from
       ``args._profile_language_specific_configs[lang]`` (set by ``cmd_analyze``
       when a profile is active).
    3. Append the profile's ``custom_semgrep_path`` template, resolved for
       this language, when the resolved file exists.

    Returns a new list — does not mutate ``configs``.
    """
    expanded: list[str] = []
    for c in configs:
        if isinstance(c, str) and "${LANG}" in c:
            resolved = c.replace("${LANG}", lang)
            # Registry refs (no path semantics) cannot be filesystem-checked;
            # accept anything that looks like a Semgrep registry handle.
            if resolved.startswith(("p/", "r/")) or ":" in resolved:
                expanded.append(resolved)
            elif Path(resolved).is_file():
                expanded.append(resolved)
            # else: drop — local-path template that didn't resolve
        else:
            expanded.append(c)

    lang_specific = getattr(args, "_profile_language_specific_configs", None) or {}
    for c in lang_specific.get(lang, []):
        if c not in expanded:
            expanded.append(c)

    custom_path = getattr(args, "_profile_custom_semgrep_path", "") or ""
    if custom_path:
        resolved = custom_path.replace("${LANG}", lang)
        if Path(resolved).is_file() and resolved not in expanded:
            expanded.append(resolved)
    return expanded


def _run_semgrep_analyze(
    args: argparse.Namespace,
    base_path: Path,
    output_dir: Path,
    repos_dir: Path,
    verbose: bool,
    force: bool,
) -> int:
    """Run Semgrep analysis on repos from config or filesystem discovery. Returns exit code."""
    from vuln_hunter_x.semgrep.analyzer import SemgrepAnalyzer

    config_path = getattr(args, "config", None) or _BUNDLED_CONFIG / "repos.yaml"
    repo_list: list[tuple[str, str]] = []

    if config_path.is_file():
        from vuln_hunter_x.codeql.repository import load_repos_config

        repos = load_repos_config(Path(config_path))
        for r in repos:
            name = r.get("name")
            if not name:
                continue
            raw_lang = (r.get("language") or "c").lower()
            lang = "cpp" if raw_lang == "cpp" else raw_lang
            if lang not in _SUPPORTED_LANGS:
                continue
            repo_list.append((lang, name))

    # Apply filters before the fallback so that --local-path repos not in
    # repos.yaml still trigger filesystem discovery.
    if args.lang:
        repo_list = [(lang, name) for lang, name in repo_list if lang == args.lang]
    if args.repo:
        repo_list = [(lang, name) for lang, name in repo_list if name.lower() == args.repo.lower()]

    # Fallback: discover repos from filesystem (supports clone --url / --local-path)
    if not repo_list:
        repo_list = _discover_repos_from_filesystem(repos_dir)
        if args.lang:
            repo_list = [(lang, name) for lang, name in repo_list if lang == args.lang]
        if args.repo:
            repo_list = [
                (lang, name)
                for lang, name in repo_list
                if name.lower() == args.repo.lower()
            ]

    if not repo_list:
        print(
            "No repositories found for Semgrep (check config and --lang/--repo).", file=sys.stderr
        )
        return 1

    raw_configs = getattr(args, "semgrep_configs", None) or ["auto"]
    # Support comma-separated in a single --semgrep-config (e.g. "auto,p/security-audit")
    configs = []
    for c in raw_configs:
        if isinstance(c, str):
            configs.extend(s.strip() for s in c.split(",") if s.strip())
        else:
            configs.append(c)
    if not configs:
        configs = ["auto"]
    semgrep_path = os.environ.get("SEMGREP_PATH", "semgrep")
    analyzer = SemgrepAnalyzer(
        semgrep_path=semgrep_path,
        output_dir=output_dir,
        verbose=verbose,
    )
    if verbose:
        analyzer.set_logger(lambda msg: print(msg))

    print(f"Running Semgrep analysis on {len(repo_list)} repo(s)\n")
    ok_count = 0
    skip_count = 0
    for lang, name in repo_list:
        repo_path = repos_dir / lang / name
        if not repo_path.is_dir():
            print(f"[{name}] {lang} - [SKIP] repo dir not found: {repo_path}")
            continue
        semgrep_sarif = output_dir / lang / name / f"{name}_semgrep.sarif"
        if semgrep_sarif.exists() and not force:
            try:
                import json

                with open(semgrep_sarif) as f:
                    data = json.load(f)
                findings_count = sum(len(run.get("results", [])) for run in data.get("runs", []))
                print(f"[{name}] {lang}")
                print(f"  [SKIP] Semgrep SARIF already exists ({findings_count} findings)")
            except Exception:
                print(f"[{name}] {lang}")
                print("  [SKIP] Semgrep SARIF already exists")
            skip_count += 1
            ok_count += 1
            continue
        print(f"[{name}] {lang}")
        # Per-repo expansion: ${LANG} → repo's language; append custom-semgrep-path
        # from the rule profile when it resolves to an existing file.
        repo_configs = _expand_per_repo_configs(args, configs, lang)
        if getattr(args, "dry_run", False):
            print(f"  [dry-run] Would run Semgrep on {repo_path}")
            print(f"  [dry-run] Configs: {repo_configs}")
            print(f"  [dry-run] Output: {semgrep_sarif}")
            ok_count += 1
            continue
        ok, result_path, msg = analyzer.run_analysis(
            repo_path, lang, name, output_dir, configs=repo_configs
        )
        if ok:
            ok_count += 1
            print(f"  -> {result_path}")
            print(f"  {msg}")
        else:
            print(f"  FAILED: {msg}", file=sys.stderr)
    if skip_count > 0:
        print(
            f"\nDone. {ok_count}/{len(repo_list)} succeeded ({skip_count} skipped, use --force to re-analyze)."
        )
    else:
        print(f"\nDone. {ok_count}/{len(repo_list)} succeeded.")
    return 0 if ok_count == len(repo_list) else 1


def _run_opengrep_analyze(
    args: argparse.Namespace,
    base_path: Path,
    output_dir: Path,
    repos_dir: Path,
    verbose: bool,
    force: bool,
) -> int:
    """Run OpenGrep analysis on repos from config or filesystem discovery. Returns exit code."""
    from vuln_hunter_x.opengrep.analyzer import OpenGrepAnalyzer

    config_path = getattr(args, "config", None) or _BUNDLED_CONFIG / "repos.yaml"
    repo_list: list[tuple[str, str]] = []

    if config_path.is_file():
        from vuln_hunter_x.codeql.repository import load_repos_config

        repos = load_repos_config(Path(config_path))
        for r in repos:
            name = r.get("name")
            if not name:
                continue
            raw_lang = (r.get("language") or "c").lower()
            lang = "cpp" if raw_lang == "cpp" else raw_lang
            if lang not in _SUPPORTED_LANGS:
                continue
            repo_list.append((lang, name))

    # Apply filters before the fallback so that --local-path repos not in
    # repos.yaml still trigger filesystem discovery.
    if args.lang:
        repo_list = [(lang, name) for lang, name in repo_list if lang == args.lang]
    if args.repo:
        repo_list = [(lang, name) for lang, name in repo_list if name.lower() == args.repo.lower()]

    # Fallback: discover repos from filesystem (supports clone --url / --local-path)
    if not repo_list:
        repo_list = _discover_repos_from_filesystem(repos_dir)
        if args.lang:
            repo_list = [(lang, name) for lang, name in repo_list if lang == args.lang]
        if args.repo:
            repo_list = [
                (lang, name)
                for lang, name in repo_list
                if name.lower() == args.repo.lower()
            ]

    if not repo_list:
        print(
            "No repositories found for OpenGrep (check config and --lang/--repo).", file=sys.stderr
        )
        return 1

    raw_configs = getattr(args, "opengrep_configs", None) or ["auto"]
    configs: list[str] = []
    for c in raw_configs:
        if isinstance(c, str):
            configs.extend(s.strip() for s in c.split(",") if s.strip())
        else:
            configs.append(c)
    if not configs:
        configs = ["auto"]
    opengrep_path = os.environ.get("OPENGREP_PATH", "opengrep")
    analyzer = OpenGrepAnalyzer(
        semgrep_path=opengrep_path,
        output_dir=output_dir,
        verbose=verbose,
    )
    if verbose:
        analyzer.set_logger(lambda msg: print(msg))

    print(f"Running OpenGrep analysis on {len(repo_list)} repo(s)\n")
    ok_count = 0
    skip_count = 0
    for lang, name in repo_list:
        repo_path = repos_dir / lang / name
        if not repo_path.is_dir():
            print(f"[{name}] {lang} - [SKIP] repo dir not found: {repo_path}")
            continue
        opengrep_sarif = output_dir / lang / name / f"{name}_opengrep.sarif"
        if opengrep_sarif.exists() and not force:
            try:
                import json

                with open(opengrep_sarif) as f:
                    data = json.load(f)
                findings_count = sum(len(run.get("results", [])) for run in data.get("runs", []))
                print(f"[{name}] {lang}")
                print(f"  [SKIP] OpenGrep SARIF already exists ({findings_count} findings)")
            except Exception:
                print(f"[{name}] {lang}")
                print("  [SKIP] OpenGrep SARIF already exists")
            skip_count += 1
            ok_count += 1
            continue
        print(f"[{name}] {lang}")
        repo_configs = _expand_per_repo_configs(args, configs, lang)
        if getattr(args, "dry_run", False):
            print(f"  [dry-run] Would run OpenGrep on {repo_path}")
            print(f"  [dry-run] Configs: {repo_configs}")
            print(f"  [dry-run] Output: {opengrep_sarif}")
            ok_count += 1
            continue
        ok, result_path, msg = analyzer.run_analysis(
            repo_path, lang, name, output_dir, configs=repo_configs
        )
        if ok:
            ok_count += 1
            print(f"  -> {result_path}")
            print(f"  {msg}")
        else:
            print(f"  FAILED: {msg}", file=sys.stderr)
    if skip_count > 0:
        print(
            f"\nDone. {ok_count}/{len(repo_list)} succeeded ({skip_count} skipped, use --force to re-analyze)."
        )
    else:
        print(f"\nDone. {ok_count}/{len(repo_list)} succeeded.")
    return 0 if ok_count == len(repo_list) else 1


def _load_analyze_defaults(base_path: Path) -> tuple[str | None, list[str], list[str]]:
    """Load codeql_suite, semgrep_configs, and opengrep_configs from config if present."""
    import yaml

    config_path = _BUNDLED_CONFIG / "confirm_findings.yaml"
    if not config_path.is_file():
        return None, [], []
    try:
        with open(config_path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except Exception:
        return None, [], []
    suite = data.get("codeql_suite")

    semgrep_configs = data.get("semgrep_configs")
    if isinstance(semgrep_configs, list):
        pass
    elif data.get("semgrep_config"):
        semgrep_configs = [data["semgrep_config"]]
    else:
        semgrep_configs = []

    opengrep_configs = data.get("opengrep_configs")
    if isinstance(opengrep_configs, list):
        pass
    elif data.get("opengrep_config"):
        opengrep_configs = [data["opengrep_config"]]
    else:
        opengrep_configs = []

    return suite, semgrep_configs, opengrep_configs


def cmd_analyze(args: argparse.Namespace) -> int:
    """Execute analyze command (CodeQL and/or Semgrep by --tool)."""
    base_path = Path.cwd()
    output_dir = base_path / "output"
    repos_dir = base_path / "repos"
    verbose = getattr(args, "verbose", False)
    force = getattr(args, "force", False)
    tool = getattr(args, "tool", "codeql")

    # --local-path mode: set up repo/lang so downstream functions find the source
    local_path = getattr(args, "local_path", None)
    if local_path:
        local_path = Path(local_path).resolve()
        if not local_path.is_dir():
            print(f"Error: local path not found: {local_path}", file=sys.stderr)
            return 1
        if not args.lang:
            print("Error: --lang is required with --local-path.", file=sys.stderr)
            return 1
        explicit_name = getattr(args, "name", None)
        if explicit_name:
            name = explicit_name
        else:
            # Auto-resolve: prefer a DB whose source-root matches local_path
            # (handles `prepare --name X` then `analyze` without --name).
            resolved = _find_db_name_by_source_root(local_path, args.lang, output_dir)
            name = resolved or local_path.name
            if resolved and resolved != local_path.name:
                print(
                    f"  Using existing database '{resolved}' for local path {local_path}"
                )
        lang = args.lang
        # Ensure repo dir exists for Semgrep/OpenGrep (symlink if needed)
        target_repo_dir = repos_dir / lang / name
        if not target_repo_dir.exists():
            target_repo_dir.parent.mkdir(parents=True, exist_ok=True)
            if target_repo_dir.is_symlink():
                target_repo_dir.unlink()
            target_repo_dir.symlink_to(local_path)
        # Set filters so only this repo is analyzed
        args.repo = name
        args.lang = lang

    # Optional: defaults from config (CLI overrides)
    default_suite, default_semgrep_configs, default_opengrep_configs = _load_analyze_defaults(
        base_path
    )
    if getattr(args, "codeql_suite", None) is None and default_suite:
        args.codeql_suite = default_suite
    if not getattr(args, "semgrep_configs", None) and default_semgrep_configs:
        args.semgrep_configs = default_semgrep_configs
    if not getattr(args, "opengrep_configs", None) and default_opengrep_configs:
        args.opengrep_configs = default_opengrep_configs

    # Rule profile: override suite/configs from the profile. Defaults to
    # "standard" so per-language packs and local custom rules always apply —
    # a bare "auto" silently skips whole languages (e.g. Go produced 0 results).
    profile_name = getattr(args, "profile", None) or "standard"
    if profile_name:
        try:
            from vuln_hunter_x.core.rule_profiles import RuleProfileManager

            mgr = RuleProfileManager(_BUNDLED_CONFIG / "rule_categories.yaml")
            profile = mgr.get_profile(profile_name)
            if getattr(args, "codeql_suite", None) is None:
                # Store suffix for per-language resolution in _run_codeql_analyze
                args._profile_codeql_suffix = profile.codeql_suite_suffix
            # Surface custom-rule flags downstream
            args._profile_include_custom_codeql = profile.include_custom_codeql
            args._profile_custom_semgrep_path = profile.custom_semgrep_path
            args._profile_language_specific_configs = profile.language_specific_configs
            if not getattr(args, "semgrep_configs", None):
                # Expand ${LANG} now if a single lang is selected; otherwise per-repo
                # expansion happens inside _run_semgrep_analyze.
                args.semgrep_configs = list(profile.semgrep_configs)
            if not getattr(args, "opengrep_configs", None):
                args.opengrep_configs = list(profile.opengrep_configs)
            if verbose:
                print(f"  Rule profile: {profile_name} — {profile.description}")
        except Exception as exc:
            print(f"Warning: failed to load rule profile {profile_name!r}: {exc}", file=sys.stderr)

    if tool == "codeql":
        return _run_codeql_analyze(args, base_path, output_dir, verbose, force)
    if tool == "semgrep":
        return _run_semgrep_analyze(args, base_path, output_dir, repos_dir, verbose, force)
    if tool == "opengrep":
        return _run_opengrep_analyze(args, base_path, output_dir, repos_dir, verbose, force)
    if tool == "both":
        codeql_code = _run_codeql_analyze(args, base_path, output_dir, verbose, force)
        semgrep_code = _run_semgrep_analyze(args, base_path, output_dir, repos_dir, verbose, force)
        return 0 if semgrep_code == 0 or codeql_code == 0 else 1
    if tool == "all":
        codeql_code = _run_codeql_analyze(args, base_path, output_dir, verbose, force)
        semgrep_code = _run_semgrep_analyze(args, base_path, output_dir, repos_dir, verbose, force)
        opengrep_code = _run_opengrep_analyze(
            args, base_path, output_dir, repos_dir, verbose, force
        )
        return 0 if any(c == 0 for c in (codeql_code, semgrep_code, opengrep_code)) else 1
    return 1


def _skip_existing_context(
    output_dir: Path,
    items: list[tuple],
    force: bool,
) -> tuple[list[tuple], int]:
    """Filter out repos that already have context CSVs unless --force.

    Returns (repos_to_process, skip_count).
    """
    to_process: list[tuple] = []
    skip_count = 0
    for item in items:
        # item[-2] is lang, item[-1] is repo_name (works for both 3-tuple formats)
        lang, name = item[-2], item[-1]
        repo_context_dir = output_dir / lang / name / "context"
        csv_files = list(repo_context_dir.glob("*.csv")) if repo_context_dir.exists() else []
        if csv_files and not force:
            print(f"[{name}] {lang}")
            print(f"  [SKIP] Context already exists ({len(csv_files)} CSV files)")
            skip_count += 1
        else:
            to_process.append(item)
    return to_process, skip_count


def _print_extraction_results(
    results: list[tuple[str, str, dict[str, tuple[bool, str]]]],
    skip_count: int,
) -> int:
    """Print extraction results and return exit code."""
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
            f"\nDone. {total_ok}/{total_queries} queries succeeded"
            f" ({skip_count} repos skipped, use --force to re-extract)."
        )
    else:
        print(f"\nDone. {total_ok}/{total_queries} queries succeeded.")
    return 0 if total_ok == total_queries else 1


def _run_context_extraction(
    *,
    lang_filter: str | None = None,
    repo_filter: str | None = None,
    backend: str = "auto",
    force: bool = False,
    dry_run: bool = False,
    local_path: Path | None = None,
    name: str | None = None,
) -> int:
    """Run context extraction (CodeQL, tree-sitter, or auto).

    This is the core logic shared by ``cmd_prepare`` (post-DB creation) and
    any direct callers.  It discovers databases / source repos, runs the
    appropriate extractor, and prints results.

    Returns 0 on success, 1 on failure.
    """
    from vuln_hunter_x.codeql.context_extractor import (
        ContextExtractorDB,
        discover_databases,
    )
    from vuln_hunter_x.context.treesitter_extractor import (
        TreeSitterContextExtractor,
        discover_repos_for_context,
    )

    base_path = Path.cwd()
    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    output_dir = base_path / "output"
    repos_dir = base_path / "repos"

    # --local-path mode: symlink into repos/ so discovery finds it
    if local_path:
        local_path = Path(local_path).resolve()
        if not local_path.is_dir():
            print(f"Error: local path not found: {local_path}", file=sys.stderr)
            return 1
        if not lang_filter:
            print("Error: --lang is required with --local-path.", file=sys.stderr)
            return 1
        name = name or local_path.name
        lang_filter = lang_filter
        target_repo_dir = repos_dir / lang_filter / name
        if not target_repo_dir.exists():
            target_repo_dir.parent.mkdir(parents=True, exist_ok=True)
            if target_repo_dir.is_symlink():
                target_repo_dir.unlink()
            target_repo_dir.symlink_to(local_path)
        repo_filter = name

    # ── Discover sources ──────────────────────────────────────────
    codeql_dbs: list[tuple[Path, str, str]] = []
    ts_repos: list[tuple[Path, str, str]] = []

    if backend in ("auto", "codeql"):
        codeql_dbs = discover_databases(output_dir)
    if backend in ("auto", "treesitter"):
        ts_repos = discover_repos_for_context(output_dir, repos_dir)
        if backend == "auto":
            # Exclude repos already covered by CodeQL
            codeql_keys = {(lg, n) for _, lg, n in codeql_dbs}
            ts_repos = [(p, lg, n) for p, lg, n in ts_repos if (lg, n) not in codeql_keys]

    # Apply filters
    if lang_filter:
        codeql_dbs = [(p, lg, n) for p, lg, n in codeql_dbs if lg == lang_filter]
        ts_repos = [(p, lg, n) for p, lg, n in ts_repos if lg == lang_filter]
    if repo_filter:
        codeql_dbs = [(p, lg, n) for p, lg, n in codeql_dbs if n.lower() == repo_filter.lower()]
        ts_repos = [(p, lg, n) for p, lg, n in ts_repos if n.lower() == repo_filter.lower()]

    if not codeql_dbs and not ts_repos:
        print("No CodeQL databases or source repos found.", file=sys.stderr)
        return 1

    total_skip = 0
    all_results: list[tuple[str, str, dict[str, tuple[bool, str]]]] = []

    # ── CodeQL extraction ─────────────────────────────────────────
    if codeql_dbs:
        codeql_dbs, skip = _skip_existing_context(output_dir, codeql_dbs, force)
        total_skip += skip

        if codeql_dbs:
            print(f"Extracting context from {len(codeql_dbs)} CodeQL database(s)\n")
            extractor = ContextExtractorDB(
                codeql_path=codeql_path,
                queries_dir=_BUNDLED_CONFIG / "queries" / "tools",
                output_dir=output_dir,
            )
            results = extractor.extract_all(
                output_dir=output_dir,
                lang_filter=lang_filter,
                repo_filter=repo_filter,
                dry_run=dry_run,
            )
            process_names = {n for _, _, n in codeql_dbs}
            all_results.extend(
                (n, lg, qr) for n, lg, qr in results if n in process_names
            )

    # ── Tree-sitter extraction ────────────────────────────────────
    if ts_repos:
        ts_repos, skip = _skip_existing_context(output_dir, ts_repos, force)
        total_skip += skip

        if ts_repos:
            print(f"Extracting context from {len(ts_repos)} repo(s) via tree-sitter\n")
            ts_extractor = TreeSitterContextExtractor(
                repos_dir=repos_dir,
                output_dir=output_dir,
            )
            for _src_path, lg, repo_name in ts_repos:
                query_results = ts_extractor.extract_for_repo(
                    lg,
                    repo_name,
                    dry_run=dry_run,
                )
                all_results.append((repo_name, lg, query_results))

    if not all_results and total_skip > 0:
        print("\nDone. All repos skipped (use --force to re-extract).")
        return 0

    return _print_extraction_results(all_results, total_skip)


def cmd_verify(args: argparse.Namespace) -> int:
    """Execute the verify command."""
    from vuln_hunter_x.verification.engine import VerificationEngine

    base_path = Path.cwd()

    # --local-path mode: symlink into repos/ so context extraction finds source
    local_path = getattr(args, "local_path", None)
    if local_path:
        local_path = Path(local_path).resolve()
        if not local_path.is_dir():
            print(f"Error: local path not found: {local_path}", file=sys.stderr)
            return 1
        if not args.lang:
            print("Error: --lang is required with --local-path.", file=sys.stderr)
            return 1
        name = getattr(args, "name", None) or local_path.name
        repos_dir = base_path / "repos"
        target_repo_dir = repos_dir / args.lang / name
        if not target_repo_dir.exists():
            target_repo_dir.parent.mkdir(parents=True, exist_ok=True)
            if target_repo_dir.is_symlink():
                target_repo_dir.unlink()
            target_repo_dir.symlink_to(local_path)
        args.repo = name

    # Load config
    if args.config:
        config = load_config(args.config, base_path)
    else:
        default_config = _BUNDLED_CONFIG / "confirm_findings.yaml"
        config = load_config(default_config, base_path) if default_config.exists() else Config()

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
            sarif_files = [(p, lang, n) for p, lang, n in sarif_files if lang == args.lang]
        if args.repo:
            sarif_files = [
                (p, lang, n) for p, lang, n in sarif_files if n.lower() == args.repo.lower()
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
    engine = VerificationEngine(config, jobs=getattr(args, "jobs", None))

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
    category_filter = getattr(args, "categories", None)
    if category_filter and not quiet:
        print(f"Category filter: {', '.join(category_filter)}")

    # Determine what to verify
    if args.sarif:
        result = engine.verify_sarif(
            args.sarif,
            lang=args.lang or "c",
            repo_name=args.sarif.stem,
            limit=args.limit or 0,
            exclude_test_paths=exclude_test_paths,
            category_filter=category_filter,
        )
    else:
        result = engine.verify_all_sarif(
            lang_filter=args.lang,
            repo_filter=args.repo,
            limit=args.limit or 0,
            exclude_test_paths=exclude_test_paths,
            category_filter=category_filter,
        )

    # Print summary
    print()
    print("=" * 60)
    print("Summary:")
    print(f"  Total: {result.total_findings}")
    for verdict_type, count in result.stats.items():
        if count > 0:
            pct = count / result.total_findings * 100 if result.total_findings else 0
            print(f"  {verdict_type}: {count} ({pct:.1f}%)")
    print(f"  Time: {result.total_time_seconds:.2f}s")

    # Save results
    summary_path, results_dir = engine.save_results(result)
    print(f"\nResults saved to: {results_dir}")
    print(f"Summary: {summary_path}")

    # Generate reports (EN + VI) automatically
    if result.verdicts:
        from vuln_hunter_x.reporting.markdown import MarkdownReportGenerator

        generator = MarkdownReportGenerator()
        en_path = generator.generate(result, results_dir / "report.md", report_lang="en")
        print(f"Report (EN): {en_path}")
        vi_path = generator.generate(result, results_dir / "report_vi.md", report_lang="vi")
        print(f"Report (VI): {vi_path}")

    return 0


def cmd_build_sanitized(args: argparse.Namespace) -> int:
    """Execute build-sanitized command (Stage 5: fuzz)."""
    from vuln_hunter_x.fuzz.build_sanitized import build_sanitized

    base_path = Path.cwd()
    config_path = args.config or _BUNDLED_CONFIG / "repos.yaml"
    repos: list[dict] = []

    if config_path.exists():
        from vuln_hunter_x.codeql.repository import load_repos_config

        repos = load_repos_config(config_path)

    # Fallback: discover C/C++ repos from filesystem
    if not repos:
        for lang, name in _discover_repos_from_filesystem(base_path / "repos"):
            if lang in ("c", "cpp"):
                repos.append({"name": name, "language": lang})

    if args.lang:
        repos = [r for r in repos if (r.get("language") or "").lower() == args.lang]
    if args.repo:
        repos = [r for r in repos if (r.get("name") or "").lower() == args.repo.lower()]

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
        first_line = msg.splitlines()[0][:120] if msg else ""
        print(f"[{name}] [{status}] {first_line}")
        if not ok and msg:
            # Show last 5 non-warning lines for diagnosis (real errors are at the end)
            err_lines = [
                ln for ln in msg.splitlines() if ln.strip() and "warning:" not in ln.lower()
            ]
            for ln in err_lines[-5:]:
                print(f"  | {ln[:200]}")
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
    queries_dir = _BUNDLED_CONFIG / "queries" / "tools"

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
        for q, (_ok, msg) in res.items():
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
    config_path = args.config or _BUNDLED_CONFIG / "confirm_findings.yaml"
    config = load_config(config_path, base_path) if config_path.exists() else Config()

    results = generate_fuzz_drivers(
        output_dir=output_dir,
        repo_filter=args.repo,
        lang_filter=args.lang,
        verdict_filter=args.verdict,
        use_verification=True,
        dry_run=args.dry_run,
    )

    if not results:
        print("No targets selected (run verify first and/or check --verdict, --repo, --lang).")
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

    if args.build and not args.dry_run and any(p for _, _, p in results if p is not None):
        print("\nBuild harnesses (Stage 7.4–7.6)\n")
        # Resolve fuzz config: CLI args override config file
        max_fix_iters = (
            args.max_fix_iterations
            if args.max_fix_iterations is not None
            else config.fuzz.max_fix_iterations
        )
        extra_inc = args.extra_include_dirs or config.fuzz.extra_include_dirs
        extra_lib_dirs = args.extra_lib_dirs or config.fuzz.extra_lib_dirs
        extra_link_libs = args.extra_link_libs or config.fuzz.extra_link_libs

        build_results = build_and_record(
            results,
            output_dir=output_dir,
            llm_fix=args.llm_fix,
            max_fix_iterations=max_fix_iters,
            llm_provider=config.llm.provider,
            llm_model=config.llm.model,
            llm_max_tokens=config.llm.max_tokens,
            extra_include_dirs=extra_inc,
            extra_lib_dirs=extra_lib_dirs,
            extra_link_libs=extra_link_libs,
        )
        verbose = getattr(args, "verbose", False)
        for repo_name, entries in build_results:
            for e in entries:
                status = e["status"]
                phase = e.get("phase_failed", "")
                err_class = e.get("error_class", "")
                fix_iters = e.get("fix_iterations_count", 0)

                # Build status detail string
                parts = [status]
                if phase:
                    parts.append(f"({phase})")
                if err_class:
                    parts.append(f"[{err_class}]")
                if fix_iters:
                    parts.append(f"fix_iterations={fix_iters}")
                status_detail = " ".join(parts)

                print(f"  [{repo_name}] {e['harness']}: {status_detail}")

                if status != "compiled" and e.get("errors"):
                    # Show failing command
                    if phase == "compile" and e.get("compile_command"):
                        print(f"    cmd: {e['compile_command'][:200]}")
                    elif phase == "link" and e.get("link_command"):
                        print(f"    cmd: {e['link_command'][:200]}")

                    max_err_lines = 10 if verbose else 3
                    for err_line in e["errors"].strip().splitlines()[:max_err_lines]:
                        print(f"    | {err_line}")

                # Show LLM fix iteration summary in verbose mode
                if verbose and e.get("iteration_history"):
                    for rec in e["iteration_history"]:
                        it = (
                            rec.iteration
                            if hasattr(rec, "iteration")
                            else rec.get("iteration", "?")
                        )
                        ec = (
                            rec.error_class
                            if hasattr(rec, "error_class")
                            else rec.get("error_class", "?")
                        )
                        rs = rec.result if hasattr(rec, "result") else rec.get("result", "?")
                        print(f"    [fix #{it}] {ec} -> {rs}")

            print(f"  -> output/<lang>/{repo_name}/fuzz_targets/status.json + build_log.json")
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
        triage=getattr(args, "triage", False),
        parallel=getattr(args, "parallel", 1),
        rss_limit_mb=getattr(args, "rss_limit", 0),
        use_corpus=getattr(args, "corpus", False),
    )

    if not results:
        print("No repos with status.json (run generate-fuzz-drivers --build first).")
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
            unique = r.get("unique_crash_count")
            elapsed = r.get("time_sec", 0)
            crash_label = f"crashes={count}"
            if unique is not None:
                crash_label += f", unique={unique}"
            print(
                f"  {r.get('harness', '?')}: {'CRASH' if crashed else 'ok'} ({crash_label}, time={elapsed}s)"
            )
            # Show triage details if available
            for tc in r.get("triaged_crashes", []):
                print(
                    f"    [{tc.get('severity', '?')}] {tc.get('crash_type', '?')} "
                    f"in {tc.get('faulting_function', '?')} (hash={tc.get('stack_hash', '?')[:8]})"
                )
        print(f"  -> {summary_path}")
    print("\nDone.")
    return 0


def cmd_report(args: argparse.Namespace) -> int:
    """Execute the report command — generate markdown from verification results."""
    from vuln_hunter_x.reporting.markdown import MarkdownReportGenerator

    base_path = Path.cwd()
    output_dir = base_path / "output"

    results_dir = getattr(args, "results_dir", None)

    if results_dir:
        results_dir = Path(results_dir)
    else:
        # Auto-discover from --lang and --repo
        if args.repo and args.lang:
            results_dir = output_dir / args.lang / args.repo / "verification_results"
        elif args.repo:
            # Search across languages
            for lang_dir in sorted(output_dir.iterdir()):
                candidate = lang_dir / args.repo / "verification_results"
                if candidate.is_dir():
                    results_dir = candidate
                    break
        else:
            # Find the most recent verification_results directory
            candidates = list(output_dir.glob("*/*/verification_results"))
            if candidates:
                # Pick the one with the newest file
                results_dir = max(
                    candidates,
                    key=lambda d: max(
                        (f.stat().st_mtime for f in d.glob("*.json")), default=0
                    ),
                )

    if not results_dir or not results_dir.is_dir():
        print(
            "No verification results found. Specify --results-dir, or --repo/--lang.",
            file=sys.stderr,
        )
        return 1

    json_files = list(results_dir.glob("*.json"))
    if not json_files:
        print(f"No JSON verdict files in {results_dir}", file=sys.stderr)
        return 1

    generator = MarkdownReportGenerator()
    result = generator.from_verdict_files(results_dir)

    if not result.verdicts:
        print("No verdicts found in the result files.", file=sys.stderr)
        return 1

    lang_report = getattr(args, "lang_report", "all")
    custom_output = getattr(args, "output", None)
    report_langs = ["en", "vi"] if lang_report == "all" else [lang_report]

    for rl in report_langs:
        if custom_output and len(report_langs) == 1:
            out_path = Path(custom_output)
        elif rl == "vi":
            out_path = results_dir / "report_vi.md"
        else:
            out_path = results_dir / "report.md"

        report_path = generator.generate(result, out_path, report_lang=rl)
        label = "EN" if rl == "en" else "VI"
        print(f"Report ({label}): {report_path}")

    print(f"  Findings: {result.total_findings}")
    for verdict_type, count in result.stats.items():
        if count > 0:
            print(f"  {verdict_type}: {count}")

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
        default_config = _BUNDLED_CONFIG / "confirm_findings.yaml"
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
    print("  Verification: LLM (multi-turn)")
    print(f"  Max iterations: {config.verification.max_iterations}")

    print()
    print("Paths:")
    print(f"  Repos: {config.paths.repos_dir}")
    print(f"  Output: {config.paths.output_dir}")

    return 0


def _stage_banner(stage: str, detail: str = "") -> None:
    """Print a visible banner separating scan pipeline stages."""
    line = f"━━ {stage}" + (f": {detail}" if detail else "")
    print(f"\n{line}\n{'─' * min(len(line), 72)}", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    """Run the full pipeline (prepare → analyze → verify → report) in one command.

    Composes the existing per-stage commands rather than duplicating their
    logic. Each stage receives a Namespace seeded with that stage's own
    argparse defaults (so every attribute the command reads is present),
    overlaid with the relevant values from the scan invocation. Short-circuits
    on the first stage that fails.
    """
    # Lazy import to avoid a circular import at module load (main imports
    # commands). By call time both modules are fully initialised.
    from vuln_hunter_x.cli.main import (
        _add_analyze_args,
        _add_prepare_args,
        _add_report_args,
        _add_verify_args,
    )

    def _stage_ns(adder) -> argparse.Namespace:
        sub = argparse.ArgumentParser(add_help=False)
        adder(sub)
        return sub.parse_args([])

    url = getattr(args, "url", None)
    local_path = getattr(args, "local_path", None)
    config = getattr(args, "config", None)
    lang = getattr(args, "lang", None)
    tool = getattr(args, "tool", "both")
    dry_run = getattr(args, "dry_run", False)
    verbose = getattr(args, "verbose", False)

    # In direct mode (--url / --local-path) we need a concrete repo name + lang
    # so the later stages can target exactly what prepare produced. In config
    # mode (repos.yaml) we fall back to the --repo filter.
    local_mode = bool(local_path)
    direct_mode = bool(url or local_path)
    if direct_mode and not lang:
        print("Error: --lang is required with --url or --local-path", file=sys.stderr)
        return 1
    name = getattr(args, "name", None) or _derive_repo_name(url, local_path) or getattr(args, "repo", None)
    if direct_mode and not name:
        print("Error: could not derive a repository name; pass --name", file=sys.stderr)
        return 1

    # Whether the chosen analyzer can run on source alone (no CodeQL DB). When
    # it can, a failed CodeQL database build is degraded-but-recoverable rather
    # than fatal — Semgrep/OpenGrep still scan the source.
    source_only_capable = tool in ("semgrep", "opengrep", "both", "all")

    def _apply_source_target(ns: argparse.Namespace) -> None:
        """Point a stage Namespace at the right source.

        Local-path scans must thread --local-path through (the source lives at
        the given path, not under repos/); analyze/verify symlink it into
        repos/<lang>/<name> themselves. URL/config scans use the --repo filter,
        which the stages resolve against the output/ + repos/ trees.
        """
        ns.lang = lang
        if local_mode:
            ns.local_path = local_path
            ns.name = name
            ns.repo = None
        else:
            ns.repo = name if direct_mode else getattr(args, "repo", None)

    # ── Stage 1: prepare ──
    _stage_banner("prepare", name or "(config mode)")
    prep = _stage_ns(_add_prepare_args)
    prep.url = url
    prep.local_path = local_path
    prep.config = config
    prep.name = name
    prep.lang = lang
    prep.repo = getattr(args, "repo", None)
    prep.build_command = getattr(args, "build_command", None)
    prep.dry_run = dry_run
    rc = cmd_prepare(prep)
    if rc != 0:
        if not source_only_capable:
            print(
                "scan: prepare failed and --tool codeql requires a CodeQL database; "
                "aborting. Re-run with --tool semgrep for source-only analysis.",
                file=sys.stderr,
            )
            return rc
        print(
            "scan: CodeQL database preparation failed — continuing with source-only "
            f"analysis (--tool {tool} includes a source scanner). CodeQL findings "
            "will be absent; fix the build to include them.",
            file=sys.stderr,
        )

    # ── Stage 2: analyze ──
    _stage_banner("analyze", f"tool={tool} profile={args.profile or 'standard'}")
    analyze = _stage_ns(_add_analyze_args)
    analyze.tool = tool
    analyze.profile = args.profile
    analyze.config = config
    analyze.verbose = verbose
    analyze.dry_run = dry_run
    _apply_source_target(analyze)
    rc = cmd_analyze(analyze)
    if rc != 0:
        print("scan: analyze failed; aborting.", file=sys.stderr)
        return rc

    if getattr(args, "skip_verify", False):
        print("\nscan: --skip-verify set; stopping after analyze.", file=sys.stderr)
        return 0

    # ── Stage 3: verify ──
    _stage_banner("verify", name or "(all)")
    verify = _stage_ns(_add_verify_args)
    verify.config = config
    verify.provider = getattr(args, "provider", None)
    verify.model = getattr(args, "model", None)
    verify.limit = getattr(args, "limit", None)
    verify.verbose = verbose
    verify.dry_run = dry_run
    _apply_source_target(verify)
    rc = cmd_verify(verify)
    if rc != 0:
        print("scan: verify failed; aborting.", file=sys.stderr)
        return rc

    if getattr(args, "skip_report", False) or dry_run:
        return 0

    # ── Stage 4: report ── (reads output/<lang>/<name>, keyed by repo name)
    _stage_banner("report", name or "(all)")
    report = _stage_ns(_add_report_args)
    report.lang = lang
    report.repo = name if direct_mode else getattr(args, "repo", None)
    rc = cmd_report(report)
    if rc != 0:
        print("scan: report failed.", file=sys.stderr)
        return rc

    print("\nscan: pipeline complete.", file=sys.stderr)
    return 0
