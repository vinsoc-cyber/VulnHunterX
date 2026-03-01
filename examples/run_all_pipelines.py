#!/usr/bin/env python3
"""
Batch Pipeline Runner: Process All Repositories

This script runs the complete CodeQL + LLM pipeline for all repositories
defined in config/repos.yaml. It logs progress and results to a timestamped
log file.

Stages:
1. Clone: Clone repository and create CodeQL database
2. Analyze: Run CodeQL security analysis (generates SARIF)
3. Extract: Extract context CSVs for multi-turn verification
4. Verify: Verify findings with LLM (LLM mode)
5. [optional] Build with sanitizers for fuzz harness linking (C/C++ only)
6. [optional] Extract fuzz context CSVs (function_signatures, includes) from C/C++ databases (C/C++ only)
7. [optional] Generate libFuzzer harness .cc from verified findings (C/C++ only)
8. [optional] Run libFuzzer for each compiled harness; collect crashes and write a summary. (C/C++ only)

Features:
- Skips stages if results already exist (use --force to override)
- Logs all output to output/logs/pipeline_{timestamp}.log
- Generates summary JSON with comprehensive statistics

Usage:
    python examples/run_all_pipelines.py              # Run all repos (all stages)
    python examples/run_all_pipelines.py --force      # Force re-run all stages
    python examples/run_all_pipelines.py --lang c     # Only C repos
    python examples/run_all_pipelines.py --repo libucl # Only specific repo
    python examples/run_all_pipelines.py --dry-run    # Preview without executing
    python examples/run_all_pipelines.py --no-verify  # Skip verification stage
    python examples/run_all_pipelines.py --verify-limit 5
    python examples/run_all_pipelines.py --fuzz --repo libucl   # Include fuzz stages 5-8 (C/C++)
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import TextIO

import yaml


# =============================================================================
# Configuration
# =============================================================================

_CLI = [sys.executable, "-m", "vuln_hunter_x.cli.main"]


class TeeOutput:
    """Write to both stdout and a log file."""
    
    def __init__(self, log_file: TextIO):
        self.terminal = sys.stdout
        self.log_file = log_file
    
    def write(self, message: str) -> None:
        self.terminal.write(message)
        self.log_file.write(message)
        self.log_file.flush()
    
    def flush(self) -> None:
        self.terminal.flush()
        self.log_file.flush()


def timestamp() -> str:
    """Return current timestamp for logging."""
    return datetime.now().strftime("%H:%M:%S")


def print_header(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def run_command(
    cmd: list[str],
    dry_run: bool = False,
    timeout: int = 1800,
) -> tuple[bool, str]:
    """
    Run a shell command and return success status.
    
    Args:
        cmd: Command as list of strings
        dry_run: If True, only print the command
        timeout: Command timeout in seconds
        
    Returns:
        Tuple of (success, output)
    """
    cmd_str = " ".join(cmd)
    
    if dry_run:
        print(f"  [DRY-RUN] Would execute: {cmd_str}")
        return True, ""
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        output = result.stdout + result.stderr
        return result.returncode == 0, output
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def load_repos(config_path: Path) -> list[dict]:
    """Load repositories from repos.yaml."""
    with open(config_path) as f:
        data = yaml.safe_load(f)
    return data.get("repos", [])


def check_sarif_exists(repo_name: str, lang: str, base_path: Path) -> tuple[bool, int]:
    """Check if SARIF file exists and return findings count."""
    sarif_path = base_path / "output" / lang / repo_name / f"{repo_name}.sarif"
    if not sarif_path.exists():
        return False, 0
    try:
        with open(sarif_path) as f:
            sarif_data = json.load(f)
        count = sum(len(run.get("results", [])) for run in sarif_data.get("runs", []))
        return True, count
    except Exception:
        return True, 0


def check_context_exists(repo_name: str, lang: str, base_path: Path) -> tuple[bool, int]:
    """Check if context CSVs exist and return file count."""
    context_dir = base_path / "output" / lang / repo_name / "context"
    if not context_dir.exists():
        return False, 0
    csv_files = list(context_dir.glob("*.csv"))
    return len(csv_files) > 0, len(csv_files)


def check_database_exists(repo_name: str, lang: str, base_path: Path) -> bool:
    """Check if CodeQL database exists."""
    db_path = base_path / "output" / lang / repo_name / "database"
    return db_path.is_dir() and (db_path / "codeql-database.yml").exists()


def get_sarif_findings_count(repo_name: str, lang: str, base_path: Path) -> int:
    """Get the number of findings from a SARIF file."""
    sarif_path = base_path / "output" / lang / repo_name / f"{repo_name}.sarif"
    if not sarif_path.exists():
        return 0
    try:
        with open(sarif_path) as f:
            sarif_data = json.load(f)
        return sum(len(run.get("results", [])) for run in sarif_data.get("runs", []))
    except Exception:
        return 0


def get_verification_stats(base_path: Path) -> dict:
    """
    Collect verification statistics from result files.
    
    Returns:
        Dictionary with verdict counts and details
    """
    output_dir = base_path / "output"
    if not output_dir.is_dir():
        return {}
    
    stats = {
        "total_verified": 0,
        "verdicts": {},
        "by_repo": {},
        "by_language": {},
    }
    
    # Scan output/<lang>/<repo>/verification_results/*.json (skip summary_*.json)
    for lang_dir in output_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        lang = lang_dir.name
        if lang not in stats["by_language"]:
            stats["by_language"][lang] = {"total": 0, "verdicts": {}}
        
        for repo_dir in lang_dir.iterdir():
            if not repo_dir.is_dir():
                continue
            repo_name = repo_dir.name
            ver_dir = repo_dir / "verification_results"
            if not ver_dir.is_dir():
                continue
            if repo_name not in stats["by_repo"]:
                stats["by_repo"][repo_name] = {"total": 0, "verdicts": {}}
            
            for result_file in ver_dir.glob("*.json"):
                if result_file.name.startswith("summary_"):
                    continue
                try:
                    with open(result_file) as f:
                        result = json.load(f)
                    
                    verdict = result.get("verdict", "Unknown")
                    
                    # Update global stats
                    stats["total_verified"] += 1
                    stats["verdicts"][verdict] = stats["verdicts"].get(verdict, 0) + 1
                    
                    # Update by repo
                    stats["by_repo"][repo_name]["total"] += 1
                    stats["by_repo"][repo_name]["verdicts"][verdict] = \
                        stats["by_repo"][repo_name]["verdicts"].get(verdict, 0) + 1
                    
                    # Update by language
                    stats["by_language"][lang]["total"] += 1
                    stats["by_language"][lang]["verdicts"][verdict] = \
                        stats["by_language"][lang]["verdicts"].get(verdict, 0) + 1
                    
                except Exception:
                    continue
    
    return stats


# =============================================================================
# Pipeline Stages
# =============================================================================

def stage_clone(
    repo_name: str,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[str, str]:
    """
    Stage 1: Clone repository and create CodeQL database.
    
    Returns:
        Tuple of (status, message) where status is OK/SKIP/FAIL
    """
    cmd = _CLI + ["clone", "--repo", repo_name]
    
    if dry_run:
        return "DRY-RUN", "Would clone and create database"
    
    success, output = run_command(cmd)
    
    if "Database already exists" in output:
        return "SKIP", "Database already exists"
    elif success:
        return "OK", "Database created"
    else:
        # Extract error message
        error_msg = output.split("\n")[-3] if output else "Unknown error"
        return "FAIL", error_msg[:80]


def stage_analyze(
    repo_name: str,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[str, str]:
    """
    Stage 2: Run CodeQL security analysis.
    
    Returns:
        Tuple of (status, message) where status is OK/SKIP/FAIL
    """
    cmd = _CLI + ["analyze", "--repo", repo_name]
    if force:
        cmd.append("--force")
    
    if dry_run:
        return "DRY-RUN", "Would run CodeQL analysis"
    
    success, output = run_command(cmd)
    
    if "[SKIP]" in output:
        # Extract findings count from skip message
        import re
        match = re.search(r"\((\d+) findings\)", output)
        count = match.group(1) if match else "?"
        return "SKIP", f"SARIF exists ({count} findings)"
    elif success:
        # Extract findings count
        import re
        match = re.search(r"(\d+) findings", output)
        count = match.group(1) if match else "?"
        return "OK", f"{count} findings"
    else:
        error_lines = [l for l in output.split("\n") if "FAIL" in l or "error" in l.lower()]
        error_msg = error_lines[0] if error_lines else "Analysis failed"
        return "FAIL", error_msg[:80]


def stage_extract_context(
    repo_name: str,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[str, str]:
    """
    Stage 3: Extract context CSVs for multi-turn verification.
    
    Returns:
        Tuple of (status, message) where status is OK/SKIP/FAIL
    """
    cmd = _CLI + ["extract-context", "--repo", repo_name]
    if force:
        cmd.append("--force")
    
    if dry_run:
        return "DRY-RUN", "Would extract context CSVs"
    
    success, output = run_command(cmd)
    
    if "[SKIP]" in output:
        import re
        match = re.search(r"\((\d+) CSV files\)", output)
        count = match.group(1) if match else "?"
        return "SKIP", f"Context exists ({count} CSV files)"
    elif success:
        # Count successful queries
        ok_count = output.count("[OK]")
        return "OK", f"{ok_count} CSV files"
    else:
        return "FAIL", "Context extraction failed"


def stage_verify(
    repo_name: str,
    lang: str,
    limit: int = 10,
    force: bool = False,
    dry_run: bool = False,
    base_path: Path | None = None,
) -> tuple[str, str]:
    """
    Stage 4: Verify findings with LLM (LLM mode).
    
    Returns:
        Tuple of (status, message) where status is OK/SKIP/FAIL
    """
    import re
    
    base_path = base_path or Path.cwd()
    
    # Check if verification results already exist for this repo
    results_dir = base_path / "output" / lang / repo_name / "verification_results"
    all_jsons = list(results_dir.glob("*.json")) if results_dir.exists() else []
    existing_results = [f for f in all_jsons if not f.name.startswith("summary_")]
    
    if existing_results and not force:
        # Count verdicts from existing results
        tp_count = fp_count = nmd_count = 0
        for result_file in existing_results:
            try:
                with open(result_file) as f:
                    result = json.load(f)
                verdict = result.get("verdict", "")
                if verdict == "True Positive":
                    tp_count += 1
                elif verdict == "False Positive":
                    fp_count += 1
                elif verdict == "Needs More Data":
                    nmd_count += 1
            except Exception:
                pass
        return "SKIP", f"Already verified ({len(existing_results)} findings: TP={tp_count}, FP={fp_count})"
    
    cmd = _CLI + [
        "verify",
        "--repo", repo_name,
        "--limit", str(limit),
        "--max-iterations", "5",
        "-q",  # Quiet mode for batch processing
    ]
    
    if dry_run:
        return "DRY-RUN", f"Would verify (LLM mode, limit={limit})"
    
    success, output = run_command(cmd, timeout=3600)  # 1 hour timeout for verification
    
    if success:
        # Extract verdict summary from output
        tp_match = re.search(r"True Positive:\s*(\d+)", output)
        fp_match = re.search(r"False Positive:\s*(\d+)", output)
        total_match = re.search(r"Total:\s*(\d+)", output)
        
        tp = tp_match.group(1) if tp_match else "?"
        fp = fp_match.group(1) if fp_match else "?"
        total = total_match.group(1) if total_match else "?"
        
        return "OK", f"{total} verified (TP={tp}, FP={fp})"
    else:
        error_lines = [l for l in output.split("\n") if "error" in l.lower()]
        error_msg = error_lines[0] if error_lines else "Verification failed"
        return "FAIL", error_msg[:80]


def stage_build_sanitized(
    repo_name: str,
    force: bool = False,
    dry_run: bool = False,
) -> tuple[str, str]:
    """
    Stage 5 (fuzz): Build repo with sanitizers for fuzz harness linking.
    C/C++ only.
    """
    cmd = _CLI + ["build-sanitized", "--repo", repo_name]
    if force:
        cmd.append("--force")
    if dry_run:
        return "DRY-RUN", "Would run build-sanitized"
    success, output = run_command(cmd, timeout=2400)
    if success:
        if "OK" in output:
            return "OK", "Sanitized build done"
        return "SKIP", "Build skipped or already exists"
    return "FAIL", (output or "Build failed")[:80]


def stage_extract_fuzz_context(
    repo_name: str,
    dry_run: bool = False,
) -> tuple[str, str]:
    """
    Stage 6 (fuzz): Extract fuzz context CSVs (function_signatures, includes).
    C/C++ only.
    """
    cmd = _CLI + ["extract-fuzz-context", "--repo", repo_name]
    if dry_run:
        return "DRY-RUN", "Would extract fuzz context"
    success, output = run_command(cmd)
    if success:
        return "OK", "Fuzz context extracted"
    return "FAIL", (output or "Extract failed")[:80]


def stage_generate_fuzz_drivers(
    repo_name: str,
    build: bool = True,
    dry_run: bool = False,
) -> tuple[str, str]:
    """
    Stage 7 (fuzz): Generate fuzz drivers and optionally build.
    C/C++ only.
    """
    cmd = _CLI + ["generate-fuzz-drivers", "--repo", repo_name, "--verdict", "tp,nmd"]
    if build:
        cmd.append("--build")
    if dry_run:
        return "DRY-RUN", "Would generate (and build) fuzz drivers"
    success, output = run_command(cmd, timeout=600)
    if success:
        count = output.count(".cc:") or output.count("harness")
        return "OK", f"Drivers generated (build={'yes' if build else 'no'})"
    return "FAIL", (output or "Generate failed")[:80]


def stage_fuzz_run(
    repo_name: str,
    timeout: int = 60,
    max_fuzz_time: int = 30,
    dry_run: bool = False,
) -> tuple[str, str]:
    """
    Stage 8 (fuzz): Run libFuzzer for compiled harnesses, collect crashes.
    C/C++ only.
    """
    cmd = _CLI + [
        "fuzz-run",
        "--repo", repo_name,
        "--timeout", str(timeout),
        "--max-fuzz-time", str(max_fuzz_time),
    ]
    if dry_run:
        return "DRY-RUN", "Would run fuzzers"
    success, output = run_command(cmd, timeout=timeout * 20)  # allow multiple harnesses
    if success:
        return "OK", "Fuzz run done"
    return "FAIL", (output or "Fuzz run failed")[:80]


# =============================================================================
# Main Pipeline Runner
# =============================================================================

def run_pipeline(
    repos: list[dict],
    force: bool = False,
    force_analyze: bool = False,
    force_extract: bool = False,
    force_verify: bool = False,
    run_verify: bool = True,
    verify_limit: int = 10,
    dry_run: bool = False,
    base_path: Path | None = None,
    run_fuzz: bool = False,
    fuzz_timeout: int = 60,
    fuzz_max_time: int = 30,
) -> dict:
    """
    Run the pipeline for all repositories.
    If run_fuzz is True, run stages 5-8 (build-sanitized, extract-fuzz-context,
    generate-fuzz-drivers --build, fuzz-run) for C/C++ repos after stage 4.
    
    Returns:
        Summary statistics dictionary
    """
    import re
    
    base_path = base_path or Path.cwd()
    total = len(repos)
    stats = {
        "total": total,
        "successful": 0,
        "failed": 0,
        "skipped": 0,
        "repos": {},
        # Pipeline run statistics
        "run_stats": {
            "total_findings": 0,
            "total_verified": 0,
            "verdicts": {
                "True Positive": 0,
                "False Positive": 0,
                "Needs More Data": 0,
            },
            "by_language": {},
            "by_repo": {},
        },
    }
    
    for i, repo in enumerate(repos, 1):
        name = repo["name"]
        lang = repo["language"]
        
        print(f"\n[{i}/{total}] {name} ({lang})")
        print("-" * 40)
        
        repo_stats = {
            "language": lang,
            "clone": None,
            "analyze": None,
            "extract": None,
            "verify": None,
            "build_sanitized": None,
            "extract_fuzz_context": None,
            "generate_fuzz_drivers": None,
            "fuzz_run": None,
        }
        
        # Stage 1: Clone
        print(f"[{timestamp()}] Clone:   ", end="", flush=True)
        status, msg = stage_clone(name, force=force, dry_run=dry_run)
        print(f"[{status}] {msg}")
        repo_stats["clone"] = {"status": status, "message": msg}
        
        if status == "FAIL":
            stats["failed"] += 1
            stats["repos"][name] = repo_stats
            continue
        
        # Stage 2: Analyze
        print(f"[{timestamp()}] Analyze: ", end="", flush=True)
        status, msg = stage_analyze(name, force=force or force_analyze, dry_run=dry_run)
        print(f"[{status}] {msg}")
        repo_stats["analyze"] = {"status": status, "message": msg}
        
        if status == "FAIL":
            stats["failed"] += 1
            stats["repos"][name] = repo_stats
            continue
        
        # Stage 3: Extract Context
        print(f"[{timestamp()}] Context: ", end="", flush=True)
        status, msg = stage_extract_context(name, force=force or force_extract, dry_run=dry_run)
        print(f"[{status}] {msg}")
        repo_stats["extract"] = {"status": status, "message": msg}
        
        if status == "FAIL":
            stats["failed"] += 1
            stats["repos"][name] = repo_stats
            continue
        
        # Stage 4: Verify (optional)
        if run_verify:
            print(f"[{timestamp()}] Verify:  ", end="", flush=True)
            status, msg = stage_verify(
                name,
                lang=lang,
                limit=verify_limit,
                force=force or force_verify,
                dry_run=dry_run,
                base_path=base_path,
            )
            print(f"[{status}] {msg}")
            repo_stats["verify"] = {"status": status, "message": msg}
            
            # Extract verification stats from message
            # Format: "X verified (TP=Y, FP=Z)" or "Already verified (X findings: TP=Y, FP=Z)"
            tp_match = re.search(r"TP[=:](\d+)", msg)
            fp_match = re.search(r"FP[=:](\d+)", msg)
            total_match = re.search(r"(\d+)\s*(?:verified|findings)", msg)
            
            if total_match:
                verified_count = int(total_match.group(1))
                tp_count = int(tp_match.group(1)) if tp_match else 0
                fp_count = int(fp_match.group(1)) if fp_match else 0
                nmd_count = verified_count - tp_count - fp_count
                
                # Update run stats
                stats["run_stats"]["total_verified"] += verified_count
                stats["run_stats"]["verdicts"]["True Positive"] += tp_count
                stats["run_stats"]["verdicts"]["False Positive"] += fp_count
                stats["run_stats"]["verdicts"]["Needs More Data"] += nmd_count
                
                # By language
                if lang not in stats["run_stats"]["by_language"]:
                    stats["run_stats"]["by_language"][lang] = {
                        "verified": 0, "tp": 0, "fp": 0, "nmd": 0
                    }
                stats["run_stats"]["by_language"][lang]["verified"] += verified_count
                stats["run_stats"]["by_language"][lang]["tp"] += tp_count
                stats["run_stats"]["by_language"][lang]["fp"] += fp_count
                stats["run_stats"]["by_language"][lang]["nmd"] += nmd_count
                
                # By repo
                stats["run_stats"]["by_repo"][name] = {
                    "language": lang,
                    "verified": verified_count,
                    "tp": tp_count,
                    "fp": fp_count,
                    "nmd": nmd_count,
                }
            
            if status == "FAIL":
                stats["failed"] += 1
            else:
                stats["successful"] += 1
        else:
            stats["successful"] += 1

        # Stages 5-8 (fuzz): C/C++ only, when --fuzz
        if run_fuzz and lang in ("c", "cpp"):
            # Stage 5: build-sanitized
            print(f"[{timestamp()}] BuildSan: ", end="", flush=True)
            status, msg = stage_build_sanitized(name, force=force, dry_run=dry_run)
            print(f"[{status}] {msg}")
            repo_stats["build_sanitized"] = {"status": status, "message": msg}
            if status == "FAIL":
                stats["failed"] += 1
                stats["repos"][name] = repo_stats
                continue

            # Stage 6: extract-fuzz-context
            print(f"[{timestamp()}] FuzzCtx:  ", end="", flush=True)
            status, msg = stage_extract_fuzz_context(name, dry_run=dry_run)
            print(f"[{status}] {msg}")
            repo_stats["extract_fuzz_context"] = {"status": status, "message": msg}
            if status == "FAIL":
                stats["failed"] += 1
                stats["repos"][name] = repo_stats
                continue

            # Stage 7: generate-fuzz-drivers --build
            print(f"[{timestamp()}] GenFuzz:  ", end="", flush=True)
            status, msg = stage_generate_fuzz_drivers(name, build=True, dry_run=dry_run)
            print(f"[{status}] {msg}")
            repo_stats["generate_fuzz_drivers"] = {"status": status, "message": msg}

            # Stage 8: fuzz-run
            print(f"[{timestamp()}] FuzzRun:  ", end="", flush=True)
            status, msg = stage_fuzz_run(name, timeout=fuzz_timeout, max_fuzz_time=fuzz_max_time, dry_run=dry_run)
            print(f"[{status}] {msg}")
            repo_stats["fuzz_run"] = {"status": status, "message": msg}
        
        # Count skips
        stages_to_check = [repo_stats["clone"], repo_stats["analyze"], repo_stats["extract"]]
        if run_verify and repo_stats["verify"]:
            stages_to_check.append(repo_stats["verify"])
        
        skip_count = sum(1 for stage in stages_to_check if stage and stage["status"] == "SKIP")
        if skip_count == len(stages_to_check):
            stats["skipped"] += 1
        
        stats["repos"][name] = repo_stats
    
    return stats


def print_summary(stats: dict, elapsed: float, base_path: Path) -> None:
    """Print pipeline summary with comprehensive statistics."""
    print_header("SUMMARY")
    
    # Pipeline execution summary
    print("Pipeline Execution:")
    print(f"  Total repos:    {stats['total']}")
    print(f"  Successful:     {stats['successful']}")
    print(f"  Failed:         {stats['failed']}")
    print(f"  All skipped:    {stats['skipped']}")
    print()
    
    # Show failed repos
    failed_repos = [
        name for name, data in stats["repos"].items()
        if any(
            stage and stage["status"] == "FAIL"
            for stage in [data.get("clone"), data.get("analyze"), data.get("extract"), data.get("verify")]
        )
    ]
    if failed_repos:
        print("Failed repos:")
        for name in failed_repos:
            data = stats["repos"][name]
            for stage_name in ["clone", "analyze", "extract", "verify"]:
                stage = data.get(stage_name)
                if stage and stage["status"] == "FAIL":
                    print(f"  - {name}: {stage_name} - {stage['message']}")
        print()
    
    # Collect findings statistics from SARIF files
    print_header("FINDINGS STATISTICS")
    
    total_findings = 0
    findings_by_lang: dict[str, int] = {}
    findings_by_repo: dict[str, tuple[str, int]] = {}  # repo -> (lang, count)
    
    for repo_name, repo_data in stats["repos"].items():
        lang = repo_data.get("language", "unknown")
        count = get_sarif_findings_count(repo_name, lang, base_path)
        
        if count > 0:
            total_findings += count
            findings_by_lang[lang] = findings_by_lang.get(lang, 0) + count
            findings_by_repo[repo_name] = (lang, count)
    
    print(f"Total CodeQL findings: {total_findings}")
    print()
    
    if findings_by_lang:
        print("Findings by language:")
        for lang in sorted(findings_by_lang.keys()):
            print(f"  {lang:12} {findings_by_lang[lang]:>5} findings")
        print()
    
    if findings_by_repo:
        print("Findings by repository:")
        # Sort by count descending
        sorted_repos = sorted(findings_by_repo.items(), key=lambda x: x[1][1], reverse=True)
        for repo_name, (lang, count) in sorted_repos[:15]:  # Top 15
            print(f"  {repo_name:30} ({lang:10}) {count:>5} findings")
        if len(sorted_repos) > 15:
            remaining = sum(c for _, (_, c) in sorted_repos[15:])
            print(f"  ... and {len(sorted_repos) - 15} more repos with {remaining} findings")
        print()
    
    # Show pipeline run verification statistics
    run_stats = stats.get("run_stats", {})
    if run_stats.get("total_verified", 0) > 0:
        print_header("PIPELINE RUN VERIFICATION")
        
        total_v = run_stats["total_verified"]
        verdicts = run_stats.get("verdicts", {})
        tp = verdicts.get("True Positive", 0)
        fp = verdicts.get("False Positive", 0)
        nmd = verdicts.get("Needs More Data", 0)
        
        # Calculate rates
        confirmed = tp + fp
        confirmation_rate = confirmed / total_v * 100 if total_v else 0
        inconclusive_rate = nmd / total_v * 100 if total_v else 0
        fp_rate = fp / confirmed * 100 if confirmed else 0
        
        print(f"Verified in this run: {total_v}")
        print(f"  Confirmed:          {confirmed} ({confirmation_rate:.1f}%)")
        print(f"  Inconclusive:       {nmd} ({inconclusive_rate:.1f}%)")
        print()
        
        print("Verdicts:")
        if tp > 0:
            print(f"  True Positive       {tp:>5} ({tp/total_v*100:>5.1f}%) - Real bugs requiring attention")
        if fp > 0:
            print(f"  False Positive      {fp:>5} ({fp/total_v*100:>5.1f}%) - Safe to ignore")
        if nmd > 0:
            print(f"  Needs More Data     {nmd:>5} ({nmd/total_v*100:>5.1f}%) - Requires manual review")
        print()
        
        # Show false positive rate among confirmed
        if confirmed > 0:
            print(f"False Positive Rate (among confirmed): {fp_rate:.1f}%")
            print()
        
        # Show recommendation for NMD findings
        if nmd > 0:
            print("Note: 'Needs More Data' findings could not be confirmed automatically.")
            print("      These require manual code review or additional context.")
            print()
        
        # Show by language
        by_lang = run_stats.get("by_language", {})
        if by_lang:
            print("By language:")
            for lang, data in sorted(by_lang.items()):
                print(f"  {lang:12} {data['verified']:>3} verified (TP: {data['tp']}, FP: {data['fp']}, NMD: {data['nmd']})")
            print()
        
        # Show by repo
        by_repo = run_stats.get("by_repo", {})
        if by_repo:
            print("By repository:")
            sorted_repos = sorted(by_repo.items(), key=lambda x: x[1]["verified"], reverse=True)
            for repo_name, data in sorted_repos[:15]:
                print(f"  {repo_name:25} {data['verified']:>3} verified (TP: {data['tp']}, FP: {data['fp']}, NMD: {data['nmd']})")
            print()
    
    # Collect overall verification statistics from disk
    verification_stats = get_verification_stats(base_path)
    
    if verification_stats.get("total_verified", 0) > 0:
        print_header("OVERALL VERIFICATION (All Results)")
        
        total_all = verification_stats['total_verified']
        all_verdicts = verification_stats.get("verdicts", {})
        all_tp = all_verdicts.get("True Positive", 0)
        all_fp = all_verdicts.get("False Positive", 0)
        all_nmd = all_verdicts.get("Needs More Data", 0)
        all_confirmed = all_tp + all_fp
        
        print(f"Total findings verified (all time): {total_all}")
        print(f"  Confirmed (TP + FP):              {all_confirmed}")
        print(f"  Inconclusive (Needs More Data):   {all_nmd}")
        if all_confirmed > 0:
            all_fp_rate = all_fp / all_confirmed * 100
            print(f"  False Positive Rate:              {all_fp_rate:.1f}%")
        print()
        
        verdicts = verification_stats.get("verdicts", {})
        if verdicts:
            print("Verdicts:")
            total_v = verification_stats["total_verified"]
            for verdict in ["True Positive", "False Positive", "Needs More Data", "Unknown"]:
                count = verdicts.get(verdict, 0)
                if count > 0:
                    pct = count / total_v * 100 if total_v else 0
                    print(f"  {verdict:20} {count:>5} ({pct:>5.1f}%)")
            print()
        
        # Show by language
        by_lang = verification_stats.get("by_language", {})
        if by_lang:
            print("Verified by language:")
            for lang, data in sorted(by_lang.items()):
                tp = data["verdicts"].get("True Positive", 0)
                fp = data["verdicts"].get("False Positive", 0)
                total_l = data["total"]
                print(f"  {lang:12} {total_l:>3} verified (TP: {tp}, FP: {fp})")
            print()
        
        # Show by repo (top repos)
        by_repo = verification_stats.get("by_repo", {})
        if by_repo:
            print("Verified by repository (top 10):")
            sorted_repos = sorted(by_repo.items(), key=lambda x: x[1]["total"], reverse=True)
            for repo_name, data in sorted_repos[:10]:
                tp = data["verdicts"].get("True Positive", 0)
                fp = data["verdicts"].get("False Positive", 0)
                nmd = data["verdicts"].get("Needs More Data", 0)
                print(f"  {repo_name:25} {data['total']:>3} verified (TP: {tp}, FP: {fp}, NMD: {nmd})")
            print()
    
    # Time summary
    minutes = int(elapsed // 60)
    seconds = int(elapsed % 60)
    print(f"Time elapsed: {minutes}m {seconds}s")
    
    # Store additional stats
    stats["findings"] = {
        "total": total_findings,
        "by_language": findings_by_lang,
        "by_repo": {k: {"language": v[0], "count": v[1]} for k, v in findings_by_repo.items()},
    }
    stats["verification"] = verification_stats


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Run CodeQL + LLM pipeline for all repositories",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Force re-run all stages (ignore existing results)",
    )
    parser.add_argument(
        "--force-analyze",
        action="store_true",
        help="Force re-run only analyze stage",
    )
    parser.add_argument(
        "--force-extract",
        action="store_true",
        help="Force re-run only extract-context stage",
    )
    parser.add_argument(
        "--force-verify",
        action="store_true",
        help="Force re-run only verify stage",
    )
    parser.add_argument(
        "--no-verify",
        action="store_true",
        help="Skip verification stage (only clone, analyze, extract)",
    )
    parser.add_argument(
        "--verify-limit",
        type=int,
        default=10,
        help="Max findings to verify per repo (default: 10)",
    )
    parser.add_argument(
        "--repo",
        help="Process only this repository",
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript", "php", "java"],
        help="Process only this language",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview actions without executing",
    )
    parser.add_argument(
        "--log-dir",
        type=Path,
        default=Path("output/logs"),
        help="Directory for log files (default: output/logs)",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("config/repos.yaml"),
        help="Path to repos.yaml (default: config/repos.yaml)",
    )
    parser.add_argument(
        "--fuzz",
        action="store_true",
        help="Run fuzz stages 5-8 for C/C++ repos (build-sanitized, extract-fuzz-context, generate-fuzz-drivers --build, fuzz-run)",
    )
    parser.add_argument(
        "--fuzz-timeout",
        type=int,
        default=60,
        help="Timeout per harness for fuzz-run in seconds (default: 60)",
    )
    parser.add_argument(
        "--fuzz-max-time",
        type=int,
        default=30,
        help="libFuzzer -max_total_time per harness (default: 30)",
    )
    
    args = parser.parse_args()
    
    # Setup
    base_path = Path.cwd()
    config_path = args.config if args.config.is_absolute() else base_path / args.config
    log_dir = args.log_dir if args.log_dir.is_absolute() else base_path / args.log_dir
    
    if not config_path.exists():
        print(f"Config not found: {config_path}", file=sys.stderr)
        return 1
    
    # Load repos
    repos = load_repos(config_path)
    
    # Apply filters
    if args.lang:
        repos = [r for r in repos if r.get("language") == args.lang]
    if args.repo:
        repos = [r for r in repos if r.get("name", "").lower() == args.repo.lower()]
    
    if not repos:
        print("No repositories to process.", file=sys.stderr)
        return 1
    
    # Setup logging
    log_dir.mkdir(parents=True, exist_ok=True)
    timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file_path = log_dir / f"pipeline_{timestamp_str}.log"
    summary_file_path = log_dir / f"pipeline_{timestamp_str}_summary.json"
    
    with open(log_file_path, "w") as log_file:
        # Redirect stdout to both terminal and log file
        original_stdout = sys.stdout
        sys.stdout = TeeOutput(log_file)
        
        try:
            # Print header
            print("=" * 70)
            print("  CodeQL + LLM Pipeline Runner")
            print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"  Repos: {len(repos)}")
            if args.force:
                print("  Mode: FORCE (re-run all stages)")
            elif args.force_analyze:
                print("  Mode: Force analyze only")
            elif args.force_extract:
                print("  Mode: Force extract-context only")
            elif args.force_verify:
                print("  Mode: Force verify only")
            else:
                print("  Mode: Skip existing results")
            if not args.no_verify:
                print(f"  Verify: LLM mode, limit={args.verify_limit}")
            else:
                print("  Verify: DISABLED (--no-verify)")
            if args.fuzz:
                print("  Fuzz: ENABLED (stages 5-8 for C/C++)")
            print("=" * 70)
            
            # Run pipeline
            start_time = time.time()
            
            stats = run_pipeline(
                repos,
                force=args.force,
                force_analyze=args.force_analyze,
                force_extract=args.force_extract,
                force_verify=args.force_verify,
                run_verify=not args.no_verify,
                verify_limit=args.verify_limit,
                dry_run=args.dry_run,
                base_path=base_path,
                run_fuzz=args.fuzz,
                fuzz_timeout=args.fuzz_timeout,
                fuzz_max_time=args.fuzz_max_time,
            )
            
            elapsed = time.time() - start_time
            
            # Print summary (also updates stats with findings/verification data)
            print_summary(stats, elapsed, base_path)
            
            # Save summary JSON
            stats["elapsed_seconds"] = elapsed
            stats["timestamp"] = timestamp_str
            stats["log_file"] = str(log_file_path)
            
            with open(summary_file_path, "w") as f:
                json.dump(stats, f, indent=2)
            
            print(f"\nLog saved:     {log_file_path}")
            print(f"Summary JSON:  {summary_file_path}")
            
        finally:
            sys.stdout = original_stdout
    
    # Return appropriate exit code
    return 0 if stats["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
