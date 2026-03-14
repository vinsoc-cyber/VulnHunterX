#!/usr/bin/env python3
"""
Full Pipeline Example: Java Repository (webgoat)

This script demonstrates the complete CodeQL + LLM verification pipeline
for a Java repository.

Note:
    Ensure `webgoat` is present in `config/repos.yaml` before running clone.

Usage:
    python examples/pipeline_java.py              # Run full pipeline
    python examples/pipeline_java.py --dry-run    # Preview without executing
    python examples/pipeline_java.py --skip-clone # Skip clone if already exists
    python examples/pipeline_java.py --api        # Use Python API instead of CLI
"""

import subprocess
import sys
import time
from pathlib import Path

# =============================================================================
# Configuration
# =============================================================================

REPO_NAME = "webgoat"
LANGUAGE = "java"
MAX_FINDINGS = 5
MAX_ITERATIONS = 5  # LLM conversation rounds per finding

_CLI = [sys.executable, "-m", "vuln_hunter_x.cli.main"]

# =============================================================================
# Pipeline Stages
# =============================================================================


def print_header(title: str) -> None:
    """Print a formatted stage header."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def run_command(cmd: list[str], dry_run: bool = False) -> tuple[bool, str]:
    """Run a shell command and return success status."""
    cmd_str = " ".join(cmd)

    if dry_run:
        print(f"[DRY-RUN] Would execute: {cmd_str}")
        return True, ""

    print(f"Executing: {cmd_str}")
    print("-" * 50)

    try:
        result = subprocess.run(
            cmd,
            capture_output=False,
            text=True,
            timeout=1200,
        )
        return result.returncode == 0, ""
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def stage_clone(dry_run: bool = False, skip: bool = False) -> tuple[bool, bool]:
    """Stage 1: Clone repository and create CodeQL database.

    Returns:
        (success, has_codeql_db) — success indicates repo is available,
        has_codeql_db indicates whether a CodeQL database was created.
    """
    print_header("Stage 1: Clone Repository & Create CodeQL Database")

    if skip:
        print(f"[SKIP] Skipping clone for {REPO_NAME}")
        db_path = Path(f"output/{LANGUAGE}/{REPO_NAME}/database/codeql-database.yml")
        return True, db_path.exists()

    print(f"Repository: {REPO_NAME} (OWASP Java training application)")
    print(f"Language: {LANGUAGE}")
    print("Build: Maven/Gradle autobuild (project-dependent)")
    print()
    print("Note: Ensure this repo exists in config/repos.yaml.")
    print()

    success, error = run_command(
        _CLI + ["clone", "--repo", REPO_NAME],
        dry_run,
    )

    if success:
        print("\n[OK] Repository cloned and database created")
        return True, True

    # Fallback: clone without DB creation (CodeQL extractor may be missing)
    print("\n[WARN] Clone with DB failed, retrying clone-only (--skip-db)...")
    success, error = run_command(
        _CLI + ["clone", "--repo", REPO_NAME, "--skip-db"],
        dry_run,
    )

    if success:
        print("\n[OK] Repository cloned (no CodeQL database)")
        return True, False

    print(f"\n[FAIL] Clone failed: {error}")
    return False, False


def stage_analyze(dry_run: bool = False, has_codeql_db: bool = True) -> bool:
    """Stage 2: Run security analysis (CodeQL with Semgrep fallback)."""
    print_header("Stage 2: Run Security Analysis")

    print("Running Java security-extended query suite...")
    print("This includes checks for:")
    print("  - SQL injection")
    print("  - Command injection")
    print("  - Path traversal")
    print("  - Unsafe deserialization")
    print("  - XXE (XML External Entity)")
    print("  - Authentication and authorization issues")
    print()

    if has_codeql_db:
        print("Trying CodeQL analysis...")
        print()
        success, error = run_command(
            _CLI + ["analyze", "--repo", REPO_NAME, "-v"],
            dry_run,
        )
        if success:
            print("\n[OK] CodeQL analysis complete")
            return True
        print(f"\n[WARN] CodeQL analysis failed: {error}")

    # Fallback to Semgrep
    print("\nFalling back to Semgrep analysis...")
    print()
    success, error = run_command(
        _CLI + ["analyze", "--tool", "semgrep", "--repo", REPO_NAME, "-v"],
        dry_run,
    )

    if success:
        print("\n[OK] Semgrep analysis complete")
    else:
        print(f"\n[FAIL] Analysis failed: {error}")

    return success


def stage_extract_context(dry_run: bool = False, has_codeql_db: bool = True) -> bool:
    """Stage 3: Extract context CSVs (CodeQL or tree-sitter fallback)."""
    print_header("Stage 3: Extract Context CSVs")

    print("Extracting Java-specific context:")
    print("  - functions.csv: Method and function definitions")
    print("  - callers.csv: Call relationships")
    print("  - classes.csv: Class definitions and hierarchy")
    print()

    if has_codeql_db:
        success, error = run_command(
            _CLI + ["extract-context", "--repo", REPO_NAME],
            dry_run,
        )
        if success:
            print("\n[OK] Context extracted")
            return True
        print(f"\n[WARN] CodeQL extraction failed: {error}")

    # Fallback to tree-sitter
    print("\nFalling back to tree-sitter extraction...")
    success, error = run_command(
        _CLI + ["extract-context", "--repo", REPO_NAME, "--backend", "treesitter"],
        dry_run,
    )

    if success:
        print("\n[OK] Context extracted (tree-sitter)")
    else:
        print(f"\n[FAIL] Extraction failed: {error}")

    return success


def stage_verify(dry_run: bool = False) -> bool:
    """Stage 4: Verify findings with LLM (LLM mode)."""
    print_header("Stage 4: LLM Bug Verification (LLM mode)")

    print("LLM mode: multi-turn with context expansion")
    print(f"Max findings: {MAX_FINDINGS}")
    print(f"Max iterations per finding: {MAX_ITERATIONS}")
    print()

    cmd = _CLI + [
        "verify",
        "--repo", REPO_NAME,
        "--limit", str(MAX_FINDINGS),
        "--max-iterations", str(MAX_ITERATIONS),
        "-v",
    ]

    success, error = run_command(cmd, dry_run)

    if success:
        print("\n[OK] Verification complete")
    else:
        print(f"\n[FAIL] Verification failed: {error}")

    return success


def run_with_api() -> None:
    """Run pipeline using Python API instead of CLI."""
    print_header("Running Pipeline with Python API")

    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

    from vuln_hunter_x import VerificationEngine
    from vuln_hunter_x.core.types import Finding, Verdict

    engine = VerificationEngine.from_config(
        Path("config/confirm_findings.yaml"),
        limit=MAX_FINDINGS,
    )

    print("Engine created (LLM mode)")
    print(f"Model: {engine.config.llm.model}")
    print()

    def on_start(i: int, total: int, finding: Finding) -> None:
        print(f"[{i}/{total}] Analyzing: {finding.rule_id}")
        print(f"         Location: {finding.location}")

    def on_complete(i: int, total: int, verdict: Verdict) -> None:
        print(f"         Verdict: {verdict.verdict} ({verdict.confidence})")
        if verdict.iterations > 1:
            print(f"         Iterations: {verdict.iterations}")

    engine.on_finding_start(on_start)
    engine.on_finding_complete(on_complete)

    sarif_path = Path(f"output/{LANGUAGE}/{REPO_NAME}/{REPO_NAME}.sarif")
    if not sarif_path.exists():
        print(f"[ERROR] SARIF file not found: {sarif_path}")
        print("Run the analysis stage first.")
        return

    print("Starting verification...")
    print()

    result = engine.verify_sarif(sarif_path, lang=LANGUAGE, repo_name=REPO_NAME)

    print_header("API Results Summary")
    print(f"Total findings: {result.total_findings}")
    print(f"True positives: {result.true_positive_count}")
    print(f"False positives: {result.false_positive_count}")
    print(f"Needs more data: {result.stats.get('Needs More Data', 0)}")
    print(f"Total time: {result.total_time_seconds:.1f}s")

    summary_path, _ = engine.save_results(result)
    print(f"\nResults saved to: {summary_path}")


def print_summary(results: dict[str, bool], elapsed: float) -> None:
    """Print pipeline summary."""
    print_header("Pipeline Summary")

    print(f"Repository: {REPO_NAME} ({LANGUAGE})")
    print(f"Total time: {elapsed:.1f} seconds")
    print()
    print("Stage Results:")

    for stage, success in results.items():
        status = "[OK]" if success else "[FAIL]"
        print(f"  {status} {stage}")

    all_success = all(results.values())
    print()
    if all_success:
        print("Pipeline completed successfully!")
        print()
        print("Output files:")
        print(f"  - SARIF: output/{LANGUAGE}/{REPO_NAME}/{REPO_NAME}.sarif")
        print(f"  - Results: output/{LANGUAGE}/{REPO_NAME}/verification_results/")
        print(f"  - Context: output/{LANGUAGE}/{REPO_NAME}/context/")


# =============================================================================
# Main
# =============================================================================


def main() -> None:
    """Run the full pipeline."""
    dry_run = "--dry-run" in sys.argv
    skip_clone = "--skip-clone" in sys.argv
    use_api = "--api" in sys.argv

    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║         CodeQL + LLM Bug Verification Pipeline                       ║
║         Java Repository: {REPO_NAME:<44}║
╚══════════════════════════════════════════════════════════════════════╝
""")

    if use_api:
        run_with_api()
        return

    if dry_run:
        print("[DRY-RUN MODE] Commands will be printed but not executed.\n")

    start_time = time.time()
    results: dict[str, bool] = {}

    clone_ok, has_codeql_db = stage_clone(dry_run, skip_clone)
    results["Clone & Create DB"] = clone_ok

    if clone_ok or skip_clone:
        results["Security Analysis"] = stage_analyze(dry_run, has_codeql_db)
    else:
        results["Security Analysis"] = False

    if results["Security Analysis"] or clone_ok:
        results["Extract Context"] = stage_extract_context(dry_run, has_codeql_db)
    else:
        results["Extract Context"] = False

    if results["Security Analysis"]:
        results["LLM Verification"] = stage_verify(dry_run)
    else:
        results["LLM Verification"] = False

    elapsed = time.time() - start_time
    print_summary(results, elapsed)

    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
