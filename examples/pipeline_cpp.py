#!/usr/bin/env python3
"""
Full Pipeline Example: C++ Repository (insecure-coding-examples)

This script demonstrates the complete CodeQL + LLM verification pipeline
for a C++ repository with intentional vulnerabilities (Patricia Gallardo's
insecure coding examples - buffer overflows, format strings, etc.).

Usage:
    python examples/pipeline_cpp.py              # Run full pipeline
    python examples/pipeline_cpp.py --dry-run    # Preview without executing
    python examples/pipeline_cpp.py --skip-clone # Skip clone if already exists
    python examples/pipeline_cpp.py --api        # Use Python API instead of CLI
    python examples/pipeline_cpp.py --fuzz       # Include fuzz stages 5-8 (confirm findings)
"""

import subprocess
import sys
import time
from pathlib import Path

# =============================================================================
# Configuration
# =============================================================================

REPO_NAME = "insecure-coding-examples"
LANGUAGE = "cpp"
MAX_FINDINGS = 5  # Limit findings to process for demo

_CLI = [sys.executable, "-m", "vuln_hunter_x.cli.main"]

# =============================================================================
# Pipeline Stages
# =============================================================================


def print_header(title: str) -> None:
    """Print a formatted stage header."""
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def run_command(cmd: list[str], dry_run: bool = False, timeout: int = 1800) -> tuple[bool, str]:
    """
    Run a shell command and return success status.

    Args:
        cmd: Command as list of strings
        dry_run: If True, only print the command
        timeout: Timeout in seconds (default 1800)

    Returns:
        Tuple of (success, output)
    """
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
            timeout=timeout,
        )
        return result.returncode == 0, ""
    except subprocess.TimeoutExpired:
        return False, "Command timed out"
    except Exception as e:
        return False, str(e)


def stage_clone(dry_run: bool = False, skip: bool = False) -> bool:
    """Stage 1: Clone repository and create CodeQL database."""
    print_header("Stage 1: Clone Repository & Create CodeQL Database")
    
    if skip:
        print(f"[SKIP] Skipping clone for {REPO_NAME}")
        return True
    
    print(f"Repository: {REPO_NAME} (Intentionally Vulnerable C++ Examples)")
    print(f"Language: {LANGUAGE}")
    print(f"Build: CMake-based build system")
    print()
    
    success, error = run_command(
        _CLI + ["clone", "--repo", REPO_NAME],
        dry_run,
    )
    
    if success:
        print(f"\n[OK] Repository cloned and database created")
    else:
        print(f"\n[FAIL] Clone failed: {error}")
        print("\nNote: C++ builds may fail due to missing dependencies.")
        print("Try: sudo apt-get install cmake build-essential")
    
    return success


def stage_analyze(dry_run: bool = False) -> bool:
    """Stage 2: Run CodeQL security analysis."""
    print_header("Stage 2: Run CodeQL Security Analysis")
    
    print(f"Running C++ security-extended query suite...")
    print("This includes checks for:")
    print("  - Buffer overflows")
    print("  - Use-after-free")
    print("  - Integer overflows")
    print("  - Memory leaks")
    print("  - Format string vulnerabilities")
    print()
    
    success, error = run_command(
        _CLI + ["analyze", "--repo", REPO_NAME, "-v"],
        dry_run,
    )
    
    if success:
        print(f"\n[OK] Analysis complete")
    else:
        print(f"\n[FAIL] Analysis failed: {error}")
    
    return success


def stage_extract_context(dry_run: bool = False) -> bool:
    """Stage 3: Extract context CSVs for multi-turn verification."""
    print_header("Stage 3: Extract Context CSVs")
    
    print("Extracting C++ specific context:")
    print("  - functions.csv: Function definitions with signatures")
    print("  - callers.csv: Call graph relationships")
    print("  - structs.csv: Class and struct definitions")
    print("  - globals.csv: Global and static variables")
    print("  - macros.csv: Preprocessor macro definitions")
    print()
    
    success, error = run_command(
        _CLI + ["extract-context", "--repo", REPO_NAME],
        dry_run,
    )
    
    if success:
        print(f"\n[OK] Context extracted")
    else:
        print(f"\n[FAIL] Extraction failed: {error}")
    
    return success


def stage_verify(dry_run: bool = False) -> bool:
    """Stage 4: Verify findings with LLM (LLM mode)."""
    print_header("Stage 4: LLM Bug Verification (LLM mode)")
    
    print("LLM mode: multi-turn with context expansion")
    print(f"Max findings: {MAX_FINDINGS}")
    print()
    
    cmd = _CLI + [
        "verify",
        "--repo", REPO_NAME,
        "--limit", str(MAX_FINDINGS),
        "--max-iterations", "5",
        "-v",
    ]
    
    success, error = run_command(cmd, dry_run)
    
    if success:
        print(f"\n[OK] Verification complete")
    else:
        print(f"\n[FAIL] Verification failed: {error}")
    
    return success


def stage_build_sanitized(dry_run: bool = False) -> bool:
    """Stage 5 (fuzz): Build repo with sanitizers for fuzz harness linking."""
    print_header("Stage 5: Build with Sanitizers")
    print("Building with ASan/UBSan for fuzz harness linking...")
    print()
    success, error = run_command(
        _CLI + ["build-sanitized", "--repo", REPO_NAME],
        dry_run,
        timeout=2400,
    )
    if success:
        print(f"\n[OK] Sanitized build done")
    else:
        print(f"\n[FAIL] Build failed: {error}")
    return success


def stage_extract_fuzz_context(dry_run: bool = False) -> bool:
    """Stage 6 (fuzz): Extract fuzz context CSVs (function_signatures, includes)."""
    print_header("Stage 6: Extract Fuzz Context")
    print("Extracting function signatures and includes for harness generation...")
    print()
    success, error = run_command(
        _CLI + ["extract-fuzz-context", "--repo", REPO_NAME],
        dry_run,
    )
    if success:
        print(f"\n[OK] Fuzz context extracted")
    else:
        print(f"\n[FAIL] Extract failed: {error}")
    return success


def stage_generate_fuzz_drivers(dry_run: bool = False) -> bool:
    """Stage 7 (fuzz): Generate fuzz drivers and build."""
    print_header("Stage 7: Generate Fuzz Drivers")
    print("Generating libFuzzer harnesses from verified findings and building...")
    print()
    success, error = run_command(
        _CLI + ["generate-fuzz-drivers", "--repo", REPO_NAME, "--verdict", "tp,nmd", "--build"],
        dry_run,
        timeout=600,
    )
    if success:
        print(f"\n[OK] Fuzz drivers generated and built")
    else:
        print(f"\n[FAIL] Generate/build failed: {error}")
    return success


def stage_fuzz_run(
    dry_run: bool = False,
    timeout: int = 60,
    max_fuzz_time: int = 30,
) -> bool:
    """Stage 8 (fuzz): Run libFuzzer for compiled harnesses, collect crashes."""
    print_header("Stage 8: Run Fuzzers")
    print(f"Running libFuzzer (timeout={timeout}s per harness, max_fuzz_time={max_fuzz_time}s)...")
    print()
    success, error = run_command(
        _CLI + [
            "fuzz-run",
            "--repo", REPO_NAME,
            "--timeout", str(timeout),
            "--max-fuzz-time", str(max_fuzz_time),
        ],
        dry_run,
        timeout=600,
    )
    if success:
        print(f"\n[OK] Fuzz run done")
    else:
        print(f"\n[FAIL] Fuzz run failed: {error}")
    return success


def run_with_api() -> None:
    """Run pipeline using Python API instead of CLI."""
    print_header("Running Pipeline with Python API")
    
    # Add src to path for development
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    
    from vuln_hunter_x import VerificationEngine
    from vuln_hunter_x.core.types import Finding, Verdict
    
    # Create engine
    engine = VerificationEngine.from_config(
        Path("config/confirm_findings.yaml"),
        limit=MAX_FINDINGS,
    )
    
    print(f"Engine created (LLM mode)")
    print(f"Model: {engine.config.llm.model}")
    print()
    
    # Set up progress callbacks
    def on_start(i: int, total: int, finding: Finding):
        print(f"[{i}/{total}] Analyzing: {finding.rule_id}")
        print(f"         Location: {finding.location}")
    
    def on_complete(i: int, total: int, verdict: Verdict):
        print(f"         Verdict: {verdict.verdict} ({verdict.confidence})")
        if verdict.iterations > 1:
            print(f"         Iterations: {verdict.iterations}")
    
    engine.on_finding_start(on_start)
    engine.on_finding_complete(on_complete)
    
    # Find SARIF file
    sarif_path = Path(f"output/{LANGUAGE}/{REPO_NAME}/{REPO_NAME}.sarif")
    if not sarif_path.exists():
        print(f"[ERROR] SARIF file not found: {sarif_path}")
        print("Run the analysis stage first.")
        return
    
    # Verify
    print("Starting verification...")
    print()
    
    result = engine.verify_sarif(sarif_path, lang=LANGUAGE, repo_name=REPO_NAME)
    
    # Print summary
    print_header("API Results Summary")
    print(f"Total findings: {result.total_findings}")
    print(f"True positives: {result.true_positive_count}")
    print(f"False positives: {result.false_positive_count}")
    print(f"Needs more data: {result.stats.get('Needs More Data', 0)}")
    print(f"Total time: {result.total_time_seconds:.1f}s")
    
    # Save results
    summary_path, _ = engine.save_results(result)
    print(f"\nResults saved to: {summary_path}")


def print_summary(results: dict[str, bool], elapsed: float, run_fuzz: bool = False) -> None:
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
        if run_fuzz:
            print(f"  - Fuzz targets: output/{LANGUAGE}/{REPO_NAME}/fuzz_targets/")
            print(f"  - Fuzz results: output/{LANGUAGE}/{REPO_NAME}/fuzz_results/")
    else:
        print("Pipeline completed with errors.")


# =============================================================================
# Main
# =============================================================================

def main():
    """Run the full pipeline."""
    # Parse arguments
    dry_run = "--dry-run" in sys.argv
    skip_clone = "--skip-clone" in sys.argv
    use_api = "--api" in sys.argv
    run_fuzz = "--fuzz" in sys.argv
    fuzz_timeout = 60
    fuzz_max_time = 30
    if "--fuzz-timeout" in sys.argv:
        i = sys.argv.index("--fuzz-timeout")
        if i + 1 < len(sys.argv):
            try:
                fuzz_timeout = int(sys.argv[i + 1])
            except ValueError:
                pass
    if "--fuzz-max-time" in sys.argv:
        i = sys.argv.index("--fuzz-max-time")
        if i + 1 < len(sys.argv):
            try:
                fuzz_max_time = int(sys.argv[i + 1])
            except ValueError:
                pass

    print(f"""
╔══════════════════════════════════════════════════════════════════════╗
║         CodeQL + LLM Bug Verification Pipeline                       ║
║         C++ Repository: {REPO_NAME:<44}║
╚══════════════════════════════════════════════════════════════════════╝
""")
    
    # API mode runs only verification
    if use_api:
        run_with_api()
        return
    
    if dry_run:
        print("[DRY-RUN MODE] Commands will be printed but not executed.\n")
    
    start_time = time.time()
    results: dict[str, bool] = {}
    
    # Stage 1: Clone
    results["Clone & Create DB"] = stage_clone(dry_run, skip_clone)
    
    # Stage 2: Analyze
    if results["Clone & Create DB"] or skip_clone:
        results["CodeQL Analysis"] = stage_analyze(dry_run)
    else:
        results["CodeQL Analysis"] = False
    
    # Stage 3: Extract Context
    if results["CodeQL Analysis"]:
        results["Extract Context"] = stage_extract_context(dry_run)
    else:
        results["Extract Context"] = False
    
    # Stage 4: Verify
    if results["CodeQL Analysis"]:
        results["LLM Verification"] = stage_verify(dry_run)
    else:
        results["LLM Verification"] = False

    # Stages 5-8 (fuzz): optional, run when --fuzz
    if run_fuzz:
        results["Build sanitized"] = stage_build_sanitized(dry_run)
        results["Extract fuzz context"] = stage_extract_fuzz_context(dry_run)
        results["Generate fuzz drivers"] = stage_generate_fuzz_drivers(dry_run)
        results["Fuzz run"] = stage_fuzz_run(dry_run, timeout=fuzz_timeout, max_fuzz_time=fuzz_max_time)

    elapsed = time.time() - start_time
    print_summary(results, elapsed, run_fuzz=run_fuzz)

    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
