#!/usr/bin/env python3
"""
Full Pipeline Example: C Repository (libucl)

This script demonstrates the complete CodeQL + LLM verification pipeline
for a C repository, covering all stages from cloning to LLM verification.

Usage:
    python examples/pipeline_c.py              # Run full pipeline
    python examples/pipeline_c.py --dry-run    # Preview without executing
    python examples/pipeline_c.py --skip-clone # Skip clone if already exists
    python examples/pipeline_c.py --simple     # Use simple mode (faster)
    python examples/pipeline_c.py --compare    # Compare simple vs vulnhalla
    python examples/pipeline_c.py --api        # Use Python API instead of CLI
    python examples/pipeline_c.py --fuzz       # Include fuzz stages 5-8 (confirm findings)
"""

import subprocess
import sys
import time
from pathlib import Path

# =============================================================================
# Configuration
# =============================================================================

REPO_NAME = "c-ares"
LANGUAGE = "c"
MAX_FINDINGS = 10  # Limit findings to process for demo

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
    
    print(f"Repository: {REPO_NAME}")
    print(f"Language: {LANGUAGE}")
    print(f"Build: CMake-based build system")
    print()
    
    success, error = run_command([
        "codeql-llm", "clone",
        "--repo", REPO_NAME,
    ], dry_run)
    
    if success:
        print(f"\n[OK] Repository cloned and database created")
    else:
        print(f"\n[FAIL] Clone failed: {error}")
    
    return success


def stage_analyze(dry_run: bool = False) -> bool:
    """Stage 2: Run CodeQL security analysis."""
    print_header("Stage 2: Run CodeQL Security Analysis")
    
    print(f"Running C security-extended query suite...")
    print("This includes checks for:")
    print("  - Buffer overflows")
    print("  - Use-after-free")
    print("  - Integer overflows")
    print("  - Memory leaks")
    print("  - Format string vulnerabilities")
    print()
    
    success, error = run_command([
        "codeql-llm", "analyze",
        "--repo", REPO_NAME,
        "-v",  # Verbose output
    ], dry_run)
    
    if success:
        print(f"\n[OK] Analysis complete - SARIF file generated")
    else:
        print(f"\n[FAIL] Analysis failed: {error}")
    
    return success


def stage_extract_context(dry_run: bool = False) -> bool:
    """Stage 3: Extract context CSVs for multi-turn verification."""
    print_header("Stage 3: Extract Context CSVs")
    
    print("Extracting structured context for Vulnhalla mode:")
    print("  - functions.csv: Function definitions")
    print("  - callers.csv: Caller-callee relationships")
    print("  - structs.csv: Structure definitions")
    print("  - globals.csv: Global variables")
    print("  - macros.csv: Macro definitions")
    print()
    
    success, error = run_command([
        "codeql-llm", "extract-context",
        "--repo", REPO_NAME,
    ], dry_run)
    
    if success:
        print(f"\n[OK] Context CSVs extracted to output/context/{REPO_NAME}/")
    else:
        print(f"\n[FAIL] Context extraction failed: {error}")
    
    return success


def stage_verify(dry_run: bool = False, mode: str = "vulnhalla") -> bool:
    """Stage 4: Verify findings with LLM."""
    print_header(f"Stage 4: LLM Bug Verification ({mode} mode)")
    
    print(f"Mode: {mode}")
    if mode == "vulnhalla":
        print("  - Multi-turn conversation with context expansion")
        print("  - LLM can request callers, structs, globals, macros")
        print("  - Higher accuracy for complex data-flow issues")
    else:
        print("  - Single-shot analysis (faster)")
        print("  - No context expansion")
    print(f"Max findings: {MAX_FINDINGS}")
    print()
    
    cmd = [
        "codeql-llm", "verify",
        "--repo", REPO_NAME,
        "--mode", mode,
        "--limit", str(MAX_FINDINGS),
    ]
    
    if mode == "vulnhalla":
        cmd.extend(["--max-iterations", "10", "-v"])
    
    success, error = run_command(cmd, dry_run)
    
    if success:
        print(f"\n[OK] Verification complete - results saved to output/results/")
    else:
        print(f"\n[FAIL] Verification failed: {error}")
    
    return success


def stage_build_sanitized(dry_run: bool = False) -> bool:
    """Stage 5 (fuzz): Build repo with sanitizers for fuzz harness linking."""
    print_header("Stage 5: Build with Sanitizers")
    print("Building with ASan/UBSan for fuzz harness linking...")
    print()
    success, error = run_command(
        ["codeql-llm", "build-sanitized", "--repo", REPO_NAME],
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
        ["codeql-llm", "extract-fuzz-context", "--repo", REPO_NAME],
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
        ["codeql-llm", "generate-fuzz-drivers", "--repo", REPO_NAME, "--verdict", "tp,nmd", "--build"],
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
        [
            "codeql-llm", "fuzz-run",
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


def compare_modes(dry_run: bool = False) -> None:
    """Compare simple vs vulnhalla verification modes."""
    print_header("Mode Comparison: Simple vs Vulnhalla")
    
    print("This will run verification twice with different modes")
    print("to demonstrate the difference in accuracy and time.\n")
    
    # Simple mode
    print("=" * 50)
    print("Running SIMPLE mode (single-shot)...")
    print("=" * 50)
    start_simple = time.time()
    stage_verify(dry_run, mode="simple")
    time_simple = time.time() - start_simple
    
    print()
    
    # Vulnhalla mode
    print("=" * 50)
    print("Running VULNHALLA mode (multi-turn)...")
    print("=" * 50)
    start_vuln = time.time()
    stage_verify(dry_run, mode="vulnhalla")
    time_vuln = time.time() - start_vuln
    
    # Summary
    print_header("Mode Comparison Summary")
    print(f"Simple mode time:    {time_simple:.1f}s")
    print(f"Vulnhalla mode time: {time_vuln:.1f}s")
    print(f"Time difference:     {time_vuln - time_simple:.1f}s")
    print()
    print("Review the output above to compare:")
    print("  - Verdict accuracy")
    print("  - Confidence levels")
    print("  - Reasoning depth")
    print("  - Context requested (vulnhalla only)")


def run_with_api(mode: str = "vulnhalla") -> None:
    """Run pipeline using Python API instead of CLI."""
    print_header("Running Pipeline with Python API")
    
    # Add src to path for development
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    
    from codeql_llm import VerificationEngine
    from codeql_llm.core.types import Finding, Verdict
    
    # Create engine
    engine = VerificationEngine.from_config(
        Path("config/confirm_findings.yaml"),
        mode=mode,
        limit=MAX_FINDINGS,
    )
    
    print(f"Engine created with mode: {engine.config.verification.mode}")
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
    sarif_path = Path(f"output/sarif/{LANGUAGE}/{REPO_NAME}.sarif")
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
        print("Next steps:")
        print(f"  - View SARIF: output/sarif/{LANGUAGE}/{REPO_NAME}.sarif")
        print("  - View results: output/results/")
        print(f"  - View context: output/context/{REPO_NAME}/")
        if run_fuzz:
            print(f"  - View fuzz targets: output/fuzz_targets/{REPO_NAME}/")
            print(f"  - View fuzz results: output/fuzz_results/{REPO_NAME}/")
    else:
        print("Pipeline completed with errors. Check the logs above.")


# =============================================================================
# Main
# =============================================================================

def main():
    """Run the full pipeline."""
    # Parse arguments
    dry_run = "--dry-run" in sys.argv
    skip_clone = "--skip-clone" in sys.argv
    simple_mode = "--simple" in sys.argv
    compare = "--compare" in sys.argv
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
║         C Repository: {REPO_NAME:<46}║
╚══════════════════════════════════════════════════════════════════════╝
""")
    
    # API mode runs only verification
    if use_api:
        mode = "simple" if simple_mode else "vulnhalla"
        run_with_api(mode)
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
    
    # Stage 3: Extract Context (skip if simple mode)
    if results["CodeQL Analysis"] and not simple_mode:
        results["Extract Context"] = stage_extract_context(dry_run)
    elif simple_mode:
        print("\n[SKIP] Skipping context extraction (simple mode)\n")
        results["Extract Context"] = True
    else:
        results["Extract Context"] = False
    
    # Stage 4: Verify (or compare modes)
    if results["CodeQL Analysis"]:
        if compare:
            compare_modes(dry_run)
            results["LLM Verification"] = True
        else:
            mode = "simple" if simple_mode else "vulnhalla"
            results["LLM Verification"] = stage_verify(dry_run, mode)
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
    
    # Exit with appropriate code
    sys.exit(0 if all(results.values()) else 1)


if __name__ == "__main__":
    main()
