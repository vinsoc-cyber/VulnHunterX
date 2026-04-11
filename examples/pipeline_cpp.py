#!/usr/bin/env python3
"""
Pipeline Example: C++

Runs the full pipeline on two repos to demonstrate the contrast:
  - re2                       (real-world regex library) → expect mostly False Positives
  - insecure-coding-examples  (intentionally vulnerable)  → expect True Positives

Note: C++ requires CMake and a C++ compiler for CodeQL database creation.

Usage:
    python examples/pipeline_cpp.py              # Run full pipeline
    python examples/pipeline_cpp.py --dry-run    # Preview without executing
    python examples/pipeline_cpp.py --skip-clone # Skip clone if already exists
    python examples/pipeline_cpp.py --api        # Use Python API instead of CLI
    python examples/pipeline_cpp.py --fuzz       # Include fuzz stages 5-8
"""

import subprocess
import sys
import time
from pathlib import Path

LANGUAGE = "cpp"
REPOS = [
    {"name": "re2",                      "label": "real-world regex library  "},
    {"name": "insecure-coding-examples", "label": "intentionally vulnerable  "},
]
MAX_FINDINGS = 5
MAX_ITERATIONS = 5

_CLI = [sys.executable, "-m", "vuln_hunter_x.cli.main"]


def print_header(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f"  {title}")
    print(f"{'=' * 70}\n")


def run_command(cmd: list[str], dry_run: bool = False, timeout: int = 1800) -> bool:
    if dry_run:
        print(f"[DRY-RUN] {' '.join(cmd)}")
        return True
    print(f"$ {' '.join(cmd)}")
    print("-" * 50)
    try:
        r = subprocess.run(cmd, text=True, timeout=timeout)
        return r.returncode == 0
    except subprocess.TimeoutExpired:
        print("[FAIL] Timed out")
        return False
    except Exception as e:
        print(f"[FAIL] {e}")
        return False


def run_pipeline(repo: str, dry_run: bool, skip_clone: bool) -> dict[str, bool]:
    results: dict[str, bool] = {}

    print_header(f"[{repo}] Stage 1: Prepare (clone + CodeQL DB)")
    if skip_clone:
        db_ok = Path(f"output/{LANGUAGE}/{repo}/database/codeql-database.yml").exists()
        results["prepare"] = True
    else:
        ok = run_command(_CLI + ["prepare", "--repo", repo], dry_run)
        if not ok:
            ok = run_command(_CLI + ["prepare", "--repo", repo, "--skip-db"], dry_run)
        results["prepare"] = ok
        db_ok = ok

    print_header(f"[{repo}] Stage 2: Analyze")
    ok = False
    if db_ok:
        ok = run_command(_CLI + ["analyze", "--repo", repo, "-v"], dry_run)
    if not ok:
        ok = run_command(_CLI + ["analyze", "--tool", "semgrep", "--repo", repo], dry_run)
    results["analyze"] = ok

    print_header(f"[{repo}] Stage 3: Extract Context")
    ok = run_command(_CLI + ["extract-context", "--repo", repo], dry_run)
    if not ok:
        ok = run_command(
            _CLI + ["extract-context", "--repo", repo, "--backend", "treesitter"], dry_run
        )
    results["extract-context"] = ok

    print_header(f"[{repo}] Stage 4: Verify")
    if results["analyze"]:
        results["verify"] = run_command(
            _CLI + ["verify", "--repo", repo,
                    "--limit", str(MAX_FINDINGS),
                    "--max-iterations", str(MAX_ITERATIONS),
                    "--report", "-v"],
            dry_run,
        )
    else:
        results["verify"] = False

    return results


def run_fuzz(repo: str, dry_run: bool) -> dict[str, bool]:
    """Stages 5-8: fuzz confirmation."""
    results: dict[str, bool] = {}
    print_header(f"[{repo}] Stage 5: Build Sanitized")
    results["build-sanitized"] = run_command(
        _CLI + ["build-sanitized", "--repo", repo], dry_run
    )
    print_header(f"[{repo}] Stage 6: Extract Fuzz Context")
    results["extract-fuzz-context"] = run_command(
        _CLI + ["extract-fuzz-context", "--repo", repo], dry_run
    )
    print_header(f"[{repo}] Stage 7: Generate Fuzz Drivers")
    results["generate-fuzz-drivers"] = run_command(
        _CLI + ["generate-fuzz-drivers", "--repo", repo, "--build", "--llm-fix"], dry_run
    )
    print_header(f"[{repo}] Stage 8: Fuzz Run")
    results["fuzz-run"] = run_command(
        _CLI + ["fuzz-run", "--repo", repo, "--triage"], dry_run
    )
    return results


def run_with_api(repo: str) -> None:
    print_header(f"Python API — {repo}")
    sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
    from vuln_hunter_x import VerificationEngine

    engine = VerificationEngine.from_config(Path("config/confirm_findings.yaml"))
    sarif = Path(f"output/{LANGUAGE}/{repo}/{repo}.sarif")
    if not sarif.exists():
        print(f"[ERROR] SARIF not found: {sarif} — run analysis first.")
        return
    result = engine.verify_sarif(sarif, lang=LANGUAGE, repo_name=repo)
    print(f"Total: {result.total_findings}  TP: {result.true_positive_count}  FP: {result.false_positive_count}")
    engine.save_results(result)


def main() -> None:
    dry_run = "--dry-run" in sys.argv
    skip_clone = "--skip-clone" in sys.argv
    use_api = "--api" in sys.argv
    do_fuzz = "--fuzz" in sys.argv

    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  VulnHunterX — C++ Pipeline                                          ║
║  normal:     re2                      (Google regex library)         ║
║  vulnerable: insecure-coding-examples (buffer overflows, fmt strings)║
╚══════════════════════════════════════════════════════════════════════╝
""")

    if use_api:
        for r in REPOS:
            run_with_api(r["name"])
        return

    start = time.time()
    all_results: dict[str, dict[str, bool]] = {}

    for repo_cfg in REPOS:
        repo = repo_cfg["name"]
        all_results[repo] = run_pipeline(repo, dry_run, skip_clone)
        if do_fuzz:
            all_results[repo].update(run_fuzz(repo, dry_run))

    print_header("Pipeline Summary")
    for repo_cfg in REPOS:
        repo = repo_cfg["name"]
        label = repo_cfg["label"]
        res = all_results[repo]
        ok_stages = sum(v for v in res.values())
        print(f"  {repo} ({label.strip()})  {ok_stages}/{len(res)} stages OK")
        for stage, ok in res.items():
            print(f"    {'[OK]  ' if ok else '[FAIL]'} {stage}")
        print(f"    Output: output/{LANGUAGE}/{repo}/verification_results/")

    print(f"\nTotal time: {time.time() - start:.1f}s")


if __name__ == "__main__":
    main()
