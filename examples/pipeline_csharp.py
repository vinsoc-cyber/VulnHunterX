#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""
Pipeline Example: C# / .NET

Runs the full pipeline on two repos to demonstrate the contrast:
  - newtonsoft-json  (real-world .NET library)        → expect mostly False Positives
  - webgoat-net      (intentionally vulnerable app)   → expect True Positives

C# is compiled, but CodeQL database creation uses **buildless extraction**
(`--build-mode none`) by default — no `dotnet build` / SDK setup required. To
get full call-graph fidelity, add a `build_command` (e.g. "dotnet build") to
the repo entry in config/repos.yaml.

Usage:
    python examples/pipeline_csharp.py              # Run full pipeline
    python examples/pipeline_csharp.py --dry-run    # Preview without executing
    python examples/pipeline_csharp.py --skip-clone # Skip clone if already exists
    python examples/pipeline_csharp.py --scan       # Use the one-shot `scan` command
    python examples/pipeline_csharp.py --api        # Use Python API instead of CLI
"""

import subprocess
import sys
import time
from pathlib import Path

LANGUAGE = "csharp"
REPOS = [
    {"name": "newtonsoft-json", "label": "real-world .NET library  "},
    {"name": "webgoat-net",     "label": "intentionally vulnerable "},
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

    print_header(f"[{repo}] Stage 1: Prepare (clone + buildless CodeQL DB)")
    if skip_clone:
        results["prepare"] = True
        db_ok = Path(f"output/{LANGUAGE}/{repo}/database/codeql-database.yml").exists()
    else:
        ok = run_command(_CLI + ["prepare", "--repo", repo], dry_run)
        if not ok:
            ok = run_command(_CLI + ["prepare", "--repo", repo, "--skip-db"], dry_run)
        results["prepare"] = ok
        db_ok = ok

    print_header(f"[{repo}] Stage 2: Analyze (CodeQL + Semgrep custom C# rules)")
    ok = False
    if db_ok:
        ok = run_command(_CLI + ["analyze", "--repo", repo, "--tool", "both", "--profile", "full", "-v"], dry_run)
    if not ok:
        ok = run_command(_CLI + ["analyze", "--tool", "semgrep", "--repo", repo, "--profile", "full"], dry_run)
    results["analyze"] = ok

    # Stage 3: verify (context CSVs extracted automatically in prepare)
    print_header(f"[{repo}] Stage 3: Verify")
    if results["analyze"]:
        results["verify"] = run_command(
            _CLI + ["verify", "--repo", repo,
                    "--limit", str(MAX_FINDINGS),
                    "--max-iterations", str(MAX_ITERATIONS),
                    "-v"],
            dry_run,
        )
    else:
        results["verify"] = False

    print_header(f"[{repo}] Stage 4: Report")
    if results["verify"]:
        results["report"] = run_command(
            _CLI + ["report", "--repo", repo, "--lang", LANGUAGE], dry_run
        )
    else:
        results["report"] = False

    return results


def run_with_scan(repo: str, dry_run: bool) -> dict[str, bool]:
    """Demonstrate the one-shot `scan` command (prepare → analyze → verify → report)."""
    print_header(f"[{repo}] One-shot scan")
    ok = run_command(
        _CLI + ["scan", "--repo", repo, "--lang", LANGUAGE,
                "--tool", "both", "--profile", "full", "--limit", str(MAX_FINDINGS)]
        + (["--dry-run"] if dry_run else []),
    )
    return {"scan": ok}


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
    use_scan = "--scan" in sys.argv

    print("""
╔══════════════════════════════════════════════════════════════════════╗
║  VulnHunterX — C# / .NET Pipeline                                      ║
║  normal:     newtonsoft-json  (Json.NET serialization library)         ║
║  vulnerable: webgoat-net      (WebGoat.NET training app)               ║
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
        if use_scan:
            all_results[repo] = run_with_scan(repo, dry_run)
        else:
            all_results[repo] = run_pipeline(repo, dry_run, skip_clone)

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
