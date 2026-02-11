"""
Stage 8: Run libFuzzer for compiled harnesses, collect crashes and summary.

Sub-stages 8.1–8.3: ensure binaries exist, run with timeout/ASAN_OPTIONS, summarize.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from pathlib import Path


def run_fuzzer(
    binary_path: Path,
    run_dir: Path,
    timeout_sec: int = 60,
    max_total_time: int = 30,
    artifact_prefix: str = "crash-",
) -> tuple[bool, list[Path], str, float]:
    """
    Run one fuzz binary with libFuzzer options (8.2).

    Args:
        binary_path: Path to the fuzz binary.
        run_dir: Working directory (crashes written here).
        timeout_sec: Subprocess timeout (should be > max_total_time).
        max_total_time: libFuzzer -max_total_time=N (seconds).
        artifact_prefix: libFuzzer -artifact_prefix= for crash files.

    Returns:
        (crashed, crash_files, combined_log, elapsed_seconds)
    """
    binary_path = Path(binary_path)
    run_dir = Path(run_dir)
    run_dir.mkdir(parents=True, exist_ok=True)

    env = os.environ.copy()
    env["ASAN_OPTIONS"] = env.get("ASAN_OPTIONS", "") or "abort_on_error=1:detect_leaks=0"
    cmd = [
        str(binary_path),
        f"-max_total_time={max_total_time}",
        f"-artifact_prefix={artifact_prefix}",
    ]
    start = time.perf_counter()
    try:
        r = subprocess.run(
            cmd,
            cwd=run_dir,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            env=env,
        )
        elapsed = time.perf_counter() - start
        log = (r.stdout or "") + "\n" + (r.stderr or "")
        # libFuzzer exits 77 on crash (or other non-zero)
        crashed = r.returncode != 0
        crash_files = sorted(run_dir.glob(f"{artifact_prefix}*")) if crashed else []
        return crashed, crash_files, log.strip(), elapsed
    except subprocess.TimeoutExpired:
        elapsed = time.perf_counter() - start
        return False, [], "Fuzzer timed out", elapsed
    except Exception as e:
        elapsed = time.perf_counter() - start
        return False, [], str(e), elapsed


def run_fuzzers_for_repo(
    repo_name: str,
    fuzz_targets_dir: Path,
    fuzz_results_dir: Path,
    timeout_per_harness: int = 60,
    max_total_time: int = 30,
    dry_run: bool = False,
) -> tuple[list[dict], Path]:
    """
    Run all compiled harnesses for a repo (8.1–8.3).

    Loads status.json; for each harness with status "compiled", runs the binary,
    collects crashes, writes summary.json and crash artifacts under fuzz_results_dir/repo_name/.

    Returns:
        (list of result dicts, summary_path)
    """
    targets_dir = Path(fuzz_targets_dir) / repo_name
    results_dir = Path(fuzz_results_dir) / repo_name
    status_path = targets_dir / "status.json"
    if not status_path.is_file():
        return [], results_dir / "summary.json"

    try:
        data = json.loads(status_path.read_text())
    except Exception:
        return [], results_dir / "summary.json"

    harnesses = data.get("harnesses") or []
    results: list[dict] = []
    for h in harnesses:
        if h.get("status") != "compiled":
            results.append({
                "harness": h.get("harness", ""),
                "status": h.get("status", "unknown"),
                "crashed": False,
                "crash_count": 0,
                "crash_files": [],
                "time_sec": 0,
                "log_snippet": "",
            })
            continue
        name = h.get("harness", "")
        stem = Path(name).stem if name else ""
        binary = targets_dir / stem  # no extension
        if not binary.is_file():
            results.append({
                "harness": name,
                "status": "binary_missing",
                "crashed": False,
                "crash_count": 0,
                "crash_files": [],
                "time_sec": 0,
                "log_snippet": "Binary not found",
            })
            continue
        run_dir = results_dir / stem
        if dry_run:
            results.append({
                "harness": name,
                "status": "compiled",
                "crashed": False,
                "crash_count": 0,
                "crash_files": [],
                "time_sec": 0,
                "log_snippet": "[dry-run] would run fuzzer",
            })
            continue
        crashed, crash_files, log, elapsed = run_fuzzer(
            binary, run_dir,
            timeout_sec=timeout_per_harness,
            max_total_time=max_total_time,
        )
        results.append({
            "harness": name,
            "status": "compiled",
            "crashed": crashed,
            "crash_count": len(crash_files),
            "crash_files": [str(p) for p in crash_files],
            "time_sec": round(elapsed, 2),
            "log_snippet": log[-2000:] if log else "",
        })

    results_dir.mkdir(parents=True, exist_ok=True)
    summary_path = results_dir / "summary.json"
    summary = {
        "repo": repo_name,
        "harnesses": results,
        "crashes_total": sum(r.get("crash_count", 0) for r in results),
    }
    if not dry_run:
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return results, summary_path


def run_all_fuzzers(
    fuzz_targets_dir: Path,
    fuzz_results_dir: Path,
    repo_filter: str | None = None,
    timeout_per_harness: int = 60,
    max_total_time: int = 30,
    dry_run: bool = False,
) -> list[tuple[str, list[dict], Path]]:
    """
    Run fuzzers for all repos that have status.json with at least one "compiled" harness.

    Returns:
        List of (repo_name, results, summary_path)
    """
    targets_dir = Path(fuzz_targets_dir)
    if not targets_dir.is_dir():
        return []
    out: list[tuple[str, list[dict], Path]] = []
    for repo_dir in targets_dir.iterdir():
        if not repo_dir.is_dir():
            continue
        repo_name = repo_dir.name
        if repo_filter and repo_name.lower() != repo_filter.lower():
            continue
        status_path = repo_dir / "status.json"
        if not status_path.is_file():
            continue
        results, summary_path = run_fuzzers_for_repo(
            repo_name,
            fuzz_targets_dir=fuzz_targets_dir,
            fuzz_results_dir=fuzz_results_dir,
            timeout_per_harness=timeout_per_harness,
            max_total_time=max_total_time,
            dry_run=dry_run,
        )
        out.append((repo_name, results, summary_path))
    return out
