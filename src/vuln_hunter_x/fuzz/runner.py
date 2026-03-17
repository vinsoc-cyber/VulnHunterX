"""
Stage 8: Run libFuzzer for compiled harnesses, collect crashes and summary.

Sub-stages 8.1–8.3: ensure binaries exist, run with timeout/ASAN_OPTIONS, summarize.
Supports corpus persistence, crash triage, and parallel execution.
"""

from __future__ import annotations

import json
import logging
import os
import subprocess
import time
from concurrent.futures import ProcessPoolExecutor, as_completed
from pathlib import Path

logger = logging.getLogger(__name__)


def run_fuzzer(
    binary_path: Path,
    run_dir: Path,
    timeout_sec: int = 60,
    max_total_time: int = 30,
    artifact_prefix: str = "crash-",
    corpus_dir: Path | None = None,
    rss_limit_mb: int = 0,
) -> tuple[bool, list[Path], str, float]:
    """
    Run one fuzz binary with libFuzzer options (8.2).

    Args:
        binary_path: Path to the fuzz binary.
        run_dir: Working directory (crashes written here).
        timeout_sec: Subprocess timeout (should be > max_total_time).
        max_total_time: libFuzzer -max_total_time=N (seconds).
        artifact_prefix: libFuzzer -artifact_prefix= for crash files.
        corpus_dir: Optional persistent corpus directory (libFuzzer positional arg).
        rss_limit_mb: Optional RSS memory limit in MB (0 = no limit).

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
    ]
    # Corpus directory as positional argument (libFuzzer convention)
    if corpus_dir:
        corpus_dir = Path(corpus_dir)
        corpus_dir.mkdir(parents=True, exist_ok=True)
        cmd.append(str(corpus_dir))

    cmd.extend([
        f"-max_total_time={max_total_time}",
        f"-artifact_prefix={artifact_prefix}",
    ])
    if rss_limit_mb > 0:
        cmd.append(f"-rss_limit_mb={rss_limit_mb}")

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


def _run_single_harness(
    binary: Path,
    run_dir: Path,
    name: str,
    timeout_per_harness: int,
    max_total_time: int,
    corpus_dir: Path | None,
    rss_limit_mb: int,
    triage: bool,
) -> dict:
    """Run a single harness and optionally triage crashes. Used by parallel executor."""
    crashed, crash_files, log, elapsed = run_fuzzer(
        binary,
        run_dir,
        timeout_sec=timeout_per_harness,
        max_total_time=max_total_time,
        corpus_dir=corpus_dir,
        rss_limit_mb=rss_limit_mb,
    )

    result: dict = {
        "harness": name,
        "status": "compiled",
        "crashed": crashed,
        "crash_count": len(crash_files),
        "crash_files": [str(p) for p in crash_files],
        "time_sec": round(elapsed, 2),
        "log_snippet": log[-2000:] if log else "",
    }

    # Crash triage
    if triage and crashed and crash_files:
        try:
            from vuln_hunter_x.fuzz.crash_triage import triage_and_dedup

            unique_crashes = triage_and_dedup(binary, crash_files)
            result["triaged_crashes"] = [c.to_dict() for c in unique_crashes]
            result["unique_crash_count"] = len(unique_crashes)
        except subprocess.TimeoutExpired as exc:
            logger.warning("Crash triage timed out for harness %s: %s", name, exc)
        except FileNotFoundError as exc:
            logger.warning(
                "Crash triage tool not found while triaging harness %s: %s",
                name,
                exc,
            )
        except Exception:
            # Log a concise error by default, with full traceback only at debug level.
            logger.error("Unexpected error during crash triage for harness %s", name)
            logger.debug("Crash triage failure details for %s", name, exc_info=True)

    return result


def run_fuzzers_for_repo(
    targets_dir: Path,
    results_dir: Path,
    repo_name: str | None = None,
    timeout_per_harness: int = 60,
    max_total_time: int = 30,
    dry_run: bool = False,
    triage: bool = False,
    parallel: int = 1,
    rss_limit_mb: int = 0,
    corpus_base_dir: Path | None = None,
) -> tuple[list[dict], Path]:
    """
    Run all compiled harnesses for a repo (8.1–8.3).

    Args:
        targets_dir: output/<lang>/<repo>/fuzz_targets (contains status.json and .cc).
        results_dir: output/<lang>/<repo>/fuzz_results.
        repo_name: Repository name for summary.
        timeout_per_harness: Subprocess timeout per harness.
        max_total_time: libFuzzer -max_total_time=N.
        dry_run: If True, skip actual execution.
        triage: If True, triage and deduplicate crashes.
        parallel: Number of parallel fuzzer processes.
        rss_limit_mb: RSS memory limit per fuzzer (0 = no limit).
        corpus_base_dir: Base directory for persistent corpus (per-harness subdirs).

    Returns:
        (list of result dicts, summary_path)
    """
    targets_dir = Path(targets_dir)
    results_dir = Path(results_dir)
    repo_name = repo_name or targets_dir.parent.name
    status_path = targets_dir / "status.json"
    if not status_path.is_file():
        return [], results_dir / "summary.json"

    try:
        data = json.loads(status_path.read_text())
    except Exception:
        return [], results_dir / "summary.json"

    harnesses = data.get("harnesses") or []
    results: list[dict] = []
    runnable: list[tuple[Path, Path, str, Path | None]] = []

    for h in harnesses:
        if h.get("status") != "compiled":
            results.append(
                {
                    "harness": h.get("harness", ""),
                    "status": h.get("status", "unknown"),
                    "crashed": False,
                    "crash_count": 0,
                    "crash_files": [],
                    "time_sec": 0,
                    "log_snippet": "",
                }
            )
            continue
        name = h.get("harness", "")
        stem = Path(name).stem if name else ""
        binary = targets_dir / stem  # no extension
        if not binary.is_file():
            results.append(
                {
                    "harness": name,
                    "status": "binary_missing",
                    "crashed": False,
                    "crash_count": 0,
                    "crash_files": [],
                    "time_sec": 0,
                    "log_snippet": "Binary not found",
                }
            )
            continue
        run_dir = results_dir / stem
        if dry_run:
            results.append(
                {
                    "harness": name,
                    "status": "compiled",
                    "crashed": False,
                    "crash_count": 0,
                    "crash_files": [],
                    "time_sec": 0,
                    "log_snippet": "[dry-run] would run fuzzer",
                }
            )
            continue
        corpus = (corpus_base_dir / stem) if corpus_base_dir else None
        runnable.append((binary, run_dir, name, corpus))

    # Execute harnesses (parallel or sequential)
    if runnable:
        effective_parallel = min(parallel, len(runnable))
        if effective_parallel > 1:
            with ProcessPoolExecutor(max_workers=effective_parallel) as pool:
                futures = {
                    pool.submit(
                        _run_single_harness,
                        binary, run_dir, name,
                        timeout_per_harness, max_total_time,
                        corpus, rss_limit_mb, triage,
                    ): name
                    for binary, run_dir, name, corpus in runnable
                }
                for completed, future in enumerate(as_completed(futures), 1):
                    hname = futures[future]
                    try:
                        result = future.result()
                        status = "CRASH" if result.get("crashed") else "ok"
                        logger.info(
                            "[%d/%d] %s: %s (%.1fs)",
                            completed, len(runnable), hname, status,
                            result.get("time_sec", 0),
                        )
                        results.append(result)
                    except Exception as e:
                        logger.error("Harness %s failed: %s", hname, e)
                        results.append({
                            "harness": hname,
                            "status": "error",
                            "crashed": False,
                            "crash_count": 0,
                            "crash_files": [],
                            "time_sec": 0,
                            "log_snippet": str(e),
                        })
        else:
            for i, (binary, run_dir, name, corpus) in enumerate(runnable):
                result = _run_single_harness(
                    binary, run_dir, name,
                    timeout_per_harness, max_total_time,
                    corpus, rss_limit_mb, triage,
                )
                status = "CRASH" if result.get("crashed") else "ok"
                logger.info(
                    "[%d/%d] %s: %s (%.1fs)",
                    i + 1, len(runnable), name, status,
                    result.get("time_sec", 0),
                )
                results.append(result)

    results_dir.mkdir(parents=True, exist_ok=True)
    summary_path = results_dir / "summary.json"
    summary = {
        "repo": repo_name,
        "harnesses": results,
        "crashes_total": sum(r.get("crash_count", 0) for r in results),
        "unique_crashes_total": sum(r.get("unique_crash_count", 0) for r in results),
    }
    if not dry_run:
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return results, summary_path


def run_all_fuzzers(
    output_dir: Path,
    repo_filter: str | None = None,
    timeout_per_harness: int = 60,
    max_total_time: int = 30,
    dry_run: bool = False,
    triage: bool = False,
    parallel: int = 1,
    rss_limit_mb: int = 0,
    use_corpus: bool = False,
) -> list[tuple[str, list[dict], Path]]:
    """
    Run fuzzers for all repos under output_dir/<lang>/<repo>/fuzz_targets that have status.json.

    Args:
        output_dir: Base output directory.
        repo_filter: Optional filter for specific repo.
        timeout_per_harness: Subprocess timeout per harness.
        max_total_time: libFuzzer max_total_time.
        dry_run: If True, skip execution.
        triage: If True, triage crashes with stack trace extraction and dedup.
        parallel: Number of parallel fuzzer processes.
        rss_limit_mb: RSS memory limit per fuzzer.
        use_corpus: If True, create persistent corpus directories.

    Returns:
        List of (repo_name, results, summary_path)
    """
    output_dir = Path(output_dir)
    if not output_dir.is_dir():
        return []
    out: list[tuple[str, list[dict], Path]] = []
    for lang_dir in output_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        for repo_dir in lang_dir.iterdir():
            if not repo_dir.is_dir():
                continue
            repo_name = repo_dir.name
            if repo_filter and repo_name.lower() != repo_filter.lower():
                continue
            targets_dir = repo_dir / "fuzz_targets"
            results_dir = repo_dir / "fuzz_results"
            status_path = targets_dir / "status.json"
            if not status_path.is_file():
                continue
            corpus_base = (repo_dir / "fuzz_corpus") if use_corpus else None
            results, summary_path = run_fuzzers_for_repo(
                targets_dir=targets_dir,
                results_dir=results_dir,
                repo_name=repo_name,
                timeout_per_harness=timeout_per_harness,
                max_total_time=max_total_time,
                dry_run=dry_run,
                triage=triage,
                parallel=parallel,
                rss_limit_mb=rss_limit_mb,
                corpus_base_dir=corpus_base,
            )
            out.append((repo_name, results, summary_path))
    return out
