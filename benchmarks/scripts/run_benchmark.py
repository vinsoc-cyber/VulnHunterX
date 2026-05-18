#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Main benchmark orchestrator.

Usage examples:
    # Smoke test (no LLM, instant):
    python benchmarks/scripts/run_benchmark.py \\
        --dataset secllmholmes --approach raw-sast --limit 10

    # Dry-run (mock LLM, no API cost):
    python benchmarks/scripts/run_benchmark.py \\
        --dataset secllmholmes --approach all --limit 20 --dry-run

    # Real run with GPT-4o-mini (cheapest):
    python benchmarks/scripts/run_benchmark.py \\
        --dataset secllmholmes --approach all --model gpt-4o-mini --limit 50

    # Full benchmark:
    python benchmarks/scripts/run_benchmark.py \\
        --dataset all --approach all --model gpt-4o

    # Resumable run — target a named directory, resume after interruption:
    python benchmarks/scripts/run_benchmark.py \\
        --dataset all --approach all --model gpt-4o \\
        --run-dir benchmarks/results/my_run
    # ... Ctrl+C ...
    python benchmarks/scripts/run_benchmark.py \\
        --dataset all --approach all --model gpt-4o \\
        --run-dir benchmarks/results/my_run --resume

    # Iteration sweep (VulnHunterX at max_iterations=1,2,3):
    python benchmarks/scripts/run_benchmark.py \\
        --dataset secllmholmes --approach vulnhunterx \\
        --model gpt-4o-mini --iteration-sweep
"""

from __future__ import annotations

import argparse
import warnings
from typing import Any
import json
import logging
import os
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path

# Allow running as script without installing the package
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# Load .env before argparse so LLM_MODEL / LLM_PROVIDER become default values
from dotenv import load_dotenv  # noqa: E402
load_dotenv(_REPO_ROOT / ".env")

# Load benchmark.yaml defaults (CLI flags override these)
_BENCHMARK_CFG: dict = {}
_BENCHMARK_YAML = _REPO_ROOT / "benchmarks" / "config" / "benchmark.yaml"
if _BENCHMARK_YAML.exists():
    try:
        import yaml  # type: ignore[import-untyped]
        _BENCHMARK_CFG = yaml.safe_load(_BENCHMARK_YAML.read_text()) or {}
    except Exception:
        pass  # yaml not installed or parse error — fall back to hard-coded defaults

_DEFAULT_MAX_ITERATIONS: int = (
    _BENCHMARK_CFG.get("verification", {}).get("max_iterations", 10)
)

from benchmarks.adapters.ground_truth import GroundTruthEntry, load_entries  # noqa: E402
from benchmarks.approaches.base import BenchmarkApproach, BenchmarkResult  # noqa: E402
from benchmarks.approaches.raw_sast import RawSastApproach  # noqa: E402
from benchmarks.approaches.ablation import AblationApproach  # noqa: E402
from benchmarks.approaches.vulnhunterx import VulnHunterXApproach  # noqa: E402
from benchmarks.metrics.cost import Pricing, load_pricing  # noqa: E402
from benchmarks.metrics.evaluator import ApproachMetrics, evaluate  # noqa: E402
from benchmarks.scripts._progress import (  # noqa: E402
    ProgressDisplay,
    print_run_footer,
    print_run_header,
)

logger = logging.getLogger(__name__)


def _setup_logging(run_dir: Path) -> None:
    """Configure logging: full INFO to file, WARNING+ to stderr.

    Keeps the terminal clean (progress bar / verbose lines only) while writing
    a complete audit trail — including per-finding entries and LiteLLM messages —
    to <run_dir>/benchmark.log.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    # File handler — full INFO+ log for debugging / post-analysis
    fh = logging.FileHandler(run_dir / "benchmark.log", encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(
        "%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
        datefmt="%H:%M:%S",
    ))
    root.addHandler(fh)

    # Stderr handler — WARNING+ only so the progress bar is never interrupted
    sh = logging.StreamHandler(sys.stderr)
    sh.setLevel(logging.WARNING)
    sh.setFormatter(logging.Formatter("%(levelname)-8s  %(message)s"))
    root.addHandler(sh)

    # Silence noisy third-party loggers (still captured in the log file)
    for lib in ("LiteLLM", "httpx", "httpcore", "openai", "anthropic"):
        logging.getLogger(lib).setLevel(logging.WARNING)

DATASETS_DIR = _REPO_ROOT / "benchmarks" / "datasets"
RESULTS_DIR = _REPO_ROOT / "benchmarks" / "results"


# ── Dataset loaders ──────────────────────────────────────────────────────────

def _load_fixture(
    fixture: Path,
    limit: int = 0,
    langs: list[str] | None = None,
    cwes: list[str] | None = None,
) -> list[GroundTruthEntry]:
    """Load fixture file with filters applied. Warns that fixture data is being used."""
    logger.warning(
        "Dataset not downloaded — using fixture file (%s). "
        "Download the full dataset for meaningful results.",
        fixture.name,
    )
    entries = load_entries(fixture)
    if langs:
        entries = [e for e in entries if e.lang in langs]
    if cwes:
        cwe_set = set(cwes)
        entries = [e for e in entries if e.cwe_id in cwe_set]
    if limit:
        entries = entries[:limit]
    return entries


def _parse_kv_options(items: list[str] | None) -> dict[str, str]:
    """Parse ``KEY=VALUE`` strings from ``action="append"`` argparse args.

    Returns a dict mapping key -> raw string value (further coercion happens
    inside the registry's ``option_schema``). A bare key with no ``=`` is
    treated as ``key=true`` so flag-shaped options stay convenient.
    """
    result: dict[str, str] = {}
    for raw in items or []:
        if "=" in raw:
            key, _, value = raw.partition("=")
        else:
            key, value = raw, "true"
        key = key.strip()
        if not key:
            continue
        result[key] = value.strip()
    return result


# Dataset on-disk directory mapping is read from benchmarks/datasets.yaml
# (the single source of truth shared with setup_datasets.py). If the
# manifest is missing or a dataset isn't listed, we fall back to using
# the registered name as the directory name.
_MANIFEST_PATH = _REPO_ROOT / "benchmarks" / "datasets.yaml"
_DATASET_DIRNAMES: dict[str, str] = {}
if _MANIFEST_PATH.is_file():
    try:
        import yaml as _yaml
        _raw = _yaml.safe_load(_MANIFEST_PATH.read_text(encoding="utf-8")) or {}
        _DATASET_DIRNAMES = {
            n: cfg["dirname"]
            for n, cfg in (_raw.get("datasets") or {}).items()
            if "dirname" in cfg
        }
    except Exception:  # noqa: BLE001
        logger.warning("Failed to load benchmark dataset manifest", exc_info=True)


def _resolve_dataset_path(name: str) -> Path:
    return DATASETS_DIR / _DATASET_DIRNAMES.get(name, name)


def _load_dataset(
    name: str,
    limit: int,
    options: dict[str, Any] | None = None,
    langs: list[str] | None = None,
    fallback_cwes: list[str] | None = None,
) -> list[GroundTruthEntry]:
    """Load entries for a given dataset name via the registry.

    Falls back to a fixture file under ``benchmarks/fixtures/`` if the
    dataset has not been downloaded. The ``options`` dict is validated
    against the adapter's ``option_schema`` by ``load_dataset()``; unknown
    keys produce a warning.
    """
    from benchmarks.adapters.registry import get_adapter, load_dataset

    options = dict(options or {})
    ds_path = _resolve_dataset_path(name)
    fixture = _REPO_ROOT / "benchmarks" / "fixtures" / f"{name}_sample.json"

    if ds_path.exists():
        return load_dataset(name, ds_path, limit=limit, options=options)

    if fixture.exists():
        return _load_fixture(fixture, limit=limit, langs=langs, cwes=fallback_cwes)

    # OWASP variants share a single bundled fixture
    if name.startswith("owasp-"):
        shared = _REPO_ROOT / "benchmarks" / "fixtures" / "owasp_benchmark_sample.json"
        if shared.exists():
            lang = name.split("-", 1)[1]
            entries = _load_fixture(shared, limit=0, langs=[lang], cwes=fallback_cwes)
            return entries[: limit or len(entries)]

    # Touch the adapter to surface a clean KeyError if the name is unknown
    # before reporting a missing-dataset error.
    get_adapter(name)
    raise FileNotFoundError(
        f"Dataset {name!r} not found at {ds_path}. "
        f"Run: python benchmarks/scripts/setup_datasets.py --dataset {name}"
    )


# ── Approach factory ─────────────────────────────────────────────────────────

def _build_approach(
    name: str,
    model: str,
    provider: str,
    dry_run: bool,
    options: dict[str, Any] | None = None,
) -> BenchmarkApproach:
    """Construct an approach instance via the registry.

    Per-approach knobs (``max_iterations``, ``force_decision``,
    ``use_slicing``) live in ``options`` and are validated against the
    approach's ``option_schema``. Unknown options for the chosen approach
    produce a warning, not a crash — see ``build_approach`` in the
    approach registry.
    """
    from benchmarks.approaches.registry import LLMConfig, build_approach

    return build_approach(
        name,
        llm=LLMConfig(provider=provider, model=model, dry_run=dry_run),
        options=options or {},
    )


# ── Checkpoint helpers ────────────────────────────────────────────────────────

def _checkpoint_path(run_dir: Path, dataset: str, approach: str) -> Path:
    return run_dir / f"{dataset}_{approach}_results.json"


def _atomic_write_json(path: Path, data: object) -> None:
    """Write JSON atomically: write to .tmp then replace, preventing corruption."""
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    os.replace(tmp, path)  # atomic on POSIX; best-effort on Windows


def _save_checkpoint(
    run_dir: Path,
    dataset: str,
    approach: str,
    results: list[BenchmarkResult],
    metrics: ApproachMetrics,
    *,
    status: str = "completed",
    raw_sast_tp: int | None = None,
    raw_sast_fp: int | None = None,
    pricing: dict[str, Pricing] | Pricing | None = None,
    model_name: str | None = None,
) -> None:
    path = _checkpoint_path(run_dir, dataset, approach)
    processed_ids = [r.entry.id for r in results]
    payload: dict = {
        "approach": approach,
        "dataset": dataset,
        # ── Resume metadata (new) ──────────────────────────────────────────
        "status": status,
        "processed_entry_ids": processed_ids,
        "total_entries_expected": len(results),
        "updated_at": datetime.now(tz=UTC).isoformat(),
        # ── Existing fields (backward-compatible) ─────────────────────────
        "metrics": metrics.summary_dict(
            raw_sast_tp=raw_sast_tp, raw_sast_fp=raw_sast_fp,
            pricing=pricing, model_name=model_name,
        ),
        "results": [r.to_dict() for r in results],
    }
    _atomic_write_json(path, payload)
    if status == "completed":
        logger.info("Checkpoint saved (%s): %s", status, path.name)
    else:
        logger.debug("Checkpoint saved (%s): %s  [%d entries]", status, path.name, len(results))


def _load_checkpoint(
    run_dir: Path, dataset: str, approach: str
) -> tuple[str, set[str], list[BenchmarkResult]] | None:
    """Load an existing checkpoint and return (status, processed_ids, results).

    Returns None if no checkpoint exists.
    Deduplicates results by entry_id (last occurrence wins, tolerating interrupted writes).
    Old checkpoints without a ``status`` field are treated as ``completed``.
    """
    path = _checkpoint_path(run_dir, dataset, approach)
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Could not read checkpoint %s: %s — starting fresh", path.name, exc)
        return None

    status = data.get("status", "completed")  # backward compat: no status → completed
    raw_results: list[dict] = data.get("results", [])

    # Deduplicate by entry_id — last occurrence wins
    seen: dict[str, dict] = {}
    for r in raw_results:
        eid = r.get("entry_id", "")
        if eid:
            seen[eid] = r

    prior_results = [BenchmarkResult.from_dict(r) for r in seen.values()]
    processed_ids = {r.entry.id for r in prior_results}
    return status, processed_ids, prior_results


# ── Per-finding log ───────────────────────────────────────────────────────────

def _log_finding(findings_log: Path, entry: GroundTruthEntry, result: BenchmarkResult) -> None:
    """Append one structured JSON line per evaluated entry to findings.jsonl."""
    record = {
        "id": entry.id,
        "cwe_id": entry.cwe_id,
        "gt_label": entry.label,
        "predicted": result.predicted_label,
        "confidence": result.confidence,
        "tokens_used": result.tokens_used,
        "cost_usd": result.cost_usd,
        "elapsed_s": round(result.elapsed_seconds, 2),
    }
    with open(findings_log, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ── Run config helpers ────────────────────────────────────────────────────────

def _save_run_config(run_dir: Path, config: dict) -> None:
    path = run_dir / "run_config.json"
    if not path.exists():
        # Only write on first creation; never overwrite so resume can detect drift
        config["started_at"] = datetime.now(tz=UTC).isoformat()
        _atomic_write_json(path, config)


def _check_run_config_drift(run_dir: Path, current: dict) -> None:
    """Warn if key args differ from the stored run config."""
    path = run_dir / "run_config.json"
    if not path.exists():
        return
    try:
        stored = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return
    drift = [
        k for k in ("model", "provider", "nmd_handling")
        if stored.get(k) != current.get(k)
    ]
    if drift:
        logger.warning(
            "Resume: stored run config differs on %s. "
            "Stored: %s. Current: %s. Proceeding with current args.",
            drift,
            {k: stored.get(k) for k in drift},
            {k: current.get(k) for k in drift},
        )


# ── Pre-flight guards ─────────────────────────────────────────────────────────

def _validate_entries(name: str, entries: list[GroundTruthEntry]) -> None:
    """Refuse to start a (potentially expensive) LLM run when the dataset's
    adapter is producing degenerate output. Two checks:

    * ≥50% of entries with no rule_id  → everything falls to default questions
    * ≥30% of entries with a stringified-list cwe_id (`CWE-[...]`)

    Skipped on samples smaller than 20 entries — the ratios aren't
    statistically meaningful on tiny smoke runs, and datasets with naturally
    sparse CWE labels (DiverseVul has ~30% unlabelled rows) would otherwise
    trip the guard by chance on a `--limit 5`.

    Bypass entirely with ``--ignore-quality-check`` when intentionally running
    a dataset whose adapter hasn't been improved yet.
    """
    if not entries or len(entries) < 20:
        return
    no_rule = sum(1 for e in entries if not e.rule_id)
    bad_cwe = sum(1 for e in entries if "[" in (e.cwe_id or ""))
    total = len(entries)
    if no_rule / total > 0.50:
        raise ValueError(
            f"{name}: {no_rule}/{total} entries have empty rule_id "
            f"({no_rule / total * 100:.0f}%). This forces 100% of LLM "
            "verifications to the default-question fallback and severely "
            "degrades recall. Fix the adapter (see "
            "benchmarks/adapters/diversevul_adapter.py for the cpp/ rule "
            "synthesis pattern) or rerun with --ignore-quality-check."
        )
    if bad_cwe / total > 0.30:
        raise ValueError(
            f"{name}: {bad_cwe}/{total} entries have malformed cwe_id "
            f"(stringified list like 'CWE-[...]'). The adapter is "
            "str()-converting a list field instead of unwrapping it. "
            "Fix the adapter or rerun with --ignore-quality-check."
        )


def _llm_preflight(provider: str, model: str) -> None:
    """Burn one ~4-token completion to fail fast on auth / quota / network
    issues. Cheaper than discovering them after 800+ failed entries.

    Uses ``LLMClient`` so the call goes through the same provider-prefix
    routing that real verifications use (e.g. an OpenAI-compatible endpoint
    set via ``OPENAI_API_BASE`` requires the ``openai/`` model prefix that
    LLMClient adds automatically).
    """
    import litellm

    from vuln_hunter_x.llm.client import LLMClient

    try:
        client = LLMClient(provider=provider, model=model, temperature=0.0, max_tokens=4)
        kwargs = client._build_completion_kwargs(
            [{"role": "user", "content": "ok"}],
        )
        litellm.completion(**kwargs)
    except Exception as exc:  # noqa: BLE001 - surface any provider error
        raise SystemExit(
            f"LLM pre-flight failed for {provider}/{model}: {exc}\n"
            "Fix credentials / quota / network before retrying. Skip the "
            "check with --skip-preflight if the failure is a benign one-off."
        )


# ── Main runner ───────────────────────────────────────────────────────────────

def run_one(
    dataset_name: str,
    approach_name: str,
    entries: list[GroundTruthEntry],
    approach: BenchmarkApproach,
    run_dir: Path,
    nmd_handling: str,
    resume: bool,
    checkpoint_every: int = 1,
    verbose: bool = False,
    quiet: bool = False,
    jobs: int = 1,
    llm_concurrency: int = 0,
) -> tuple[ApproachMetrics, list[BenchmarkResult]] | None:
    """Evaluate one (dataset, approach) pair with incremental checkpointing.

    Returns (metrics, all_results) or None when the pair was skipped.
    """
    prior_results: list[BenchmarkResult] = []
    processed_ids: set[str] = set()

    checkpoint_data = _load_checkpoint(run_dir, dataset_name, approach_name)
    if checkpoint_data is not None:
        ck_status, processed_ids, prior_results = checkpoint_data
        if resume:
            if ck_status == "completed":
                logger.info("SKIP (completed): %s × %s", dataset_name, approach_name)
                return None
            # in_progress: resume from where we left off
            remaining = [e for e in entries if e.id not in processed_ids]
            logger.info(
                "Resuming %s × %s — %d/%d entries already done, %d remaining",
                approach_name, dataset_name, len(prior_results), len(entries), len(remaining),
            )
            # Handle dataset drift (entries removed/changed since checkpoint)
            orphaned = processed_ids - {e.id for e in entries}
            if orphaned:
                logger.warning(
                    "%d checkpoint entry IDs not found in current dataset; "
                    "those results are kept but won't be re-evaluated.",
                    len(orphaned),
                )
            entries = remaining
        else:
            logger.info(
                "Overwriting existing checkpoint for %s × %s (--resume not set)",
                approach_name, dataset_name,
            )
            prior_results = []
            processed_ids = set()

    logger.info(
        "Running %s × %s on %d entries …",
        approach_name, dataset_name, len(entries),
    )

    progress = ProgressDisplay(
        dataset=dataset_name,
        approach=approach_name,
        total=len(prior_results) + len(entries),
        verbose=verbose,
        quiet=quiet,
    )
    progress.start(resumed_count=len(prior_results))

    # Wall-clock anchor for this (dataset, approach) pair. Distinct from the
    # sum-of-per-entry `total_elapsed` so parallel runs report honest
    # wall-time in summaries.
    pair_wall_start = time.monotonic()
    findings_log = run_dir / "findings.jsonl"
    # Pre-allocate slots so completion order doesn't reshuffle output order.
    slots: list[BenchmarkResult | None] = [None] * len(entries)
    state_lock = threading.Lock()
    done_count = 0

    # Concurrency gate for LLM-using approaches. ThreadPoolExecutor still runs
    # at --jobs parallelism (cheap work like raw-sast fans out freely), but the
    # actual model call is funnelled through a bounded semaphore so a low-RPM
    # proxy doesn't see 30 simultaneous requests and 429 everyone.
    llm_gate: threading.BoundedSemaphore | None = None
    if llm_concurrency and llm_concurrency > 0 and approach_name != "raw-sast":
        effective = min(llm_concurrency, max(jobs, 1))
        llm_gate = threading.BoundedSemaphore(effective)

    def _evaluate(entry: GroundTruthEntry) -> BenchmarkResult:
        if llm_gate is None:
            return approach.evaluate(entry)
        with llm_gate:
            return approach.evaluate(entry)

    def _completed_results() -> list[BenchmarkResult]:
        return [r for r in slots if r is not None]

    if jobs <= 1 or len(entries) <= 1:
        try:
            for i, entry in enumerate(entries, 1):
                result = _evaluate(entry)
                slots[i - 1] = result
                progress.update(result)
                _log_finding(findings_log, entry, result)
                logger.info(
                    "[%s] %s → %s (%s) | %d tok  $%.4f  %.1fs",
                    entry.id, entry.cwe_id, result.predicted_label,
                    result.confidence or "?", result.tokens_used,
                    result.cost_usd, result.elapsed_seconds,
                )
                if quiet and (i % 10 == 0 or i == len(entries)):
                    logger.info(
                        "  %d/%d done",
                        len(prior_results) + i,
                        len(prior_results) + len(entries),
                    )
                if i % checkpoint_every == 0 or i == len(entries):
                    all_so_far = prior_results + _completed_results()
                    partial_metrics = evaluate(
                        all_so_far, approach_name, dataset_name, nmd_handling
                    )
                    partial_metrics.wall_seconds = time.monotonic() - pair_wall_start
                    _save_checkpoint(
                        run_dir, dataset_name, approach_name,
                        all_so_far, partial_metrics, status="in_progress",
                    )
        except KeyboardInterrupt:
            completed = _completed_results()
            if completed:
                all_so_far = prior_results + completed
                partial_metrics = evaluate(
                    all_so_far, approach_name, dataset_name, nmd_handling
                )
                partial_metrics.wall_seconds = time.monotonic() - pair_wall_start
                _save_checkpoint(
                    run_dir, dataset_name, approach_name,
                    all_so_far, partial_metrics, status="in_progress",
                )
                logger.info(
                    "Interrupted. Progress saved (%d/%d entries).",
                    len(all_so_far), len(prior_results) + len(entries),
                )
            raise
    else:
        pool = ThreadPoolExecutor(max_workers=jobs, thread_name_prefix="vhx-bench")
        try:
            futures = {
                pool.submit(_evaluate, entry): idx
                for idx, entry in enumerate(entries)
            }
            try:
                for future in as_completed(futures):
                    idx = futures[future]
                    entry = entries[idx]
                    result = future.result()
                    with state_lock:
                        slots[idx] = result
                        done_count += 1
                        local_done = done_count
                        progress.update(result)
                        _log_finding(findings_log, entry, result)
                    logger.info(
                        "[%s] %s → %s (%s) | %d tok  $%.4f  %.1fs",
                        entry.id, entry.cwe_id, result.predicted_label,
                        result.confidence or "?", result.tokens_used,
                        result.cost_usd, result.elapsed_seconds,
                    )
                    if quiet and (local_done % 10 == 0 or local_done == len(entries)):
                        logger.info(
                            "  %d/%d done",
                            len(prior_results) + local_done,
                            len(prior_results) + len(entries),
                        )
                    if local_done % checkpoint_every == 0 or local_done == len(entries):
                        with state_lock:
                            all_so_far = prior_results + _completed_results()
                        partial_metrics = evaluate(
                            all_so_far, approach_name, dataset_name, nmd_handling
                        )
                        partial_metrics.wall_seconds = time.monotonic() - pair_wall_start
                        _save_checkpoint(
                            run_dir, dataset_name, approach_name,
                            all_so_far, partial_metrics, status="in_progress",
                        )
            except KeyboardInterrupt:
                pool.shutdown(cancel_futures=True, wait=True)
                with state_lock:
                    completed = _completed_results()
                if completed:
                    all_so_far = prior_results + completed
                    partial_metrics = evaluate(
                        all_so_far, approach_name, dataset_name, nmd_handling
                    )
                    partial_metrics.wall_seconds = time.monotonic() - pair_wall_start
                    _save_checkpoint(
                        run_dir, dataset_name, approach_name,
                        all_so_far, partial_metrics, status="in_progress",
                    )
                    logger.info(
                        "Interrupted. Progress saved (%d/%d entries).",
                        len(all_so_far), len(prior_results) + len(entries),
                    )
                raise
        finally:
            pool.shutdown(wait=True)

    all_results = prior_results + _completed_results()
    metrics = evaluate(all_results, approach_name, dataset_name, nmd_handling)
    metrics.wall_seconds = time.monotonic() - pair_wall_start
    progress.finish(metrics)
    return metrics, all_results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VulnHunterX Benchmark Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    # ``--dataset`` and ``--approach`` accept any name registered with the
    # respective registry, plus ``all`` and family tags (e.g. ``owasp``).
    # No closed ``choices`` list — keeping the parser open lets a newly-
    # added adapter or approach work without editing this file.
    from benchmarks.adapters.registry import all_adapter_names
    from benchmarks.approaches.registry import all_approach_names

    _adapter_names = all_adapter_names()
    _approach_names = all_approach_names()
    parser.add_argument(
        "--dataset",
        default="secllmholmes",
        metavar="DATASET",
        help=(
            f"Dataset name: one of {_adapter_names!r}, a family tag, or "
            f"'all'. (Adapters auto-discovered from the registry.)"
        ),
    )
    parser.add_argument(
        "--approach",
        nargs="+",
        default=["all"],
        metavar="APPROACH",
        help=f"One or more of: {' '.join(_approach_names)} all",
    )
    parser.add_argument("--model", default=os.environ.get("LLM_MODEL", "gpt-4o"))
    parser.add_argument("--provider", default=os.environ.get("LLM_PROVIDER", "openai"))
    parser.add_argument("--limit", type=int, default=0, help="Cap entries per dataset (0=all)")
    parser.add_argument(
        "--lang",
        nargs="+",
        choices=["c", "cpp", "python", "javascript", "php", "java", "go"],
        default=None,
        metavar="LANG",
        help=(
            "Filter fixture entries by language(s). "
            "E.g. --lang c cpp python. Default: all languages."
        ),
    )
    parser.add_argument(
        "--cwe",
        nargs="+",
        default=None,
        metavar="CWE",
        help=(
            "DiverseVul only: filter by CWE ID(s). "
            "E.g. --cwe CWE-787 CWE-416. Default: all CWEs."
        ),
    )
    parser.add_argument(
        "--include-unknown-cwe",
        action="store_true",
        help=(
            "DiverseVul only: keep records whose CVE has no CWE mapping. "
            "By default these are dropped because they pollute per-CWE "
            "stratification and force generic-fallback guided questions."
        ),
    )
    parser.add_argument(
        "--diversevul-negative-fraction",
        type=float,
        default=None,
        metavar="FRAC",
        help=(
            "DiverseVul only: rebalance returned entries to include this "
            "fraction of target=0 (non-vulnerable) records. e.g. 0.5 for a "
            "50/50 positive/negative mix. Required to make FP-Reduction a "
            "meaningful metric — by default raw-sast hits 100%% precision "
            "by construction because the dataset is filtered to positives."
        ),
    )
    parser.add_argument(
        "--juliet-per-cwe",
        type=int,
        default=20,
        metavar="N",
        help=(
            "Juliet only: max entries per CWE, balanced TP/FP (N//2 each). "
            "Default 20 → 160 total across 8 CWEs (~$5.50). "
            "Use 10 for a quick run (80 entries, ~$2.70). "
            "Use 0 for all entries across all 15 target CWEs (local model recommended)."
        ),
    )
    parser.add_argument("--max-iterations", type=int, default=_DEFAULT_MAX_ITERATIONS,
                        help=f"Max iterations for multi-turn approaches (default: {_DEFAULT_MAX_ITERATIONS}, from benchmarks/config/benchmark.yaml). "
                             "Deprecated; prefer --approach-option max_iterations=N.")
    parser.add_argument(
        "--dataset-option",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "Set a dataset-adapter option (repeatable). The key is "
            "validated against the chosen dataset's option_schema; "
            "unknown keys warn. Examples: "
            "--dataset-option negative_fraction=0.5 (diversevul), "
            "--dataset-option per_cwe_limit=20 (juliet), "
            "--dataset-option include_unknown_cwe=true (diversevul)."
        ),
    )
    parser.add_argument(
        "--approach-option",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help=(
            "Set an approach option (repeatable). Validated against the "
            "chosen approach's option_schema. Examples: "
            "--approach-option max_iterations=4 (vulnhunterx/ablation), "
            "--approach-option force_decision=false (vulnhunterx), "
            "--approach-option use_slicing=true (vulnhunterx)."
        ),
    )
    parser.add_argument(
        "--nmd-handling",
        choices=["exclude", "fp"],
        default="exclude",
        help="How to count Needs-More-Data verdicts in metrics",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mock LLM responses for testing without API costs",
    )
    parser.add_argument(
        "--ignore-quality-check",
        action="store_true",
        help=(
            "Bypass the adapter quality gate (>50%% empty rule_id or "
            ">30%% malformed cwe_id). Use when intentionally running an "
            "adapter with known gaps."
        ),
    )
    parser.add_argument(
        "--skip-preflight",
        action="store_true",
        help=(
            "Skip the one-shot LLM connectivity check before each "
            "(provider, model) pair. Useful for offline tests."
        ),
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help=(
            "Resume an interrupted run. Skips completed pairs; "
            "continues in-progress pairs from their last checkpoint."
        ),
    )
    parser.add_argument(
        "--run-dir",
        type=Path,
        default=None,
        help=(
            "Explicit output directory for this run. "
            "Use the same path with --resume to continue an interrupted run. "
            "Defaults to benchmarks/results/<timestamp>."
        ),
    )
    parser.add_argument(
        "--run-id",
        default=None,
        help="Timestamp alias for --run-dir (e.g. 20260305_113225). "
             "Resolves to benchmarks/results/<run-id>.",
    )
    parser.add_argument(
        "--checkpoint-every",
        type=int,
        default=1,
        metavar="N",
        help="Save incremental checkpoint every N entries (default: 1).",
    )
    parser.add_argument(
        "-j", "--jobs",
        type=int,
        default=4,
        metavar="N",
        help="Concurrent benchmark entries to evaluate (default: 4; set 1 to disable).",
    )
    parser.add_argument(
        "--llm-concurrency",
        type=int,
        default=4,
        metavar="N",
        help=(
            "Cap concurrent in-flight LLM calls (default: 4). Independent of "
            "--jobs: threads still spawn at --jobs parallelism, but the model "
            "call is gated by a semaphore so rate-limited proxies don't see "
            "all N requests at once. Set 0 to disable the cap. Has no effect "
            "on the raw-sast approach."
        ),
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print a detailed line per entry during the run.",
    )
    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress progress display; only emit log lines.",
    )
    parser.add_argument(
        "--force-decision",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Force a TP/FP decision when LLM returns Needs More Data (default: enabled)",
    )
    parser.add_argument(
        "--sliced-context",
        action="store_true",
        help="Use variable-aware code slicing for VulnHunterX approach",
    )
    parser.add_argument(
        "--iteration-sweep",
        action="store_true",
        help="Run vulnhunterx at max_iterations=1,2,3 to show multi-turn contribution",
    )
    parser.add_argument(
        "--pricing",
        type=Path,
        default=None,
        metavar="PATH",
        help=(
            "Path to a JSON pricing schedule (USD per 1M tokens) used to "
            "compute imputed_api_cost_usd. Defaults to the built-in "
            "DEFAULT_PRICING in benchmarks/metrics/cost.py. "
            "Use this to cost models not in the default schedule "
            "(e.g. DeepSeek): --pricing pricing.deepseek.json."
        ),
    )
    args = parser.parse_args()

    try:
        pricing_schedule = load_pricing(args.pricing)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: --pricing: {exc}", file=sys.stderr)
        return 2

    # Register custom pricing with LiteLLM so litellm.completion_cost resolves
    # for non-default models (e.g. qwen via Anthropic-compatible proxy).
    # Otherwise LiteLLM prints "Provider List: ..." on every call.
    try:
        import litellm  # noqa: PLC0415
        registry: dict[str, dict] = {}
        schedule_items = (
            pricing_schedule.items() if isinstance(pricing_schedule, dict) else {}
        )
        for model_name, p in schedule_items:
            registry[model_name] = {
                "input_cost_per_token": p.input / 1_000_000,
                "output_cost_per_token": p.output / 1_000_000,
                "litellm_provider": (
                    model_name.split("/", 1)[0] if "/" in model_name else "openai"
                ),
                "mode": "chat",
            }
        if registry:
            litellm.register_model(registry)
    except Exception:
        pass

    # Determine datasets and approaches via the registries.
    # ``all`` expands to every registered adapter. A family tag (e.g.
    # ``owasp``) expands to every adapter whose ``family`` attribute
    # matches — discovered from the registry, not hard-coded. A specific
    # adapter name is used as-is.
    from benchmarks.adapters.registry import (
        adapters_in_family,
        all_adapter_names,
    )
    from benchmarks.approaches.registry import all_approach_names

    if args.dataset == "all":
        datasets = all_adapter_names()
    else:
        family_expansion = adapters_in_family(args.dataset)
        datasets = family_expansion if family_expansion else [args.dataset]
    approaches = (
        all_approach_names()
        if "all" in args.approach
        else list(dict.fromkeys(args.approach))
    )

    if args.iteration_sweep:
        approaches = ["vulnhunterx"]

    # Resolve run directory (Phase 1)
    if args.run_dir is not None:
        run_dir = args.run_dir.expanduser().resolve()
    elif args.run_id is not None:
        run_dir = RESULTS_DIR / args.run_id
    elif args.resume:
        # --resume without an explicit dir: pick the latest existing run that
        # has at least one checkpoint. Without this, we'd create a fresh
        # timestamped dir, find no checkpoints, and silently start over.
        candidates = sorted(
            (d for d in RESULTS_DIR.glob("*") if d.is_dir() and any(d.glob("*_results.json"))),
            key=lambda d: d.stat().st_mtime,
        )
        if not candidates:
            print(
                f"error: --resume given but no resumable run found under {RESULTS_DIR}. "
                "Pass --run-dir or --run-id to point at a specific run.",
                file=sys.stderr,
            )
            return 2
        run_dir = candidates[-1]
        print(f"--resume: continuing latest run {run_dir.name}", file=sys.stderr)
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = RESULTS_DIR / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    if args.resume and not any(run_dir.glob("*_results.json")):
        print(
            f"error: --resume given but {run_dir} has no checkpoints to resume from.",
            file=sys.stderr,
        )
        return 2
    _setup_logging(run_dir)
    logger.info("Run directory: %s", run_dir)

    # Persist run config; warn on config drift when resuming (Phase 1)
    current_config = {
        "model": args.model,
        "provider": args.provider,
        "nmd_handling": args.nmd_handling,
        "limit": args.limit,
        "max_iterations": args.max_iterations,
        "datasets": datasets,
        "approaches": approaches,
        "dry_run": args.dry_run,
    }
    _save_run_config(run_dir, current_config)
    if args.resume:
        _check_run_config_drift(run_dir, current_config)

    # Count already-completed pairs for header display
    completed_before = sum(
        1 for ds in datasets for ap in approaches
        if _load_checkpoint(run_dir, ds, ap) is not None
        and (_load_checkpoint(run_dir, ds, ap) or (None,))[0] == "completed"
    )
    total_pairs = len(datasets) * len(approaches)

    print_run_header(
        run_dir, args.model, args.provider, datasets, approaches,
        resuming=args.resume,
        completed_pairs=completed_before,
        total_pairs=total_pairs,
        quiet=args.quiet,
    )

    all_metrics: list[ApproachMetrics] = []
    wall_start = time.monotonic()

    # One-shot LLM pre-flight before the run starts. Skip when dry-running or
    # when only raw-sast (no LLM) was requested.
    if (
        not args.dry_run
        and not args.skip_preflight
        and any(a != "raw-sast" for a in approaches)
    ):
        _llm_preflight(args.provider, args.model)

    # Statistical-noise guard: rebalancing diversevul to a fixed positive/
    # negative fraction with a small --limit produces per-CWE F1 numbers
    # that swing by ~25pp per misclassification. The 2026-05-15 16:45 run
    # used --limit 40 and over half its CWEs ended up with n<5 — drawing
    # conclusions from that is meaningless. Warn loudly so the user picks
    # a real sample size.
    if (
        args.diversevul_negative_fraction is not None
        and "diversevul" in datasets
        and 0 < args.limit < 100
    ):
        logger.warning(
            "--diversevul-negative-fraction is set but --limit=%d is small. "
            "Per-CWE F1 will be noise at this sample size (e.g. 4 ground-"
            "truth TPs in CWE-264 → ±25pp swing per misclassification). "
            "Recommend --limit 200 or higher for stable numbers.",
            args.limit,
        )

    # Merge --dataset-option / --approach-option KEY=VALUE entries (free-
    # form) with deprecated per-dataset / per-approach flags. The
    # deprecated flags still work for one release but emit a warning and
    # only apply to the target they were originally scoped to.
    user_dataset_options = _parse_kv_options(args.dataset_option)
    user_approach_options = _parse_kv_options(args.approach_option)

    def _options_for_dataset(name: str) -> dict[str, Any]:
        opts: dict[str, Any] = dict(user_dataset_options)
        if name == "diversevul":
            if args.include_unknown_cwe and "include_unknown_cwe" not in opts:
                warnings.warn(
                    "--include-unknown-cwe is deprecated; use "
                    "--dataset-option include_unknown_cwe=true",
                    DeprecationWarning, stacklevel=2,
                )
                opts["include_unknown_cwe"] = True
            if (args.diversevul_negative_fraction is not None
                    and "negative_fraction" not in opts):
                warnings.warn(
                    "--diversevul-negative-fraction is deprecated; use "
                    "--dataset-option negative_fraction=<float>",
                    DeprecationWarning, stacklevel=2,
                )
                opts["negative_fraction"] = args.diversevul_negative_fraction
            if args.cwe and "cwes" not in opts:
                opts["cwes"] = list(args.cwe)
        elif name == "juliet":
            if "per_cwe_limit" not in opts and args.juliet_per_cwe != 20:
                warnings.warn(
                    "--juliet-per-cwe is deprecated; use "
                    "--dataset-option per_cwe_limit=N",
                    DeprecationWarning, stacklevel=2,
                )
                opts["per_cwe_limit"] = args.juliet_per_cwe
            opts.setdefault("per_cwe_limit", args.juliet_per_cwe)
            opts.setdefault("benchmark_cwes_only", args.juliet_per_cwe > 0)
        return opts

    try:
        for dataset_name in datasets:
            logger.info("Loading dataset: %s (limit=%d)", dataset_name, args.limit)
            try:
                entries = _load_dataset(
                    dataset_name,
                    args.limit,
                    options=_options_for_dataset(dataset_name),
                    langs=args.lang,
                    fallback_cwes=args.cwe,
                )
            except FileNotFoundError as exc:
                logger.error("%s", exc)
                continue
            logger.info("  %d entries loaded", len(entries))

            # Tier 2A: refuse to start a real (LLM) run on a degenerate dataset.
            # Allow dry-run through unconditionally and let --ignore-quality-check
            # override deliberately.
            if not args.dry_run and not args.ignore_quality_check:
                try:
                    _validate_entries(dataset_name, entries)
                except ValueError as exc:
                    logger.error("Adapter quality check failed: %s", exc)
                    continue

            iteration_values = [1, 2, 3] if args.iteration_sweep else [args.max_iterations]

            # Collect all approach results for this dataset so we can compute
            # fp_reduction_rate and tp_preservation_rate relative to raw-sast.
            dataset_runs: list[tuple[str, ApproachMetrics, list[BenchmarkResult]]] = []

            for approach_name in approaches:
                for max_iters in iteration_values:
                    effective_name = (
                        f"{approach_name}_iter{max_iters}"
                        if args.iteration_sweep
                        else approach_name
                    )
                    approach_options = dict(user_approach_options)
                    # Deprecation shims: the historic CLI flags still set
                    # these options unless the user passed them explicitly
                    # via --approach-option. We only propagate options the
                    # chosen approach actually declares — otherwise raw-sast
                    # (which has an empty option_schema) would spam warnings
                    # for every default flag value.
                    from benchmarks.approaches.registry import get_approach
                    schema = get_approach(approach_name).option_schema
                    if "max_iterations" in schema:
                        approach_options.setdefault("max_iterations", max_iters)
                    if (
                        "force_decision" in schema
                        and "force_decision" not in approach_options
                    ):
                        approach_options["force_decision"] = args.force_decision
                    if (
                        "use_slicing" in schema
                        and args.sliced_context
                        and "use_slicing" not in approach_options
                    ):
                        approach_options["use_slicing"] = True
                    approach = _build_approach(
                        approach_name,
                        args.model,
                        args.provider,
                        args.dry_run,
                        options=approach_options,
                    )
                    approach.name = effective_name

                    result = run_one(
                        dataset_name,
                        effective_name,
                        entries,
                        approach,
                        run_dir,
                        args.nmd_handling,
                        args.resume,
                        checkpoint_every=args.checkpoint_every,
                        verbose=args.verbose,
                        quiet=args.quiet,
                        jobs=args.jobs,
                        llm_concurrency=args.llm_concurrency,
                    )
                    if result is not None:
                        metrics, results = result
                        dataset_runs.append((effective_name, metrics, results))

            # Find raw-sast baseline counts for this dataset
            raw_sast_tp: int | None = None
            raw_sast_fp: int | None = None
            for name, m, _ in dataset_runs:
                if name == "raw-sast":
                    raw_sast_tp = m.true_labels_tp
                    raw_sast_fp = m.true_labels_fp
                    break

            # Save final completed checkpoints with baseline-relative metrics (Phase 6)
            for name, m, results in dataset_runs:
                _save_checkpoint(
                    run_dir, dataset_name, name, results, m,
                    status="completed",
                    raw_sast_tp=raw_sast_tp, raw_sast_fp=raw_sast_fp,
                    pricing=pricing_schedule, model_name=args.model,
                )
                all_metrics.append(m)

    except KeyboardInterrupt:
        logger.info("Benchmark interrupted by user. Partial progress saved to %s", run_dir)
        # Fall through to write partial summary

    wall_elapsed = time.monotonic() - wall_start

    # Find per-dataset raw-sast baselines for summary
    raw_sast_by_dataset: dict[str, tuple[int, int]] = {}
    for m in all_metrics:
        if m.approach_name == "raw-sast":
            raw_sast_by_dataset[m.dataset_name] = (m.true_labels_tp, m.true_labels_fp)

    # Build summary from completed checkpoints on disk (Phase 6)
    # This is more accurate than just all_metrics (which may be empty on interrupt)
    completed_summaries = []
    incomplete_runs = []
    for f in sorted(run_dir.glob("*_results.json")):
        try:
            ck = json.loads(f.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            continue
        if ck.get("status", "completed") == "completed" and "metrics" in ck:
            completed_summaries.append(ck["metrics"])
        elif ck.get("status") == "in_progress":
            incomplete_runs.append({
                "file": f.name,
                "approach": ck.get("approach"),
                "dataset": ck.get("dataset"),
                "entries_done": len(ck.get("processed_entry_ids", [])),
                "entries_expected": ck.get("total_entries_expected"),
            })

    total_cost = sum(
        s.get("total_cost_usd", 0.0) for s in completed_summaries
    )

    summary: dict = {
        "run_dir": str(run_dir),
        "model": args.model,
        "provider": args.provider,
        "dry_run": args.dry_run,
        "wall_seconds": round(wall_elapsed, 2),
        "approaches_run": list({s.get("approach") for s in completed_summaries}),
        "summary": completed_summaries,
    }
    if incomplete_runs:
        summary["incomplete_runs"] = incomplete_runs

    summary_path = run_dir / "summary.json"
    _atomic_write_json(summary_path, summary)
    logger.info("Summary written: %s", summary_path)

    print_run_footer(
        run_dir, wall_elapsed, total_cost,
        quiet=args.quiet,
    )

    # Auto-generate report with charts after run completes
    try:
        from benchmarks.scripts.generate_report import generate_report as _generate_report
        report_path = _generate_report(run_dir, include_charts=True)
        logger.info("Report generated: %s", report_path)
    except Exception:
        logger.warning("Report generation failed", exc_info=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
