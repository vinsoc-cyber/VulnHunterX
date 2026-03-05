#!/usr/bin/env python3
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
import json
import logging
import os
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

# Allow running as script without installing the package
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.adapters.ground_truth import GroundTruthEntry, load_entries  # noqa: E402
from benchmarks.approaches.base import BenchmarkApproach, BenchmarkResult  # noqa: E402
from benchmarks.approaches.generic_questions import GenericQuestionsApproach  # noqa: E402
from benchmarks.approaches.raw_sast import RawSastApproach  # noqa: E402
from benchmarks.approaches.single_shot import SingleShotApproach  # noqa: E402
from benchmarks.approaches.vulnhunterx import VulnHunterXApproach  # noqa: E402
from benchmarks.metrics.evaluator import ApproachMetrics, evaluate  # noqa: E402
from benchmarks.scripts._progress import (  # noqa: E402
    ProgressDisplay,
    print_run_footer,
    print_run_header,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)

DATASETS_DIR = _REPO_ROOT / "benchmarks" / "datasets"
RESULTS_DIR = _REPO_ROOT / "benchmarks" / "results"


# ── Dataset loaders ──────────────────────────────────────────────────────────

def _load_dataset(name: str, limit: int) -> list[GroundTruthEntry]:
    """Load entries for a given dataset name."""
    # Check for fixture files first (for smoke tests)
    fixture = _REPO_ROOT / "benchmarks" / "fixtures" / f"{name}_sample.json"

    if name == "secllmholmes":
        ds_path = DATASETS_DIR / "secllmholmes"
        if ds_path.exists():
            from benchmarks.adapters.secllmholmes_adapter import SecLLMHolmesAdapter
            return SecLLMHolmesAdapter(ds_path).load(limit=limit)
        if fixture.exists():
            logger.info("Using fixture file: %s", fixture)
            return load_entries(fixture)
        raise FileNotFoundError(
            f"SecLLMHolmes dataset not found at {ds_path}. "
            "Run: python benchmarks/scripts/setup_datasets.py --dataset secllmholmes"
        )

    if name == "juliet":
        ds_path = DATASETS_DIR / "juliet"
        if ds_path.exists():
            from benchmarks.adapters.juliet_adapter import JulietAdapter
            return JulietAdapter(ds_path).load(mode="offline", limit=limit)
        if fixture.exists():
            logger.info("Using fixture file: %s", fixture)
            return load_entries(fixture)
        raise FileNotFoundError(
            f"Juliet dataset not found at {ds_path}. "
            "Run: python benchmarks/scripts/setup_datasets.py --dataset juliet"
        )

    if name == "cvefixes":
        db_path = DATASETS_DIR / "cvefixes" / "CVEfixes.db"
        if not db_path.exists():
            # Try .zip extraction artefact naming
            for candidate in (DATASETS_DIR / "cvefixes").rglob("*.db"):
                db_path = candidate
                break
        if db_path.exists():
            from benchmarks.adapters.cvefixes_adapter import CVEfixesAdapter
            return CVEfixesAdapter(db_path).load(limit=limit)
        if fixture.exists():
            logger.info("Using fixture file: %s", fixture)
            return load_entries(fixture)
        raise FileNotFoundError(
            f"CVEfixes DB not found at {db_path}. "
            "Run: python benchmarks/scripts/setup_datasets.py --dataset cvefixes"
        )

    raise ValueError(f"Unknown dataset: {name!r}")


# ── Approach factory ─────────────────────────────────────────────────────────

def _build_approach(
    name: str,
    model: str,
    provider: str,
    max_iterations: int,
    dry_run: bool,
) -> BenchmarkApproach:
    common = {"provider": provider, "model": model, "dry_run": dry_run}
    if name == "raw-sast":
        return RawSastApproach()
    if name == "single-shot":
        return SingleShotApproach(**common)
    if name == "generic-questions":
        return GenericQuestionsApproach(**common, max_iterations=max_iterations)
    if name == "vulnhunterx":
        return VulnHunterXApproach(**common, max_iterations=max_iterations)
    raise ValueError(f"Unknown approach: {name!r}")


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

    new_results: list[BenchmarkResult] = []

    try:
        for i, entry in enumerate(entries, 1):
            result = approach.evaluate(entry)
            new_results.append(result)
            progress.update(result)

            # Incremental checkpoint (also logs at 10-entry intervals in quiet mode)
            if quiet and (i % 10 == 0 or i == len(entries)):
                logger.info("  %d/%d done", len(prior_results) + i, len(prior_results) + len(entries))

            if i % checkpoint_every == 0 or i == len(entries):
                all_so_far = prior_results + new_results
                partial_metrics = evaluate(all_so_far, approach_name, dataset_name, nmd_handling)
                _save_checkpoint(
                    run_dir, dataset_name, approach_name,
                    all_so_far, partial_metrics, status="in_progress",
                )

    except KeyboardInterrupt:
        # Best-effort checkpoint before surfacing the interrupt
        if new_results:
            all_so_far = prior_results + new_results
            partial_metrics = evaluate(all_so_far, approach_name, dataset_name, nmd_handling)
            _save_checkpoint(
                run_dir, dataset_name, approach_name,
                all_so_far, partial_metrics, status="in_progress",
            )
            logger.info(
                "Interrupted. Progress saved (%d/%d entries).",
                len(all_so_far), len(prior_results) + len(entries),
            )
        raise

    all_results = prior_results + new_results
    metrics = evaluate(all_results, approach_name, dataset_name, nmd_handling)
    progress.finish(metrics)
    return metrics, all_results


def main() -> int:
    parser = argparse.ArgumentParser(
        description="VulnHunterX Benchmark Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--dataset",
        choices=["secllmholmes", "juliet", "cvefixes", "all"],
        default="secllmholmes",
    )
    parser.add_argument(
        "--approach",
        choices=["raw-sast", "single-shot", "generic-questions", "vulnhunterx", "all"],
        default="all",
    )
    parser.add_argument("--model", default="gpt-4o")
    parser.add_argument("--provider", default="openai")
    parser.add_argument("--limit", type=int, default=0, help="Cap entries per dataset (0=all)")
    parser.add_argument("--max-iterations", type=int, default=3)
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
        "--iteration-sweep",
        action="store_true",
        help="Run vulnhunterx at max_iterations=1,2,3 to show multi-turn contribution",
    )
    args = parser.parse_args()

    # Determine datasets and approaches
    datasets = (
        ["secllmholmes", "juliet", "cvefixes"]
        if args.dataset == "all"
        else [args.dataset]
    )
    approaches = (
        ["raw-sast", "single-shot", "generic-questions", "vulnhunterx"]
        if args.approach == "all"
        else [args.approach]
    )

    if args.iteration_sweep:
        approaches = ["vulnhunterx"]

    # Resolve run directory (Phase 1)
    if args.run_dir is not None:
        run_dir = args.run_dir.expanduser().resolve()
    elif args.run_id is not None:
        run_dir = RESULTS_DIR / args.run_id
    else:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        run_dir = RESULTS_DIR / ts
    run_dir.mkdir(parents=True, exist_ok=True)
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

    try:
        for dataset_name in datasets:
            logger.info("Loading dataset: %s (limit=%d)", dataset_name, args.limit)
            try:
                entries = _load_dataset(dataset_name, args.limit)
            except FileNotFoundError as exc:
                logger.error("%s", exc)
                continue
            logger.info("  %d entries loaded", len(entries))

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
                    approach = _build_approach(
                        approach_name,
                        args.model,
                        args.provider,
                        max_iters,
                        args.dry_run,
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
