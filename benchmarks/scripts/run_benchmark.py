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

    # Iteration sweep (VulnHunterX at max_iterations=1,2,3):
    python benchmarks/scripts/run_benchmark.py \\
        --dataset secllmholmes --approach vulnhunterx \\
        --model gpt-4o-mini --iteration-sweep
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import time
from datetime import datetime
from pathlib import Path

# Allow running as script without installing the package
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.adapters.ground_truth import GroundTruthEntry, load_entries
from benchmarks.approaches.base import BenchmarkApproach, BenchmarkResult
from benchmarks.approaches.generic_questions import GenericQuestionsApproach
from benchmarks.approaches.raw_sast import RawSastApproach
from benchmarks.approaches.single_shot import SingleShotApproach
from benchmarks.approaches.vulnhunterx import VulnHunterXApproach
from benchmarks.metrics.evaluator import ApproachMetrics, evaluate

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


def _already_done(run_dir: Path, dataset: str, approach: str) -> bool:
    return _checkpoint_path(run_dir, dataset, approach).exists()


def _save_checkpoint(
    run_dir: Path,
    dataset: str,
    approach: str,
    results: list[BenchmarkResult],
    metrics: ApproachMetrics,
) -> None:
    path = _checkpoint_path(run_dir, dataset, approach)
    payload = {
        "approach": approach,
        "dataset": dataset,
        "metrics": metrics.summary_dict(),
        "results": [r.to_dict() for r in results],
    }
    path.write_text(json.dumps(payload, indent=2))
    logger.info("Saved checkpoint: %s", path)


# ── Main runner ───────────────────────────────────────────────────────────────

def run_one(
    dataset_name: str,
    approach_name: str,
    entries: list[GroundTruthEntry],
    approach: BenchmarkApproach,
    run_dir: Path,
    nmd_handling: str,
    resume: bool,
) -> ApproachMetrics | None:
    if resume and _already_done(run_dir, dataset_name, approach_name):
        logger.info("SKIP (already done): %s × %s", dataset_name, approach_name)
        return None

    logger.info(
        "Running %s × %s on %d entries …",
        approach_name,
        dataset_name,
        len(entries),
    )
    results: list[BenchmarkResult] = []
    for i, entry in enumerate(entries, 1):
        result = approach.evaluate(entry)
        results.append(result)
        if i % 10 == 0 or i == len(entries):
            logger.info("  %d/%d done", i, len(entries))

    metrics = evaluate(results, approach_name, dataset_name, nmd_handling)
    _save_checkpoint(run_dir, dataset_name, approach_name, results, metrics)
    return metrics


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
        help="Skip already-completed (dataset, approach) pairs",
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

    # Create run directory
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = RESULTS_DIR / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    logger.info("Run directory: %s", run_dir)

    all_metrics: list[ApproachMetrics] = []
    wall_start = time.monotonic()

    for dataset_name in datasets:
        logger.info("Loading dataset: %s (limit=%d)", dataset_name, args.limit)
        try:
            entries = _load_dataset(dataset_name, args.limit)
        except FileNotFoundError as exc:
            logger.error("%s", exc)
            continue
        logger.info("  %d entries loaded", len(entries))

        iteration_values = [1, 2, 3] if args.iteration_sweep else [args.max_iterations]

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

                metrics = run_one(
                    dataset_name,
                    effective_name,
                    entries,
                    approach,
                    run_dir,
                    args.nmd_handling,
                    args.resume,
                )
                if metrics is not None:
                    all_metrics.append(metrics)

    wall_elapsed = time.monotonic() - wall_start
    logger.info("Total wall time: %.1f s", wall_elapsed)

    # Write summary
    summary = {
        "run_dir": str(run_dir),
        "model": args.model,
        "provider": args.provider,
        "dry_run": args.dry_run,
        "wall_seconds": round(wall_elapsed, 2),
        "approaches_run": [m.approach_name for m in all_metrics],
        "summary": [m.summary_dict() for m in all_metrics],
    }
    summary_path = run_dir / "summary.json"
    summary_path.write_text(json.dumps(summary, indent=2))
    logger.info("Summary written: %s", summary_path)
    logger.info(
        "Run 'python benchmarks/scripts/generate_report.py --run-dir %s' to generate report.",
        run_dir,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
