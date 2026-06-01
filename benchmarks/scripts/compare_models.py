#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Aggregate a model-matrix run into one side-by-side comparison.

Reads ``matrix.json`` (written by ``run_model_matrix.py``) from a matrix
directory, loads each member model's ``summary.json`` using the same loaders as
``generate_report.py``, and writes ``COMPARISON.md`` — one row per
(model × dataset × approach) with precision / recall / F1 / FP-reduction /
NMD-rate / tokens-per-finding / p95 latency / cost.

Model-independent baselines (``is_baseline`` approaches such as ``raw-sast``,
which make no LLM call) produce identical metrics for every model, so they are
collapsed to a **single** row per (dataset × approach) rather than duplicated
once per model. A ``⚠️`` callout is emitted if the supposedly-identical baseline
numbers ever diverge across members.

Cost is the real provider-reported cost (``total_cost_usd``); it is $0 for local
/ Ollama models and for any model LiteLLM has no price for.

Examples:
    python benchmarks/scripts/compare_models.py --run-dir benchmarks/results/matrix_20260530_101500
    python benchmarks/scripts/compare_models.py --run-dir <matrix_dir> --charts
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.approaches.registry import get_approach  # noqa: E402
from benchmarks.scripts.generate_report import _load_results, _load_run_meta  # noqa: E402


def _is_baseline_approach(name: str) -> bool:
    """True if the approach is model-independent (no LLM, identical across models).

    Driven by the registry's ``is_baseline`` flag (``get_approach`` lazily loads
    the registry) so a future baseline arm is collapsed automatically; falls back
    to the known ``raw-sast`` name if a stale checkpoint references an approach no
    longer registered.
    """
    try:
        return bool(get_approach(name).is_baseline)
    except KeyError:
        return name == "raw-sast"


def _metric_differs(a: float | None, b: float | None) -> bool:
    """True if two metric values disagree beyond float rounding noise."""
    if a is None or b is None:
        return a is not b
    return abs(a - b) > 1e-9


def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v * 100:.1f}%"


def _num(v: float | int | None, dec: int = 1) -> str:
    return "—" if v is None else f"{v:.{dec}f}"


def _member_cost(summaries: list[dict]) -> float:
    """Real provider-reported cost summed across a member's rows."""
    return sum(s.get("total_cost_usd", 0.0) or 0.0 for s in summaries)


def _cost_str(real: float) -> str:
    return f"${real:.4f}"


def build_comparison(matrix_dir: Path) -> str:
    manifest_path = matrix_dir / "matrix.json"
    if not manifest_path.is_file():
        raise FileNotFoundError(f"matrix.json not found in {matrix_dir}")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    members = manifest.get("members", [])

    rows: list[dict] = []
    failed: list[str] = []
    for member in members:
        mid = member["model_id"]
        if member.get("returncode", 0) != 0:
            failed.append(f"{mid} (exit {member['returncode']})")
        member_dir = matrix_dir / member.get("subdir", mid)
        if not member_dir.is_dir():
            continue
        summaries = _load_results(member_dir)
        meta = _load_run_meta(member_dir)
        model_label = meta.get("model", member.get("model", mid))
        for s in summaries:
            rows.append(
                {
                    "model_id": mid,
                    "model": model_label,
                    "provider": member.get("provider", meta.get("provider", "")),
                    "dataset": s.get("dataset", "?"),
                    "approach": s.get("approach", "?"),
                    "precision": s.get("precision"),
                    "recall": s.get("recall"),
                    "f1": s.get("f1"),
                    "fp_reduction_rate": s.get("fp_reduction_rate"),
                    "nmd_rate": s.get("nmd_rate"),
                    "tokens_per_finding": s.get("tokens_per_finding"),
                    "p95_latency_s": s.get("p95_latency_s"),
                    "cost": _cost_str(_member_cost([s])),
                }
            )

    # Model-independent baselines (e.g. raw-sast) are identical for every model:
    # collapse each (dataset × approach) group to one row instead of repeating it
    # per model, and flag any group whose metrics actually diverge across members.
    model_rows = [r for r in rows if not _is_baseline_approach(r["approach"])]
    baseline_groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        if _is_baseline_approach(r["approach"]):
            baseline_groups.setdefault((r["dataset"], r["approach"]), []).append(r)

    baseline_rows: list[dict] = []
    diverged: list[str] = []
    for (dataset, approach), group in baseline_groups.items():
        baseline_rows.append(group[0])
        for metric in ("precision", "recall", "f1"):
            vals = [g.get(metric) for g in group]
            if any(_metric_differs(vals[0], v) for v in vals[1:]):
                members = ", ".join(g["model_id"] for g in group)
                diverged.append(
                    f"{approach} on {dataset}: {metric} differs across "
                    f"members ({members}) — baseline is meant to be "
                    "model-independent."
                )
                break

    model_rows.sort(key=lambda r: (r["dataset"], r["approach"], -(r["f1"] or 0.0)))
    baseline_rows.sort(key=lambda r: (r["dataset"], r["approach"]))

    out: list[str] = ["# Model Comparison", ""]
    out.append(f"Matrix dir: `{matrix_dir}`  ")
    out.append(
        f"Datasets: {', '.join(manifest.get('datasets', []))} · "
        f"Approaches: {', '.join(manifest.get('approaches', []))} · "
        f"limit: {manifest.get('limit', 0)}"
        f"{' · *(dry-run)*' if manifest.get('dry_run') else ''}"
    )
    out.append("")
    if failed:
        out.append(
            f"> ⚠️ Member run(s) failed: {', '.join(failed)}. Their rows may be missing or partial."
        )
        out.append("")
    for warning in diverged:
        out.append(f"> ⚠️ {warning}")
    if diverged:
        out.append("")

    header = (
        "| Model | Dataset | Approach | Precision | Recall | F1 | "
        "FP-Reduction | NMD | Tok/Find | p95 s | Cost |"
    )
    divider = "| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |"

    def _row(r: dict, model_cell: str) -> str:
        return (
            f"| {model_cell} | {r['dataset']} | {r['approach']} | "
            f"{_pct(r['precision'])} | {_pct(r['recall'])} | {_pct(r['f1'])} | "
            f"{_pct(r['fp_reduction_rate'])} | {_pct(r['nmd_rate'])} | "
            f"{_num(r['tokens_per_finding'], 0)} | {_num(r['p95_latency_s'], 2)} | "
            f"{r['cost']} |"
        )

    out.append(header)
    out.append(divider)
    for r in model_rows:
        out.append(_row(r, r["model_id"]))
    out.append("")
    out.append(
        "_Cost is the real provider-reported API cost; $0 for local/Ollama "
        "models and any model LiteLLM has no price for._"
    )

    if baseline_rows:
        out.append("")
        out.append("## Baselines (model-independent)")
        out.append("")
        out.append(
            "_These approaches make no LLM call, so their metrics depend only "
            "on the dataset's ground-truth split — identical for every model. "
            "Shown once, not per model._"
        )
        out.append("")
        out.append(header)
        out.append(divider)
        for r in baseline_rows:
            out.append(_row(r, "— (all models)"))
    return "\n".join(out) + "\n"


def _render_charts(matrix_dir: Path) -> None:
    """F1-by-model bar chart. No-op if matplotlib is absent."""
    try:
        import matplotlib  # noqa: PLC0415

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # noqa: PLC0415
    except ImportError:
        print(
            "matplotlib not installed — skipping charts "
            '(install with `uv pip install -e ".[benchmark]"`).',
            file=sys.stderr,
        )
        return

    manifest = json.loads((matrix_dir / "matrix.json").read_text(encoding="utf-8"))
    labels, f1s = [], []
    for member in manifest.get("members", []):
        member_dir = matrix_dir / member.get("subdir", member["model_id"])
        if not member_dir.is_dir():
            continue
        summaries = _load_results(member_dir)
        # Mean F1 across that member's non-baseline rows.
        f1_vals = [
            s.get("f1")
            for s in summaries
            if not _is_baseline_approach(s.get("approach", "")) and s.get("f1") is not None
        ]
        if not f1_vals:
            continue
        labels.append(member["model_id"])
        f1s.append(sum(f1_vals) / len(f1_vals))

    if not labels:
        print("No scored members — skipping charts.", file=sys.stderr)
        return

    fig, ax = plt.subplots(figsize=(max(6, len(labels) * 1.2), 4))
    ax.bar(labels, [f * 100 for f in f1s], color="#4c72b0")
    ax.set_ylabel("Mean F1 (%)")
    ax.set_title("F1 by model")
    ax.set_ylim(0, 100)
    plt.xticks(rotation=30, ha="right")
    fig.tight_layout()
    fig.savefig(matrix_dir / "f1_by_model.png", dpi=120)
    plt.close(fig)
    print(f"Chart written to {matrix_dir / 'f1_by_model.png'}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate a model-matrix run.")
    parser.add_argument(
        "--run-dir",
        type=Path,
        required=True,
        help="Matrix parent directory containing matrix.json.",
    )
    parser.add_argument(
        "--charts", action="store_true", help="Also render the F1-by-model chart."
    )
    args = parser.parse_args()

    try:
        report = build_comparison(args.run_dir)
    except (FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    out_path = args.run_dir / "COMPARISON.md"
    out_path.write_text(report, encoding="utf-8")
    print(f"✓ COMPARISON.md written: {out_path}", file=sys.stderr)
    if args.charts:
        _render_charts(args.run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
