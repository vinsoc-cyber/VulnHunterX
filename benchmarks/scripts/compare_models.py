#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Aggregate a model-matrix run into one side-by-side comparison.

Reads ``matrix.json`` (written by ``run_model_matrix.py``) from a matrix
directory, loads each member model's ``summary.json`` using the same loaders as
``generate_report.py``, and writes ``COMPARISON.md`` — one row per
(model × dataset × approach) with precision / recall / F1 / FP-reduction /
NMD-rate / tokens-per-finding / p95 latency / cost.

Cost note: for local / Ollama models the real API cost is $0; the imputed cost
(tokens × list price, where available) is shown so the cost-vs-F1 frontier
doesn't plot them misleadingly.

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

from benchmarks.scripts.generate_report import _load_results, _load_run_meta  # noqa: E402


def _pct(v: float | None) -> str:
    return "—" if v is None else f"{v * 100:.1f}%"


def _num(v: float | int | None, dec: int = 1) -> str:
    return "—" if v is None else f"{v:.{dec}f}"


def _member_cost(summaries: list[dict]) -> tuple[float, float | None]:
    """Return (real_cost, imputed_cost_or_None) summed across a member's rows."""
    real = sum(s.get("total_cost_usd", 0.0) or 0.0 for s in summaries)
    imp = [s.get("imputed_api_cost_usd") for s in summaries
           if s.get("imputed_api_cost_usd") is not None]
    return real, (sum(imp) if imp else None)


def _cost_str(real: float, imputed: float | None) -> str:
    if imputed is not None and (real == 0.0 or imputed > real):
        return f"${real:.4f} (imp ${imputed:.4f})"
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
        real, imputed = _member_cost(summaries)
        model_label = meta.get("model", member.get("model", mid))
        for s in summaries:
            rows.append({
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
                "cost": _cost_str(*_member_cost([s])),
            })

    rows.sort(key=lambda r: (r["dataset"], r["approach"], -(r["f1"] or 0.0)))

    out: list[str] = ["# Model Comparison", ""]
    out.append(f"Matrix dir: `{matrix_dir}`  ")
    out.append(f"Datasets: {', '.join(manifest.get('datasets', []))} · "
               f"Approaches: {', '.join(manifest.get('approaches', []))} · "
               f"limit: {manifest.get('limit', 0)}"
               f"{' · *(dry-run)*' if manifest.get('dry_run') else ''}")
    out.append("")
    if failed:
        out.append(f"> ⚠️ Member run(s) failed: {', '.join(failed)}. "
                   "Their rows may be missing or partial.")
        out.append("")

    out.append("| Model | Dataset | Approach | Precision | Recall | F1 | "
               "FP-Reduction | NMD | Tok/Find | p95 s | Cost |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
    for r in rows:
        out.append(
            f"| {r['model_id']} | {r['dataset']} | {r['approach']} | "
            f"{_pct(r['precision'])} | {_pct(r['recall'])} | {_pct(r['f1'])} | "
            f"{_pct(r['fp_reduction_rate'])} | {_pct(r['nmd_rate'])} | "
            f"{_num(r['tokens_per_finding'], 0)} | {_num(r['p95_latency_s'], 2)} | "
            f"{r['cost']} |"
        )
    out.append("")
    out.append("_Cost shows real API cost; `(imp $…)` is the imputed "
               "tokens×list-price estimate (used for local/Ollama, billed $0)._")
    return "\n".join(out) + "\n"


def _render_charts(matrix_dir: Path) -> None:
    """F1-by-model bar + cost-vs-F1 scatter. No-op if matplotlib is absent."""
    try:
        import matplotlib  # noqa: PLC0415
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt  # noqa: PLC0415
    except ImportError:
        print("matplotlib not installed — skipping charts "
              "(install with `uv pip install -e \".[benchmark]\"`).", file=sys.stderr)
        return

    manifest = json.loads((matrix_dir / "matrix.json").read_text(encoding="utf-8"))
    labels, f1s, costs = [], [], []
    for member in manifest.get("members", []):
        member_dir = matrix_dir / member.get("subdir", member["model_id"])
        if not member_dir.is_dir():
            continue
        summaries = _load_results(member_dir)
        # Mean F1 across that member's non-baseline rows.
        f1_vals = [s.get("f1") for s in summaries
                   if s.get("approach") != "raw-sast" and s.get("f1") is not None]
        if not f1_vals:
            continue
        real, imputed = _member_cost(summaries)
        labels.append(member["model_id"])
        f1s.append(sum(f1_vals) / len(f1_vals))
        costs.append(imputed if (real == 0.0 and imputed is not None) else real)

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

    fig, ax = plt.subplots(figsize=(6, 5))
    ax.scatter(costs, [f * 100 for f in f1s], color="#dd8452")
    for x, y, lab in zip(costs, f1s, labels, strict=False):
        ax.annotate(lab, (x, y * 100), fontsize=8, xytext=(4, 4),
                    textcoords="offset points")
    ax.set_xlabel("Cost (USD, real or imputed)")
    ax.set_ylabel("Mean F1 (%)")
    ax.set_title("Cost vs F1 frontier")
    fig.tight_layout()
    fig.savefig(matrix_dir / "cost_vs_f1.png", dpi=120)
    plt.close(fig)
    print(f"Charts written to {matrix_dir}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate a model-matrix run.")
    parser.add_argument("--run-dir", type=Path, required=True,
                        help="Matrix parent directory containing matrix.json.")
    parser.add_argument("--charts", action="store_true",
                        help="Also render F1-by-model and cost-vs-F1 charts.")
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
