#!/usr/bin/env python3
"""Generate Markdown + CSV report from benchmark results.

Usage:
    python benchmarks/scripts/generate_report.py --run-dir benchmarks/results/<timestamp>
    python benchmarks/scripts/generate_report.py --run-dir benchmarks/results/<timestamp> --charts
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s  %(message)s")
logger = logging.getLogger(__name__)


def _pct(val: float | None, decimals: int = 1) -> str:
    if val is None:
        return "—"
    return f"{val * 100:.{decimals}f}%"


def _num(val: float | int | None, decimals: int = 3) -> str:
    if val is None:
        return "—"
    return f"{val:.{decimals}f}"


def _load_results(run_dir: Path) -> list[dict]:
    """Load all checkpoint JSON files from a run directory."""
    summaries = []
    summary_file = run_dir / "summary.json"
    if summary_file.exists():
        data = json.loads(summary_file.read_text())
        return data.get("summary", [])

    # Fall back to reading individual checkpoints
    for f in sorted(run_dir.glob("*_results.json")):
        try:
            data = json.loads(f.read_text())
        except (json.JSONDecodeError, OSError):
            continue
        # Only include completed checkpoints; skip in-progress (resumed but not done)
        if data.get("status", "completed") != "completed":
            continue
        if "metrics" in data:
            summaries.append(data["metrics"])
    return summaries


def _main_table(summaries: list[dict]) -> str:
    """Build the main Markdown comparison table."""
    headers = [
        "Approach", "Dataset", "Precision", "Recall", "F1",
        "FP Reduc.", "TP Pres.", "NMD Rate",
        "Tokens/Finding", "Cost (USD)", "Latency p95 (s)",
    ]
    rows = [headers]
    rows.append(["---"] * len(headers))

    for s in summaries:
        rows.append([
            s.get("approach", "?"),
            s.get("dataset", "?"),
            _pct(s.get("precision")),
            _pct(s.get("recall")),
            _pct(s.get("f1")),
            _pct(s.get("fp_reduction_rate")),
            _pct(s.get("tp_preservation_rate")),
            _pct(s.get("nmd_rate")),
            _num(s.get("tokens_per_finding"), 0),
            f"${s.get('total_cost_usd', 0):.4f}",
            _num(s.get("p95_latency_s")),
        ])

    return "\n".join("| " + " | ".join(r) + " |" for r in rows)


def _calibration_table(summaries: list[dict]) -> str:
    """Build calibration accuracy table."""
    lines = ["| Approach | Dataset | Confidence | Total | Correct | Accuracy |",
             "|---|---|---|---|---|---|"]
    for s in summaries:
        cal = s.get("calibration", {})
        for bucket, data in cal.items():
            lines.append(
                f"| {s.get('approach','?')} | {s.get('dataset','?')} | {bucket} "
                f"| {data.get('total','?')} | {data.get('correct','?')} "
                f"| {_pct(data.get('accuracy'))} |"
            )
    return "\n".join(lines) if len(lines) > 2 else "_No calibration data._"


def _cwe_table(summaries: list[dict]) -> str:
    """Build per-CWE breakdown table for all approaches."""
    lines = ["| Approach | CWE | Total | Precision | Recall | F1 |",
             "|---|---|---|---|---|---|"]
    for s in summaries:
        for cwe in s.get("per_cwe", []):
            lines.append(
                f"| {s.get('approach','?')} | {cwe.get('cwe_id','?')} "
                f"| {cwe.get('total','?')} "
                f"| {_pct(cwe.get('precision'))} "
                f"| {_pct(cwe.get('recall'))} "
                f"| {_pct(cwe.get('f1'))} |"
            )
    return "\n".join(lines) if len(lines) > 2 else "_No per-CWE data._"


def _cost_table(summaries: list[dict]) -> str:
    """Build cost and latency table."""
    headers = ["Approach", "Dataset", "Total Tokens", "Total Cost", "Mean Latency", "Iterations (mean/max)"]
    rows = [headers, ["---"] * len(headers)]
    for s in summaries:
        iters = (
            f"{_num(s.get('mean_iterations'), 1)} / {s.get('max_iterations', '—')}"
        )
        rows.append([
            s.get("approach", "?"),
            s.get("dataset", "?"),
            str(s.get("total_tokens", 0)),
            f"${s.get('total_cost_usd', 0):.4f}",
            _num(s.get("mean_latency_s")),
            iters,
        ])
    return "\n".join("| " + " | ".join(r) + " |" for r in rows)


def _generate_charts(summaries: list[dict], out_dir: Path) -> list[str]:
    """Generate matplotlib charts if available. Returns list of chart paths."""
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed; skipping charts. pip install matplotlib")
        return []

    charts = []

    # Precision/Recall bar chart per approach
    approaches = [s.get("approach", "?") for s in summaries]
    precisions = [(s.get("precision") or 0) * 100 for s in summaries]
    recalls = [(s.get("recall") or 0) * 100 for s in summaries]

    x = range(len(approaches))
    fig, ax = plt.subplots(figsize=(max(6, len(approaches) * 1.5), 5))
    width = 0.35
    ax.bar([xi - width / 2 for xi in x], precisions, width, label="Precision (%)")
    ax.bar([xi + width / 2 for xi in x], recalls, width, label="Recall (%)")
    ax.set_xticks(list(x))
    ax.set_xticklabels(approaches, rotation=20, ha="right")
    ax.set_ylim(0, 105)
    ax.set_ylabel("Percentage")
    ax.set_title("Precision and Recall by Approach")
    ax.legend()
    fig.tight_layout()
    chart_path = out_dir / "precision_recall.png"
    fig.savefig(chart_path, dpi=120)
    plt.close(fig)
    charts.append(str(chart_path))
    logger.info("Chart saved: %s", chart_path)

    return charts


def generate_report(run_dir: Path, include_charts: bool = False) -> Path:
    """Generate REPORT.md in the run directory."""
    summaries = _load_results(run_dir)
    if not summaries:
        logger.error("No benchmark results found in %s", run_dir)
        sys.exit(1)

    chart_paths = _generate_charts(summaries, run_dir) if include_charts else []

    lines = [
        "# VulnHunterX Benchmark Report",
        "",
        f"**Run directory**: `{run_dir}`",
        "",
        "---",
        "",
        "## Summary Comparison",
        "",
        _main_table(summaries),
        "",
        "> **Columns**: Precision/Recall/F1 computed on TP+FP labels only (BENIGN excluded).",
        "> FP Reduc. = (SAST FPs − approach FPs) / SAST FPs.",
        "> TP Pres. = approach TPs / SAST TPs.",
        "> NMD Rate = fraction of findings returned as Needs-More-Data (excluded from P/R/F1).",
        "",
        "---",
        "",
        "## Confidence Calibration",
        "",
        _calibration_table(summaries),
        "",
        "> Within each confidence bucket, what fraction of predictions matched ground truth?",
        "> Well-calibrated approaches show High → higher accuracy than Low.",
        "",
        "---",
        "",
        "## Per-CWE Breakdown",
        "",
        _cwe_table(summaries),
        "",
        "---",
        "",
        "## Cost & Latency",
        "",
        _cost_table(summaries),
        "",
    ]

    if chart_paths:
        lines += ["---", "", "## Charts", ""]
        for cp in chart_paths:
            rel = Path(cp).relative_to(run_dir)
            lines.append(f"![{rel}]({rel})")
        lines.append("")

    report_path = run_dir / "REPORT.md"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info("Report written: %s", report_path)
    return report_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-dir", required=True, type=Path, help="Benchmark run directory")
    parser.add_argument("--charts", action="store_true", help="Generate matplotlib charts")
    args = parser.parse_args()

    run_dir = Path(args.run_dir)
    if not run_dir.is_dir():
        logger.error("Run directory not found: %s", run_dir)
        return 1

    report_path = generate_report(run_dir, include_charts=args.charts)
    print(f"Report: {report_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
