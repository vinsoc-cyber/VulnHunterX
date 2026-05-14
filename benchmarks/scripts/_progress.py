# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Lightweight CLI progress display for the benchmark runner.

No third-party dependencies — uses only stdlib (sys, shutil, time).
Outputs to stderr so stdout (piped output) is unaffected.

Display modes
─────────────
TTY (default)   per-entry overwriting progress line + final summary line per pair
Quiet / piped   falls back to plain logger calls (caller's responsibility)

Usage::

    progress = ProgressDisplay(
        dataset="secllmholmes",
        approach="vulnhunterx",
        total=228,
        verbose=False,
        quiet=False,
    )
    progress.start(resumed_count=47)   # show header; if resuming, skip past count
    for entry, result in zip(entries, results):
        progress.update(result)
    metrics = evaluate(results, ...)
    progress.finish(metrics)
"""

from __future__ import annotations

import shutil
import sys
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from benchmarks.approaches.base import BenchmarkResult
    from benchmarks.metrics.evaluator import ApproachMetrics

def _stderr() -> Any:
    """Return sys.stderr dynamically so pytest capsys redirection works."""
    return sys.stderr


# ANSI codes (only emitted when stderr is a TTY)
_BOLD = "\033[1m"
_GREEN = "\033[32m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_CYAN = "\033[36m"
_DIM = "\033[2m"
_RESET = "\033[0m"

_LABEL_COLOURS = {
    "TP": _GREEN,
    "FP": _RED,
    "NMD": _YELLOW,
    "ERROR": _RED,
}


def _is_tty() -> bool:
    s = _stderr()
    return hasattr(s, "isatty") and s.isatty()


def _colour(text: str, code: str) -> str:
    if _is_tty():
        return f"{code}{text}{_RESET}"
    return text


def _fmt_seconds(s: float) -> str:
    """Format seconds into human-readable duration string."""
    s = int(s)
    if s < 60:
        return f"{s}s"
    m, sec = divmod(s, 60)
    if m < 60:
        return f"{m}m{sec:02d}s"
    h, m = divmod(m, 60)
    return f"{h}h{m:02d}m"


def _term_width() -> int:
    return shutil.get_terminal_size((100, 24)).columns


@dataclass
class _RunningTotals:
    tp: int = 0
    fp: int = 0
    nmd: int = 0
    err: int = 0
    cost: float = 0.0
    tokens: int = 0
    elapsed_list: list[float] = field(default_factory=list)

    @property
    def count(self) -> int:
        return self.tp + self.fp + self.nmd + self.err

    def update(self, result: BenchmarkResult) -> None:
        label = result.predicted_label
        if label == "TP":
            self.tp += 1
        elif label == "FP":
            self.fp += 1
        elif label == "NMD":
            self.nmd += 1
        else:
            self.err += 1
        self.cost += result.cost_usd
        self.tokens += result.tokens_used
        self.elapsed_list.append(result.elapsed_seconds)

    @property
    def mean_elapsed(self) -> float | None:
        return sum(self.elapsed_list) / len(self.elapsed_list) if self.elapsed_list else None


class ProgressDisplay:
    """Renders a live progress line to stderr during a benchmark run."""

    def __init__(
        self,
        dataset: str,
        approach: str,
        total: int,
        *,
        verbose: bool = False,
        quiet: bool = False,
    ) -> None:
        self.dataset = dataset
        self.approach = approach
        self.total = total
        self.verbose = verbose
        self.quiet = quiet
        self._tty = _is_tty() and not quiet
        self._totals = _RunningTotals()
        self._start_time = time.monotonic()
        self._resumed_count = 0
        self._pair_label = f"{dataset} × {approach}"

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self, resumed_count: int = 0) -> None:
        """Print a pair header line. Call once before the entry loop."""
        self._resumed_count = resumed_count
        if self.quiet:
            return
        header = _colour(
            f"  ▶  {self._pair_label}  [{self.total} entries",
            _CYAN,
        )
        if resumed_count:
            header += _colour(f", resuming from #{resumed_count}", _DIM)
        header += _colour("]", _CYAN)
        _stderr().write(header + "\n")
        _stderr().flush()

    def update(self, result: BenchmarkResult) -> None:
        """Call after each entry is evaluated. Updates the live progress line."""
        self._totals.update(result)
        if self.quiet:
            return

        done = self._resumed_count + self._totals.count

        if self.verbose:
            # Non-overwriting verbose line per entry
            label_colour = _LABEL_COLOURS.get(result.predicted_label, "")
            func = (result.entry.function_name or "")[:30]
            cwe = result.entry.cwe_id or "?"
            line = (
                f"    #{done:>4}  {cwe:<10}  {func:<30}  "
                f"→ {_colour(result.predicted_label, label_colour)} "
                f"({result.confidence or '?':<6})  "
                f"{result.elapsed_seconds:.1f}s  "
                f"{result.tokens_used}tok  "
                f"${result.cost_usd:.4f}"
            )
            _stderr().write(line + "\n")
            _stderr().flush()
        elif self._tty:
            self._render_bar(done)

    def finish(self, metrics: ApproachMetrics) -> None:
        """Print a final summary line after a pair completes."""
        if self.quiet:
            return

        # Clear the progress bar line
        if self._tty and not self.verbose:
            _stderr().write("\r" + " " * _term_width() + "\r")

        elapsed = time.monotonic() - self._start_time
        p = metrics.precision
        r = metrics.recall
        f1 = metrics.f1

        p_str = f"P={p * 100:.1f}%" if p is not None else "P=—"
        r_str = f"R={r * 100:.1f}%" if r is not None else "R=—"
        f1_str = f"F1={f1 * 100:.1f}%" if f1 is not None else "F1=—"

        cost_str = f"${self._totals.cost:.4f}"
        time_str = _fmt_seconds(elapsed)

        line = _colour("  ✓ ", _GREEN) + _colour(self._pair_label, _BOLD)
        line += f"  {self.total}/{self.total}"
        line += f"  {p_str} {r_str} {f1_str}"
        line += _colour(f"  {cost_str}", _DIM)
        line += _colour(f"  {time_str}", _DIM)

        _stderr().write(line + "\n")
        _stderr().flush()

    # ── Internal ──────────────────────────────────────────────────────────────

    def _render_bar(self, done: int) -> None:
        """Overwrite current line with a compact progress summary."""
        t = self._totals
        # Wall-clock throughput so the figure stays honest under parallel
        # execution (-j > 1). Per-entry elapsed_seconds is roughly constant
        # whether one worker or N run concurrently, so dividing total wall time
        # by entries-actually-done naturally accounts for the speedup.
        completed_now = done - self._resumed_count
        wall_elapsed = time.monotonic() - self._start_time
        if completed_now > 0 and wall_elapsed > 0:
            wall_per_entry = wall_elapsed / completed_now
            remaining = self.total - done
            eta = _fmt_seconds(remaining * wall_per_entry)
            speed = f"{wall_per_entry:.1f}s/entry"
        else:
            eta = "?"
            speed = "—"

        label_part = (
            f"TP:{_colour(str(t.tp), _GREEN)} "
            f"FP:{_colour(str(t.fp), _RED)} "
            f"NMD:{t.nmd} ERR:{t.err}"
        )

        bar = (
            f"\r  [{self._pair_label}]  "
            f"{done}/{self.total}  "
            f"{label_part}  "
            f"${t.cost:.3f}  "
            f"{speed}  ETA {eta}"
        )

        # Truncate to terminal width to avoid line wrap
        width = _term_width()
        # Strip ANSI for length calculation is complex; pad with spaces instead
        _stderr().write(bar[:width])
        _stderr().flush()


def print_run_header(
    run_dir: Path,  # type: ignore[name-defined]  # noqa: F821
    model: str,
    provider: str,
    datasets: list[str],
    approaches: list[str],
    *,
    resuming: bool = False,
    completed_pairs: int = 0,
    total_pairs: int = 0,
    quiet: bool = False,
) -> None:
    """Print a run-level header to stderr."""
    if quiet:
        return
    w = min(_term_width(), 60)
    sep = _colour("═" * w, _CYAN)
    _stderr().write(sep + "\n")
    title = _colour("  VulnHunterX Benchmark", _BOLD)
    if resuming:
        title += _colour(f"  (resuming {completed_pairs}/{total_pairs} pairs done)", _YELLOW)
    _stderr().write(title + "\n")
    _stderr().write(f"  Run dir:    {run_dir}\n")
    _stderr().write(f"  Log file:   {run_dir}/benchmark.log\n")
    _stderr().write(f"  Model:      {model}  ({provider})\n")
    _stderr().write(f"  Datasets:   {', '.join(datasets)}\n")
    _stderr().write(f"  Approaches: {', '.join(approaches)}\n")
    _stderr().write(sep + "\n")
    _stderr().flush()


def print_run_footer(
    run_dir: Path,  # type: ignore[name-defined]  # noqa: F821
    wall_seconds: float,
    total_cost: float,
    *,
    quiet: bool = False,
) -> None:
    """Print a run-level footer to stderr."""
    if quiet:
        return
    w = min(_term_width(), 60)
    sep = _colour("═" * w, _CYAN)
    _stderr().write(sep + "\n")
    _stderr().write(_colour("  Run Complete\n", _BOLD))
    _stderr().write(f"  Wall time:  {_fmt_seconds(wall_seconds)}\n")
    if total_cost > 0:
        _stderr().write(f"  Total cost: ${total_cost:.4f}\n")
    _stderr().write(
        f"  Report:     python benchmarks/scripts/generate_report.py --run-dir {run_dir}\n"
    )
    _stderr().write(f"  Details:    {run_dir}/findings.jsonl\n")
    _stderr().write(sep + "\n")
    _stderr().flush()
