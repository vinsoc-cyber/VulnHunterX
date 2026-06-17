# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for benchmarks.scripts._progress.

Focus: ETA / "s/entry" must be derived from wall-clock time so they remain
honest under parallel execution (run_benchmark.py -j N), not from a mean of
per-entry elapsed_seconds (which is invariant under concurrency).
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest

from benchmarks.approaches.base import BenchmarkResult
from benchmarks.scripts import _progress as progress_mod


def _mk_result(elapsed: float) -> BenchmarkResult:
    """Minimal BenchmarkResult with the only fields ProgressDisplay reads."""
    entry = MagicMock()
    entry.function_name = "f"
    entry.cwe_id = "CWE-89"
    return BenchmarkResult(
        entry=entry,
        predicted_label="TP",
        confidence="High",
        reasoning="ok",
        elapsed_seconds=elapsed,
        tokens_used=100,
        cost_usd=0.001,
    )


def test_render_bar_uses_wall_clock_for_eta_and_speed():
    """Per-entry elapsed_seconds is 50 s for every result. Wall clock advances
    only 10 s for 4 entries (i.e. ~2.5 s/entry due to parallel execution).
    The progress bar must report ~2.5 s/entry, NOT 50 s/entry."""
    stderr = io.StringIO()
    with patch.object(progress_mod, "_stderr", return_value=stderr), \
         patch.object(progress_mod, "_is_tty", return_value=True):
        # Control time precisely.
        clock = [1000.0]
        with patch.object(progress_mod.time, "monotonic", side_effect=lambda: clock[0]):
            display = progress_mod.ProgressDisplay(
                dataset="ds", approach="ap", total=10, verbose=False, quiet=False,
            )
            display.start(resumed_count=0)
            # Simulate 4 entries finishing concurrently — per-entry elapsed
            # reads 50 s each, but only 10 s of wall time passed.
            clock[0] += 10.0
            for _ in range(4):
                display.update(_mk_result(elapsed=50.0))

    out = stderr.getvalue()
    # Wall-per-entry = 10 / 4 = 2.5 s, ETA for remaining 6 = 15 s.
    assert "2.5s/entry" in out, out
    assert "ETA 15s" in out, out
    # And the misleading per-entry-mean figure must NOT appear.
    assert "50.0s/entry" not in out


def test_render_bar_skips_resumed_count_in_throughput():
    """A resumed run inherits prior completions. Wall throughput should only
    account for entries this process actually evaluated, not the resumed
    prefix — otherwise the first few ticks underestimate ETA wildly."""
    stderr = io.StringIO()
    with patch.object(progress_mod, "_stderr", return_value=stderr), \
         patch.object(progress_mod, "_is_tty", return_value=True):
        clock = [500.0]
        with patch.object(progress_mod.time, "monotonic", side_effect=lambda: clock[0]):
            display = progress_mod.ProgressDisplay(
                dataset="ds", approach="ap", total=100, verbose=False, quiet=False,
            )
            display.start(resumed_count=40)
            # 5 s of this process produced 1 fresh entry.
            clock[0] += 5.0
            display.update(_mk_result(elapsed=2.0))

    out = stderr.getvalue()
    # Wall-per-entry must be 5 s (the new entry), not 5/41 s.
    assert "5.0s/entry" in out, out
    # ETA for remaining 59 entries at 5 s each = 295 s = 4m55s.
    assert "ETA 4m55s" in out, out


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
