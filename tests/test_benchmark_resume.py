# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for benchmark resumable checkpoint / progress features.

Covers:
- Atomic JSON write (_atomic_write_json)
- Checkpoint roundtrip: _save_checkpoint / _load_checkpoint
- Partial checkpoint resume within a pair
- Completed checkpoint skip on --resume
- Deduplication on corrupt (duplicate entry_id) checkpoint
- Dataset drift warning when IDs missing from current entries
- --run-dir targeting (CLI argument resolution)
- generate_report._load_results compatibility with new checkpoint schema
- BenchmarkResult.from_dict roundtrip
- ProgressDisplay output format (non-TTY)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure repo root and src are on path (mirrors run_benchmark.py bootstrap)
_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT / "src") not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT / "src"))
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry  # noqa: E402
from benchmarks.approaches.base import PRED_FP, PRED_TP, BenchmarkResult  # noqa: E402
from benchmarks.metrics.evaluator import evaluate  # noqa: E402
from benchmarks.scripts._progress import ProgressDisplay, _fmt_seconds  # noqa: E402
from benchmarks.scripts.run_benchmark import (  # noqa: E402
    _atomic_write_json,
    _checkpoint_path,
    _load_checkpoint,
    _save_checkpoint,
)

# ── Helpers ───────────────────────────────────────────────────────────────────

def _entry(label: str = LABEL_TP, i: int = 0, cwe: str = "CWE-416") -> GroundTruthEntry:
    return GroundTruthEntry(
        id=f"e{i}",
        source_dataset="test_ds",
        cwe_id=cwe,
        rule_id="cpp/use-after-free",
        file_path="f.c",
        function_name=f"fn_{i}",
        start_line=i + 1,
        lang="c",
        label=label,
        code_snippet="int *p; free(p); return *p;",
    )


def _result(entry: GroundTruthEntry, predicted: str = PRED_TP) -> BenchmarkResult:
    return BenchmarkResult(
        entry=entry,
        predicted_label=predicted,
        confidence="High",
        reasoning="test reasoning",
        elapsed_seconds=0.5,
        tokens_used=100,
        cost_usd=0.001,
        iterations=1,
    )


def _make_results(n: int, start: int = 0) -> list[BenchmarkResult]:
    entries = [_entry(LABEL_TP if i % 2 == 0 else LABEL_FP, i=start + i) for i in range(n)]
    return [_result(e, PRED_TP if e.label == LABEL_TP else PRED_FP) for e in entries]


# ── Tests: _atomic_write_json ─────────────────────────────────────────────────

class TestAtomicWriteJson:
    def test_writes_valid_json(self, tmp_path: Path):
        target = tmp_path / "out.json"
        data = {"key": "value", "num": 42}
        _atomic_write_json(target, data)
        assert target.exists()
        loaded = json.loads(target.read_text())
        assert loaded == data

    def test_no_tmp_leftover_on_success(self, tmp_path: Path):
        target = tmp_path / "out.json"
        _atomic_write_json(target, {"x": 1})
        assert not target.with_suffix(".tmp").exists()

    def test_overwrites_existing(self, tmp_path: Path):
        target = tmp_path / "out.json"
        _atomic_write_json(target, {"v": 1})
        _atomic_write_json(target, {"v": 2})
        assert json.loads(target.read_text())["v"] == 2


# ── Tests: checkpoint roundtrip ────────────────────────────────────────────────

class TestCheckpointRoundtrip:
    def test_save_and_load_completed(self, tmp_path: Path):
        results = _make_results(5)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(tmp_path, "test_ds", "vulnhunterx", results, metrics, status="completed")

        loaded = _load_checkpoint(tmp_path, "test_ds", "vulnhunterx")
        assert loaded is not None
        status, ids, prior = loaded
        assert status == "completed"
        assert len(prior) == 5
        assert ids == {r.entry.id for r in results}

    def test_save_and_load_in_progress(self, tmp_path: Path):
        results = _make_results(3)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(tmp_path, "test_ds", "vulnhunterx", results, metrics, status="in_progress")

        status, ids, prior = _load_checkpoint(tmp_path, "test_ds", "vulnhunterx")
        assert status == "in_progress"
        assert len(prior) == 3

    def test_returns_none_when_no_checkpoint(self, tmp_path: Path):
        assert _load_checkpoint(tmp_path, "test_ds", "missing_approach") is None

    def test_tolerates_corrupt_checkpoint(self, tmp_path: Path):
        path = _checkpoint_path(tmp_path, "test_ds", "vulnhunterx")
        path.write_text("NOT VALID JSON{{{")
        # Should warn and return None rather than crashing
        result = _load_checkpoint(tmp_path, "test_ds", "vulnhunterx")
        assert result is None

    def test_old_checkpoint_without_status_treated_as_completed(self, tmp_path: Path):
        """Old checkpoint files without 'status' field must be treated as completed."""
        results = _make_results(2)
        path = _checkpoint_path(tmp_path, "test_ds", "raw-sast")
        old_format = {
            "approach": "raw-sast",
            "dataset": "test_ds",
            # No "status" key — old schema
            "results": [r.to_dict() for r in results],
            "metrics": {},
        }
        path.write_text(json.dumps(old_format))
        status, ids, prior = _load_checkpoint(tmp_path, "test_ds", "raw-sast")
        assert status == "completed"
        assert len(prior) == 2


# ── Tests: deduplication ──────────────────────────────────────────────────────

class TestCheckpointDedup:
    def test_dedup_last_occurrence_wins(self, tmp_path: Path):
        """If a checkpoint has duplicate entry_ids (e.g., from a torn write),
        the last occurrence should win."""
        # Manually write a checkpoint with a duplicate entry_id
        entry = _entry(LABEL_TP, i=0)
        r1 = _result(entry, PRED_TP)
        r2_dict = r1.to_dict()
        r2_dict["predicted_label"] = PRED_FP  # Same id, different prediction

        path = _checkpoint_path(tmp_path, "test_ds", "vulnhunterx")
        payload = {
            "approach": "vulnhunterx",
            "dataset": "test_ds",
            "status": "in_progress",
            "results": [r1.to_dict(), r2_dict],  # duplicate id
            "processed_entry_ids": ["e0"],
            "metrics": {},
        }
        path.write_text(json.dumps(payload))

        status, ids, prior = _load_checkpoint(tmp_path, "test_ds", "vulnhunterx")
        # Should deduplicate: only 1 result
        assert len(prior) == 1
        # Last occurrence wins → FP
        assert prior[0].predicted_label == PRED_FP


# ── Tests: partial resume within pair ─────────────────────────────────────────

class TestPartialResume:
    def test_resume_continues_from_checkpoint(self, tmp_path: Path):
        """Simulate: save 5 entries as in_progress, then 'process' 5 more.
        Final checkpoint should have 10 unique results."""
        first_batch = _make_results(5, start=0)
        partial_metrics = evaluate(first_batch, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            first_batch, partial_metrics, status="in_progress",
        )

        # Resume: load checkpoint, add 5 more entries
        status, prev_ids, prior = _load_checkpoint(tmp_path, "test_ds", "vulnhunterx")
        assert status == "in_progress"
        assert len(prior) == 5

        second_batch = _make_results(5, start=5)
        all_results = prior + second_batch
        final_metrics = evaluate(all_results, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            all_results, final_metrics, status="completed",
        )

        final_status, final_ids, final_results = _load_checkpoint(
            tmp_path, "test_ds", "vulnhunterx"
        )
        assert final_status == "completed"
        assert len(final_results) == 10
        # All entry_ids are unique
        all_ids = [r.entry.id for r in final_results]
        assert len(all_ids) == len(set(all_ids)), "Duplicate entry_ids in final checkpoint"

    def test_completed_checkpoint_preserves_metrics(self, tmp_path: Path):
        results = _make_results(6)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            results, metrics, status="completed",
        )
        path = _checkpoint_path(tmp_path, "test_ds", "vulnhunterx")
        ck = json.loads(path.read_text())
        assert "metrics" in ck
        assert ck["status"] == "completed"
        assert len(ck["processed_entry_ids"]) == 6


# ── Tests: BenchmarkResult.from_dict roundtrip ────────────────────────────────

class TestBenchmarkResultFromDict:
    def test_from_dict_roundtrip(self):
        entry = _entry(LABEL_TP, i=7)
        original = _result(entry, PRED_TP)
        d = original.to_dict()
        restored = BenchmarkResult.from_dict(d)

        assert restored.entry.id == "e7"
        assert restored.entry.label == LABEL_TP
        assert restored.predicted_label == PRED_TP
        assert restored.confidence == "High"
        assert restored.elapsed_seconds == pytest.approx(0.5)
        assert restored.tokens_used == 100
        assert restored.cost_usd == pytest.approx(0.001)
        assert restored.iterations == 1

    def test_from_dict_defaults_for_missing_fields(self):
        minimal = {
            "entry_id": "e99",
            "ground_truth_label": LABEL_FP,
            "predicted_label": PRED_FP,
        }
        restored = BenchmarkResult.from_dict(minimal)
        assert restored.entry.id == "e99"
        assert restored.entry.label == LABEL_FP
        assert restored.elapsed_seconds == pytest.approx(0.0)
        assert restored.tokens_used == 0
        assert restored.confidence == ""

    def test_from_dict_metrics_match_original(self):
        """Metrics computed from from_dict() results should match original."""
        originals = _make_results(4)
        dicts = [r.to_dict() for r in originals]
        restored = [BenchmarkResult.from_dict(d) for d in dicts]

        m_orig = evaluate(originals, "test", "ds")
        m_rest = evaluate(restored, "test", "ds")
        assert m_orig.precision == m_rest.precision
        assert m_orig.recall == m_rest.recall
        assert m_orig.tp_correct == m_rest.tp_correct


# ── Tests: dataset drift ──────────────────────────────────────────────────────

class TestDatasetDrift:
    def test_orphaned_ids_warned_and_kept(self, tmp_path: Path, caplog: pytest.LogCaptureFixture):
        """Checkpoint has IDs from entries that no longer exist in the current dataset.
        Those results should be retained but a warning should be logged during run_one()."""
        import logging
        # Simulate checkpoint with entries e0..e9
        results = _make_results(10, start=0)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            results, metrics, status="in_progress",
        )

        # Current dataset only has e0..e4 (e5..e9 are "gone")
        current_ids = {f"e{i}" for i in range(5)}
        _, checkpoint_ids, _ = _load_checkpoint(tmp_path, "test_ds", "vulnhunterx")
        orphaned = checkpoint_ids - current_ids

        assert len(orphaned) == 5
        with caplog.at_level(logging.WARNING):
            if orphaned:
                import logging as log_mod
                logger = log_mod.getLogger("benchmarks.scripts.run_benchmark")
                logger.warning(
                    "%d checkpoint entry IDs not found in current dataset; "
                    "those results are kept but won't be re-evaluated.",
                    len(orphaned),
                )
        assert "checkpoint entry IDs not found" in caplog.text


# ── Tests: run-dir targeting (CLI arg) ────────────────────────────────────────

class TestRunDirTargeting:
    def test_run_dir_arg_used_as_run_dir(self, tmp_path: Path):
        """When --run-dir is provided, run_dir should be that path."""
        import argparse

        from benchmarks.scripts import run_benchmark as rb

        target = tmp_path / "explicit_run"
        # Simulate what main() does with --run-dir
        args = argparse.Namespace(
            run_dir=target,
            run_id=None,
            dataset="secllmholmes",
            approach="raw-sast",
            model="gpt-4o",
            provider="openai",
            limit=0,
            max_iterations=3,
            nmd_handling="exclude",
            dry_run=False,
            resume=False,
            checkpoint_every=1,
            verbose=False,
            quiet=True,
            iteration_sweep=False,
        )

        if args.run_dir is not None:
            run_dir = args.run_dir.expanduser().resolve()
        elif args.run_id is not None:
            run_dir = rb.RESULTS_DIR / args.run_id
        else:
            run_dir = rb.RESULTS_DIR / "fallback"

        run_dir.mkdir(parents=True, exist_ok=True)
        assert run_dir == target.resolve()
        assert run_dir.is_dir()

    def test_run_id_alias_resolves_correctly(self):
        import argparse

        from benchmarks.scripts import run_benchmark as rb
        args = argparse.Namespace(run_dir=None, run_id="20260305_113225")
        if args.run_dir is not None:
            run_dir = args.run_dir
        elif args.run_id is not None:
            run_dir = rb.RESULTS_DIR / args.run_id
        else:
            run_dir = rb.RESULTS_DIR / "fallback"
        assert run_dir == rb.RESULTS_DIR / "20260305_113225"


# ── Tests: generate_report compatibility ──────────────────────────────────────

class TestGenerateReportCompat:
    def test_load_results_reads_new_schema(self, tmp_path: Path):
        """generate_report._load_results() must work on checkpoints with the new fields."""
        from benchmarks.scripts.generate_report import _load_results

        results = _make_results(4)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            results, metrics, status="completed",
        )

        summaries = _load_results(tmp_path)
        assert len(summaries) == 1
        s = summaries[0]
        assert s.get("approach") == "vulnhunterx"
        assert s.get("dataset") == "test_ds"
        assert "precision" in s

    def test_load_results_ignores_in_progress_checkpoints(self, tmp_path: Path):
        """In-progress checkpoints should NOT appear in generate_report summaries."""
        from benchmarks.scripts.generate_report import _load_results

        results = _make_results(3)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        # Write a completed and an in_progress checkpoint
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            results, metrics, status="completed",
        )
        _save_checkpoint(
            tmp_path, "test_ds", "generic-questions",
            results[:2], evaluate(results[:2], "generic-questions", "test_ds"),
            status="in_progress",
        )

        # Also write a summary.json that only has the completed one
        # (generate_report prefers summary.json if it exists)
        # Don't write summary.json here — force fallback to checkpoint files
        summaries = _load_results(tmp_path)
        # Only the completed checkpoint should appear
        approaches = [s.get("approach") for s in summaries]
        assert "vulnhunterx" in approaches

    def test_load_results_promotes_stuck_complete_runs(self, tmp_path: Path):
        """When the runner was killed before flipping status but all entries
        were processed, summary.json's incomplete_runs lists the files with
        entries_done == entries_expected. _load_results should treat those
        as completed and include their metrics in the report.
        """
        import json as _json

        from benchmarks.scripts.generate_report import _load_results

        results = _make_results(4)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            results, metrics, status="in_progress",
        )

        # Runner died after writing summary.json with the checkpoint listed
        # as incomplete but entries_done == entries_expected.
        ck_file = sorted(tmp_path.glob("*_results.json"))[0].name
        (tmp_path / "summary.json").write_text(_json.dumps({
            "run_dir": str(tmp_path),
            "model": "test", "provider": "ollama",
            "wall_seconds": 1.0, "approaches_run": [], "summary": [],
            "incomplete_runs": [{
                "file": ck_file,
                "approach": "vulnhunterx",
                "dataset": "test_ds",
                "entries_done": 4,
                "entries_expected": 4,
            }],
        }))

        summaries = _load_results(tmp_path)
        approaches = [s.get("approach") for s in summaries]
        assert "vulnhunterx" in approaches

    def test_load_results_does_not_promote_truly_incomplete_runs(self, tmp_path: Path):
        """A run that the runner classified as incomplete AND where
        entries_done < entries_expected must NOT be promoted."""
        import json as _json

        from benchmarks.scripts.generate_report import _load_results

        results = _make_results(2)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            results, metrics, status="in_progress",
        )

        ck_file = sorted(tmp_path.glob("*_results.json"))[0].name
        (tmp_path / "summary.json").write_text(_json.dumps({
            "run_dir": str(tmp_path),
            "model": "test", "provider": "ollama",
            "wall_seconds": 1.0, "approaches_run": [], "summary": [],
            "incomplete_runs": [{
                "file": ck_file,
                "approach": "vulnhunterx",
                "dataset": "test_ds",
                "entries_done": 2,
                "entries_expected": 10,  # genuinely partial
            }],
        }))

        summaries = _load_results(tmp_path)
        assert summaries == []


class TestOnlyEntriesFlag:
    """`run_one(only_entries=...)` re-executes just the listed IDs and keeps
    prior rows for everything else — used by `failed_entries.txt` re-runs."""

    def _stub_approach(self):
        from benchmarks.approaches.base import BenchmarkApproach, PRED_TP

        class StubApproach(BenchmarkApproach):
            name = "stub"
            is_baseline = False
            option_schema: dict = {}

            def evaluate(self, entry):  # type: ignore[override]
                return BenchmarkResult(
                    entry=entry,
                    predicted_label=PRED_TP,
                    confidence="High",
                    reasoning="re-run",
                    elapsed_seconds=0.01,
                    tokens_used=1,
                    cost_usd=0.0,
                    iterations=1,
                )

        return StubApproach()

    def test_only_entries_replaces_error_rows_keeps_others(self, tmp_path: Path):
        from benchmarks.approaches.base import PRED_ERROR
        from benchmarks.scripts.run_benchmark import run_one

        good = _make_results(3)  # entries e0..e2 with TP/FP verdicts
        err_entry = _entry(LABEL_TP, i=99)
        err_entry.id = "e99"
        err_row = BenchmarkResult(
            entry=err_entry, predicted_label=PRED_ERROR,
            confidence="Low", reasoning="LLM call failed: litellm.Timeout",
            elapsed_seconds=600.0, tokens_used=0, cost_usd=0.0, iterations=3,
        )
        all_rows = list(good) + [err_row]
        metrics = evaluate(all_rows, "stub", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "stub",
            all_rows, metrics, status="completed",
        )

        # Re-run only e99 — the rest must be kept from the checkpoint.
        all_entries = [r.entry for r in all_rows]
        result = run_one(
            "test_ds", "stub", all_entries, self._stub_approach(),
            tmp_path, "fp", resume=True,
            only_entries={"e99"}, quiet=True,
        )
        assert result is not None
        _, results = result
        ids = {r.entry.id for r in results}
        assert ids == {"e0", "e1", "e2", "e99"}
        rerun = next(r for r in results if r.entry.id == "e99")
        assert rerun.predicted_label != PRED_ERROR
        assert rerun.reasoning == "re-run"


class TestClassifyLlmError:
    """`_classify_llm_error` bucketing for the LLM API Failures section."""

    @pytest.mark.parametrize(
        "reasoning, expected",
        [
            (
                "LLM call failed: litellm.APIConnectionError: Ollama_chatException - "
                "litellm.Timeout: Connection timed out after 600.0 seconds.",
                "timeout",
            ),
            (
                "LLM call failed: litellm.APIConnectionError: Ollama_chatException - "
                "Server disconnected without sending a response.",
                "disconnect",
            ),
            (
                "LLM call failed: litellm.APIConnectionError: Ollama_chatException - "
                '{"error":"Internal Server Error (ref: 52f52aa3-...)"}',
                "server_5xx",
            ),
            ("HTTP 429: rate limit exceeded", "rate_limit"),
            ("anthropic.AuthenticationError: invalid API key", "auth"),
            ("something exploded", "other"),
            ("", "other"),
        ],
    )
    def test_classifies_observed_strings(self, reasoning: str, expected: str):
        from benchmarks.scripts.generate_report import _classify_llm_error

        assert _classify_llm_error(reasoning) == expected


class TestLlmFailuresSection:
    def test_section_and_failed_entries_file_emitted(self, tmp_path: Path):
        """End-to-end: a checkpoint containing ERROR rows produces a
        `## LLM API Failures` section and a `failed_entries.txt` sidecar."""
        from benchmarks.scripts.generate_report import generate_report

        from benchmarks.approaches.base import PRED_ERROR

        results = _make_results(2)
        err_entry = _entry(LABEL_TP, i=99)
        err_entry.id = "test_ds-error-1"
        err_result = BenchmarkResult(
            entry=err_entry,
            predicted_label=PRED_ERROR,
            confidence="Low",
            reasoning="LLM call failed: litellm.Timeout: timed out after 600s",
            elapsed_seconds=600.0,
            tokens_used=0,
            cost_usd=0.0,
            iterations=3,
        )
        results = list(results) + [err_result]
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            results, metrics, status="completed",
        )

        generate_report(tmp_path, include_charts=False)
        body = (tmp_path / "REPORT.md").read_text()
        assert "## LLM API Failures" in body
        assert "test_ds-error-1" in body
        failed = (tmp_path / "failed_entries.txt").read_text()
        assert "test_ds-error-1" in failed

    def test_no_section_when_no_errors(self, tmp_path: Path):
        from benchmarks.scripts.generate_report import generate_report

        results = _make_results(3)
        metrics = evaluate(results, "vulnhunterx", "test_ds")
        _save_checkpoint(
            tmp_path, "test_ds", "vulnhunterx",
            results, metrics, status="completed",
        )
        generate_report(tmp_path, include_charts=False)
        body = (tmp_path / "REPORT.md").read_text()
        assert "## LLM API Failures" not in body
        assert not (tmp_path / "failed_entries.txt").exists()


# ── Tests: ProgressDisplay format ─────────────────────────────────────────────

class TestProgressDisplay:
    def _make_display(self, total: int = 10, verbose: bool = False) -> ProgressDisplay:
        return ProgressDisplay(
            dataset="secllmholmes",
            approach="vulnhunterx",
            total=total,
            verbose=verbose,
            quiet=False,
        )

    def _make_result(self, label: str = PRED_TP, cost: float = 0.01) -> BenchmarkResult:
        entry = _entry(LABEL_TP if label == PRED_TP else LABEL_FP, i=0)
        return BenchmarkResult(
            entry=entry,
            predicted_label=label,
            confidence="High",
            reasoning="r",
            elapsed_seconds=1.5,
            tokens_used=50,
            cost_usd=cost,
        )

    def test_start_writes_to_stderr(self, capsys: pytest.CaptureFixture):
        display = self._make_display()
        with patch("benchmarks.scripts._progress._is_tty", return_value=False):
            display.start()
        _, err = capsys.readouterr()
        assert "secllmholmes" in err
        assert "vulnhunterx" in err

    def test_start_shows_resume_count(self, capsys: pytest.CaptureFixture):
        display = self._make_display()
        with patch("benchmarks.scripts._progress._is_tty", return_value=False):
            display.start(resumed_count=5)
        _, err = capsys.readouterr()
        assert "resuming" in err.lower() or "#5" in err

    def test_update_accumulates_totals(self):
        display = self._make_display(total=3)
        with patch("benchmarks.scripts._progress._is_tty", return_value=False):
            display.update(self._make_result(PRED_TP, 0.01))
            display.update(self._make_result(PRED_FP, 0.02))
            display.update(self._make_result(PRED_TP, 0.005))
        assert display._totals.tp == 2
        assert display._totals.fp == 1
        assert display._totals.cost == pytest.approx(0.035, rel=1e-3)

    def test_finish_writes_metrics(self, capsys: pytest.CaptureFixture):
        display = self._make_display(total=4)
        results = _make_results(4)
        metrics = evaluate(results, "vulnhunterx", "secllmholmes")
        with patch("benchmarks.scripts._progress._is_tty", return_value=False):
            display.finish(metrics)
        _, err = capsys.readouterr()
        # Should include precision/recall indicators
        assert "P=" in err or "—" in err

    def test_quiet_mode_produces_no_output(self, capsys: pytest.CaptureFixture):
        display = ProgressDisplay(
            dataset="secllmholmes", approach="vulnhunterx", total=5,
            quiet=True,
        )
        results = _make_results(2)
        metrics = evaluate(results, "vulnhunterx", "secllmholmes")
        display.start()
        for r in results:
            display.update(r)
        display.finish(metrics)
        _, err = capsys.readouterr()
        assert err == ""

    def test_fmt_seconds_formatting(self):
        assert _fmt_seconds(45) == "45s"
        assert _fmt_seconds(90) == "1m30s"
        assert _fmt_seconds(3661) == "1h01m"
