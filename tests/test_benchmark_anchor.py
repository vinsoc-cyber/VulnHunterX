"""P0 (#125): explicit real-anchor semantics for benchmark ground truth.

A line-aware verifier must not be fed a fabricated ``line 1`` anchor for
function-granularity datasets. Entries carry an explicit optional ``sink_line``
(the real scanner-derived flagged line); its absence means the entry is
line-unanchored and must be excluded from line-anchored verifier approaches.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry, LABEL_TP, load_entries
from benchmarks.approaches.base import entry_to_finding

_FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks" / "fixtures"


def _entry(**kw) -> GroundTruthEntry:
    base = dict(
        id="e1", source_dataset="secllmholmes", cwe_id="CWE-79", rule_id="",
        file_path="a.c", function_name="f", start_line=1, lang="c",
        label=LABEL_TP, code_snippet="x",
    )
    base.update(kw)
    return GroundTruthEntry(**base)


# ── Task 1: explicit sink_line anchor on GroundTruthEntry ──────────────────
def test_default_is_line_unanchored():
    e = _entry()
    assert e.sink_line is None
    assert e.is_line_anchored is False


def test_sink_line_anchors_and_roundtrips():
    e = _entry(sink_line=42)
    assert e.is_line_anchored is True
    assert GroundTruthEntry.from_dict(e.to_dict()).sink_line == 42


def test_legacy_json_without_sink_line_loads():
    d = _entry().to_dict()
    d.pop("sink_line", None)
    assert GroundTruthEntry.from_dict(d).sink_line is None


# ── Task 2: entry_to_finding anchors on sink_line, refuses to fabricate ────
def test_entry_to_finding_uses_sink_line():
    f = entry_to_finding(_entry(sink_line=42, file_path="a.c"))
    assert f.start_line == 42
    assert f.end_line == 42


def test_entry_to_finding_rejects_unanchored():
    with pytest.raises(ValueError, match="line-unanchored"):
        entry_to_finding(_entry(sink_line=None))


# ── Task 3: adapters set anchors honestly (RealVuln real; the 6 unanchored) ─
def test_realvuln_fixture_is_line_anchored():
    entries = load_entries(_FIXTURES / "realvuln_sample.json")
    assert entries, "realvuln fixture must be non-empty"
    assert all(e.is_line_anchored for e in entries)
    assert all(e.sink_line == e.start_line for e in entries)


@pytest.mark.parametrize("fixture", [
    "diversevul_sample.json", "juliet_sample.json", "openvuln_sample.json",
    "owasp_benchmark_sample.json", "secllmholmes_sample.json",
    "security-rules_sample.json",
])
def test_function_granularity_fixtures_are_unanchored(fixture):
    entries = load_entries(_FIXTURES / fixture)
    assert entries, f"{fixture} must be non-empty"
    assert all(not e.is_line_anchored for e in entries)
