"""P0 (#125): explicit real-anchor semantics for benchmark ground truth.

A line-aware verifier must not be fed a fabricated ``line 1`` anchor for
function-granularity datasets. Entries carry an explicit optional ``sink_line``
(the real scanner-derived flagged line); its absence means the entry is
line-unanchored and must be excluded from line-anchored verifier approaches.
"""
from __future__ import annotations

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry, LABEL_TP


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
