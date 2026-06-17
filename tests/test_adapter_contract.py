# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Lightweight contract tests for every benchmark adapter.

The bugs we fixed in DiverseVul (stringified-list `cwe_id`, empty `rule_id`)
and earlier in BenchmarkPython (`src/` vs `testcode/` layout) all share a
shape: per-entry data shipped to the LLM verifier was malformed, but nothing
caught it before the run. These tests assert the minimum invariants every
GroundTruthEntry must satisfy and run against the bundled fixtures so any
future adapter regression is caught at PR time.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.adapters.ground_truth import (
    LABEL_BENIGN,
    LABEL_FP,
    LABEL_TP,
    load_entries,
)

_FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks" / "fixtures"

_VALID_LANGS = {"c", "cpp", "python", "javascript", "java", "php", "go"}
_VALID_LABELS = {LABEL_TP, LABEL_FP, LABEL_BENIGN}


@pytest.mark.parametrize(
    "fixture",
    [
        "secllmholmes_sample.json",
        "juliet_sample.json",
        "diversevul_sample.json",
        "owasp_benchmark_sample.json",
        "realvuln_sample.json",
    ],
)
def test_adapter_contract(fixture: str):
    """Every fixture must produce well-formed entries.

    Note: a non-empty `rule_id` is *preferred* but not required at the per-
    entry level — some upstream datasets legitimately lack one for certain
    rows. The runner-level `_validate_entries` guard (run_benchmark.py)
    enforces the *aggregate* rule_id population threshold; this test is the
    per-row shape check.
    """
    path = _FIXTURES / fixture
    assert path.is_file(), f"Missing fixture: {path}"

    entries = load_entries(path)
    assert entries, f"{fixture}: fixture loaded zero entries"

    for e in entries:
        assert e.id, f"{fixture}: empty id on {e!r}"
        assert e.lang in _VALID_LANGS, f"{fixture}: bad lang {e.lang!r} on {e.id}"
        assert e.label in _VALID_LABELS, f"{fixture}: bad label {e.label!r} on {e.id}"
        # Two regressions we want to catch forever:
        if e.cwe_id:
            assert not e.cwe_id.startswith("CWE-["), (
                f"{fixture}: stringified-list cwe_id on {e.id}: {e.cwe_id!r}"
            )
            assert (
                e.cwe_id == "Unknown" or e.cwe_id.startswith("CWE-")
            ), f"{fixture}: malformed cwe_id on {e.id}: {e.cwe_id!r}"


# ── DiverseVul adapter regressions (post-fix expectations) ──────────────────

def test_diversevul_adapter_unwraps_list_cwe():
    """Source field `cwe` is a list per the DiverseVul schema. The adapter
    must unwrap it, never str()-stringify it."""
    from benchmarks.adapters.diversevul_adapter import DiverseVulAdapter

    adapter = DiverseVulAdapter("/tmp/ignored")
    record = {
        "func": "void f(){}",
        "target": 1,
        "cwe": ["CWE-119", "CWE-787"],
        "project": "p",
        "commit_id": "c",
    }
    entry = adapter._record_to_entry(record, seen_hashes=set(), cwe_filter=None)
    assert entry is not None
    assert entry.cwe_id == "CWE-119"
    assert entry.metadata["all_cwes"] == ["CWE-119", "CWE-787"]


def test_diversevul_adapter_synthesises_cpp_rule_id():
    """A populated cwe must yield a `cpp/...` rule_id via cwe_to_rules so the
    loader's exact-match path fires (instead of falling to default)."""
    from benchmarks.adapters.diversevul_adapter import DiverseVulAdapter

    adapter = DiverseVulAdapter("/tmp/ignored")
    record = {"func": "void f(){}", "target": 1, "cwe": ["CWE-416"]}
    entry = adapter._record_to_entry(record, seen_hashes=set(), cwe_filter=None)
    assert entry is not None
    assert entry.rule_id.startswith("cpp/") or entry.rule_id.startswith("c/"), entry.rule_id


def test_diversevul_adapter_handles_empty_cwe():
    """Many DiverseVul entries have `cwe: []`. The adapter must produce
    `cwe_id='Unknown'` and `rule_id=''`, not `CWE-[]`."""
    from benchmarks.adapters.diversevul_adapter import DiverseVulAdapter

    adapter = DiverseVulAdapter("/tmp/ignored")
    record = {"func": "void f(){}", "target": 1, "cwe": []}
    entry = adapter._record_to_entry(record, seen_hashes=set(), cwe_filter=None)
    assert entry is not None
    assert entry.cwe_id == "Unknown"
    assert entry.rule_id == ""
    assert entry.metadata["all_cwes"] == []


# ── Runner-level pre-flight guards ──────────────────────────────────────────

def test_validate_entries_rejects_empty_rule_id_majority():
    """When >50% of entries have empty rule_id, the runner must refuse to start.
    Uses N=25 to clear the small-sample short-circuit (min-N is 20)."""
    from benchmarks.adapters.ground_truth import GroundTruthEntry
    from benchmarks.scripts.run_benchmark import _validate_entries

    entries = [
        GroundTruthEntry(
            id=f"e{i}", source_dataset="bad",
            cwe_id="CWE-119", rule_id="" if i < 15 else "cpp/foo",
            file_path="x", function_name="f", start_line=1, lang="c",
            label=LABEL_TP, code_snippet="// ...",
        )
        for i in range(25)
    ]
    with pytest.raises(ValueError, match="empty rule_id"):
        _validate_entries("bad-adapter", entries)


def test_validate_entries_rejects_malformed_cwe_majority():
    """Stringified-list cwe_id (like 'CWE-[\\'CWE-119\\']') must be rejected
    when it dominates the dataset."""
    from benchmarks.adapters.ground_truth import GroundTruthEntry
    from benchmarks.scripts.run_benchmark import _validate_entries

    entries = [
        GroundTruthEntry(
            id=f"e{i}", source_dataset="bad",
            cwe_id="CWE-['CWE-119']" if i < 18 else "CWE-119",
            rule_id="cpp/foo",
            file_path="x", function_name="f", start_line=1, lang="c",
            label=LABEL_TP, code_snippet="// ...",
        )
        for i in range(25)
    ]
    with pytest.raises(ValueError, match="malformed cwe_id"):
        _validate_entries("bad-adapter", entries)


def test_validate_entries_passes_clean_dataset():
    """A well-formed dataset must not raise."""
    from benchmarks.adapters.ground_truth import GroundTruthEntry
    from benchmarks.scripts.run_benchmark import _validate_entries

    entries = [
        GroundTruthEntry(
            id=f"e{i}", source_dataset="good",
            cwe_id="CWE-119", rule_id="cpp/overflow-buffer",
            file_path="x", function_name="f", start_line=1, lang="c",
            label=LABEL_TP, code_snippet="// ...",
        )
        for i in range(25)
    ]
    _validate_entries("good-adapter", entries)  # no raise


def test_validate_entries_skips_small_samples():
    """N<20 sample sizes short-circuit — too noisy to gate on."""
    from benchmarks.adapters.ground_truth import GroundTruthEntry
    from benchmarks.scripts.run_benchmark import _validate_entries

    entries = [
        GroundTruthEntry(
            id=f"e{i}", source_dataset="tiny",
            cwe_id="CWE-119", rule_id="",  # 100% empty rule_id but only 5 entries
            file_path="x", function_name="f", start_line=1, lang="c",
            label=LABEL_TP, code_snippet="// ...",
        )
        for i in range(5)
    ]
    _validate_entries("tiny-smoke", entries)  # no raise


# ── Report renderer regressions ─────────────────────────────────────────────

def test_clean_cwe_unwraps_stringified_list():
    """The report cleaner must rescue cwe ids from older runs that have the
    pre-fix DiverseVul `CWE-['CWE-119']` shape."""
    from benchmarks.scripts.generate_report import _clean_cwe

    assert _clean_cwe("CWE-['CWE-119']") == "CWE-119"
    assert _clean_cwe("CWE-[]") == "Unknown"
    assert _clean_cwe("CWE-119") == "CWE-119"
    assert _clean_cwe("") == "Unknown"
    assert _clean_cwe("Unknown") == "Unknown"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
