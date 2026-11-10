"""P0 (#125): explicit real-anchor semantics for benchmark ground truth.

A line-aware verifier must not be fed a fabricated ``line 1`` anchor for
function-granularity datasets. Entries carry an explicit optional ``sink_line``
(the real scanner-derived flagged line); its absence means the entry is
line-unanchored and must be excluded from line-anchored verifier approaches.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.adapters.ground_truth import LABEL_TP, GroundTruthEntry, load_entries
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
    "diversevul_sample.json", "juliet_sample.json",
    "owasp_benchmark_sample.json", "secllmholmes_sample.json",
    "security-rules_sample.json",
])
def test_function_granularity_fixtures_are_unanchored(fixture):
    entries = load_entries(_FIXTURES / fixture)
    assert entries, f"{fixture} must be non-empty"
    assert all(not e.is_line_anchored for e in entries)


# ── Task 4: line-anchored approaches exclude unanchored entries ────────────
class _StubApproach:
    def __init__(self, line_anchored: bool) -> None:
        self.line_anchored = line_anchored


def test_benchmark_approach_default_not_line_anchored():
    from benchmarks.approaches.base import BenchmarkApproach
    assert BenchmarkApproach.line_anchored is False


def test_verifier_approaches_are_line_anchored():
    from benchmarks.approaches.ablation import AblationGenericApproach, AblationZeroApproach
    from benchmarks.approaches.raw_sast import RawSastApproach
    from benchmarks.approaches.vulnhunterx import VulnHunterXApproach
    assert VulnHunterXApproach.line_anchored is True
    assert AblationGenericApproach.line_anchored is True
    assert AblationZeroApproach.line_anchored is True
    assert RawSastApproach.line_anchored is False  # raw-sast doesn't run the line-aware verifier


def test_filter_drops_unanchored_for_line_anchored_approach():
    from benchmarks.approaches.base import filter_for_approach
    entries = [_entry(id="a", sink_line=10), _entry(id="b", sink_line=None), _entry(id="c", sink_line=20)]
    kept, dropped = filter_for_approach(entries, _StubApproach(True))
    assert [e.id for e in kept] == ["a", "c"]
    assert dropped == 1


def test_filter_keeps_all_for_non_line_anchored_approach():
    from benchmarks.approaches.base import filter_for_approach
    entries = [_entry(id="a", sink_line=None), _entry(id="b", sink_line=10)]
    kept, dropped = filter_for_approach(entries, _StubApproach(False))
    assert len(kept) == 2 and dropped == 0


# ── Task 5: end-to-end — line-anchored panel has zero fabricated line-1 anchors ─
def test_e2e_function_granularity_dataset_fully_excluded():
    """secllmholmes (all line-1) is entirely excluded for the real VulnHunterX
    approach, so no fabricated line-1 anchor ever reaches the verifier (#125)."""
    from benchmarks.approaches.base import filter_for_approach
    from benchmarks.approaches.vulnhunterx import VulnHunterXApproach

    sec = load_entries(_FIXTURES / "secllmholmes_sample.json")
    kept, dropped = filter_for_approach(sec, VulnHunterXApproach)
    assert kept == [] and dropped == len(sec)
    # And forcing an unanchored entry through would be rejected, never fabricated:
    with pytest.raises(ValueError, match="line-unanchored"):
        entry_to_finding(sec[0])


def test_e2e_realvuln_entries_flow_through_with_real_anchors():
    """RealVuln (real lines) is kept and every entry yields a Finding anchored
    on its real sink line — never line 1 (#125)."""
    from benchmarks.approaches.base import filter_for_approach
    from benchmarks.approaches.vulnhunterx import VulnHunterXApproach

    rv = load_entries(_FIXTURES / "realvuln_sample.json")
    kept, dropped = filter_for_approach(rv, VulnHunterXApproach)
    assert dropped == 0 and len(kept) == len(rv)
    for e in kept:
        f = entry_to_finding(e)  # must not raise
        assert f.start_line == e.sink_line
        assert f.start_line != 1  # realvuln fixture lines are all real (15,25,42,60,88)


# ── Scanner-derived anchoring: opengrep gives real sink lines (#125 fix) ────
def _fake_finding(file: str, line: int, cwes: list[str], rule: str = "r1") -> dict:
    return {"file": file, "line": line, "rule_id": rule, "message": f"msg@{line}", "cwes": cwes}


def _make_dataset(tmp_path: Path, files: list[str]) -> Path:
    for rel in files:
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("x = 1\n", encoding="utf-8")
    return tmp_path


def test_anchor_strict_requires_cwe_aligned_finding(tmp_path, monkeypatch):
    from benchmarks.adapters import scanner_anchor

    root = _make_dataset(tmp_path, ["a.py", "b.py", "c.py"])
    canned = {
        "a.py": [_fake_finding("a.py", 12, ["CWE-79"])],   # aligned → anchors
        "b.py": [_fake_finding("b.py", 7, ["CWE-676"])],   # misaligned → dropped (strict)
        # c.py: no findings → dropped
    }
    monkeypatch.setattr(
        scanner_anchor, "_run_opengrep",
        lambda binary, dataset_root, rel_files, lang: [
            f for rel in rel_files for f in canned.get(rel, [])
        ],
    )
    monkeypatch.setattr(scanner_anchor, "opengrep_binary", lambda: "opengrep")

    entries = [
        _entry(id="a", file_path="a.py", lang="python", cwe_id="CWE-79"),
        _entry(id="b", file_path="b.py", lang="python", cwe_id="CWE-79"),
        _entry(id="c", file_path="c.py", lang="python", cwe_id="CWE-79"),
    ]
    kept, stats = scanner_anchor.anchor_entries(entries, root, alignment="strict", use_cache=False)

    assert [e.id for e in kept] == ["a"]
    assert kept[0].sink_line == 12
    assert kept[0].metadata["message"] == "msg@12"
    assert kept[0].metadata["anchor_tool"] == "opengrep"
    assert kept[0].metadata["rule_aligned"] is True
    assert stats.anchored_aligned == 1
    assert stats.dropped_misaligned == 1
    assert stats.dropped_no_finding == 1


def test_anchor_any_keeps_misaligned_and_marks_it(tmp_path, monkeypatch):
    from benchmarks.adapters import scanner_anchor

    root = _make_dataset(tmp_path, ["b.py"])
    monkeypatch.setattr(
        scanner_anchor, "_run_opengrep",
        lambda *a, **kw: [_fake_finding("b.py", 7, ["CWE-676"])],
    )
    monkeypatch.setattr(scanner_anchor, "opengrep_binary", lambda: "opengrep")

    kept, stats = scanner_anchor.anchor_entries(
        [_entry(id="b", file_path="b.py", lang="python", cwe_id="CWE-79")],
        root, alignment="any", use_cache=False,
    )
    assert len(kept) == 1
    assert kept[0].sink_line == 7
    assert kept[0].metadata["rule_aligned"] is False
    assert stats.anchored_misaligned == 1


def test_anchor_prefers_aligned_over_earlier_misaligned(tmp_path, monkeypatch):
    from benchmarks.adapters import scanner_anchor

    root = _make_dataset(tmp_path, ["a.py"])
    monkeypatch.setattr(
        scanner_anchor, "_run_opengrep",
        lambda *a, **kw: [
            _fake_finding("a.py", 3, ["CWE-676"]),
            _fake_finding("a.py", 20, ["CWE-79"]),
        ],
    )
    monkeypatch.setattr(scanner_anchor, "opengrep_binary", lambda: "opengrep")

    kept, _ = scanner_anchor.anchor_entries(
        [_entry(id="a", file_path="a.py", lang="python", cwe_id="CWE-79")],
        root, alignment="any", use_cache=False,
    )
    assert kept[0].sink_line == 20
    assert kept[0].metadata["rule_aligned"] is True


def test_anchor_passes_pre_anchored_entries_through(tmp_path, monkeypatch):
    from benchmarks.adapters import scanner_anchor

    root = _make_dataset(tmp_path, [])
    monkeypatch.setattr(scanner_anchor, "opengrep_binary", lambda: "opengrep")
    calls: list = []
    monkeypatch.setattr(scanner_anchor, "_run_opengrep", lambda *a, **kw: calls.append(a) or [])

    e = _entry(id="pre", sink_line=42)
    kept, stats = scanner_anchor.anchor_entries([e], root, use_cache=False)
    assert kept == [e] and e.sink_line == 42
    assert stats.pre_anchored == 1
    assert not calls  # nothing to scan


def test_anchor_missing_binary_raises(tmp_path, monkeypatch):
    from benchmarks.adapters import scanner_anchor

    monkeypatch.setattr(scanner_anchor, "opengrep_binary", lambda: None)
    with pytest.raises(FileNotFoundError, match="opengrep"):
        scanner_anchor.anchor_entries([_entry()], tmp_path, use_cache=False)


def test_anchor_cache_avoids_rescan(tmp_path, monkeypatch):
    from benchmarks.adapters import scanner_anchor

    root = _make_dataset(tmp_path, ["a.py"])
    monkeypatch.setattr(scanner_anchor, "opengrep_binary", lambda: "opengrep")
    calls = {"n": 0}

    def fake_run(binary, dataset_root, rel_files, lang):
        calls["n"] += 1
        return [_fake_finding("a.py", 12, ["CWE-79"])]

    monkeypatch.setattr(scanner_anchor, "_run_opengrep", fake_run)

    def _fresh():
        return [_entry(id="a", file_path="a.py", lang="python", cwe_id="CWE-79")]

    kept1, s1 = scanner_anchor.anchor_entries(_fresh(), root, use_cache=True)
    kept2, s2 = scanner_anchor.anchor_entries(_fresh(), root, use_cache=True)
    assert calls["n"] == 1
    assert not s1.cache_hit and s2.cache_hit
    assert kept1[0].sink_line == kept2[0].sink_line == 12


# ── run_one refuses to score an empty pair (no FP-Reduction 100% on n=0) ───
def test_run_one_skips_zero_entry_pair_without_checkpoint(tmp_path):
    from benchmarks.scripts.run_benchmark import run_one

    class _Anchored:
        name = "vulnhunterx"
        line_anchored = True

        def evaluate(self, entry):  # pragma: no cover — must never be called
            raise AssertionError("evaluate() called on an empty pair")

    result = run_one(
        "secllmholmes", "vulnhunterx",
        [_entry(sink_line=None)],  # filtered out → pair is empty
        _Anchored(), tmp_path, "exclude", resume=False,
    )
    assert result is None
    assert not list(tmp_path.glob("*_results.json"))  # no bogus checkpoint


# ── zero-entry metrics render as None, never as a perfect score ─────────────
def test_empty_run_reports_no_fp_reduction():
    from benchmarks.metrics.evaluator import evaluate

    m = evaluate([], "vulnhunterx", "secllmholmes", "exclude")
    assert m.fp_reduction_rate(126) is None
    assert m.tp_preservation_rate(138) is None
    assert m.fp_reduction_ci(126) is None
