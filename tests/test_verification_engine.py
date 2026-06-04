# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Tests for verification engine (e.g. test path exclusion)."""

from __future__ import annotations

import re

from vuln_hunter_x.core.types import Finding, Verdict, VerificationResult
from vuln_hunter_x.verification.engine import (
    VerificationEngine,
    _is_test_path,
    _verdict_filename,
)


def _make_finding(
    rule_id: str = "go/timing-unsafe-comparison",
    file: str = "pkg/utils/signature.go",
    start_line: int = 66,
    end_line: int = 66,
    message: str = "Timing attack against signature comparison.",
    dataflow_path: list[str] | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=message,
        file=file,
        start_line=start_line,
        end_line=end_line,
        repo_name="demo-repo",
        lang="go",
        dataflow_path=dataflow_path or [],
    )


class TestIsTestPath:
    """Tests for _is_test_path helper."""

    def test_tests_segment(self):
        assert _is_test_path("repo/tests/foo.c") is True
        assert _is_test_path("tests/unit/bar.py") is True
        assert _is_test_path("/abs/path/tests/baz.js") is True

    def test_test_segment(self):
        assert _is_test_path("repo/test/foo.c") is True
        assert _is_test_path("test/unit/bar.py") is True
        assert _is_test_path("/abs/path/test/baz.js") is True

    def test_file_uri(self):
        assert _is_test_path("file:///repo/tests/foo.c") is True
        assert _is_test_path("file:///repo/test/bar.py") is True

    def test_not_test_path(self):
        assert _is_test_path("src/foo.c") is False
        assert _is_test_path("contest.c") is False
        assert _is_test_path("lib/testing/helper.py") is False
        assert _is_test_path("") is False

    def test_backslash_normalized(self):
        assert _is_test_path("repo\\tests\\foo.c") is True
        assert _is_test_path("repo\\test\\bar.py") is True

    def test_spec_directory_not_matched(self):
        # spec/ is not in the default exclusion list
        assert _is_test_path("src/spec/foo.js") is False

    def test_test_word_in_filename_not_matched(self):
        # "testing_helper.py" or "contest.c" should NOT be excluded
        assert _is_test_path("src/testing/helper.py") is False
        assert _is_test_path("src/contest.c") is False
        assert _is_test_path("unittest_utils.py") is False

    def test_deeply_nested_test_dir(self):
        assert _is_test_path("a/b/c/d/tests/e/f.c") is True
        assert _is_test_path("a/b/c/d/test/e/f.c") is True


class TestVerdictFilename:
    """Tests for _verdict_filename (per-finding verdict file naming)."""

    def test_no_collision_across_files(self):
        # Same rule + start_line, different file -> distinct filenames.
        # This is the exact bug the old "{rule}_{start_line}.json" scheme had.
        a = _make_finding(file="merchant-gateway/pkg/utils/signature.go", start_line=66)
        b = _make_finding(file="token-payment/pkg/token/pci_bound.go", start_line=66)
        assert _verdict_filename(a) != _verdict_filename(b)

    def test_no_collision_across_lines(self):
        a = _make_finding(start_line=66)
        b = _make_finding(start_line=81)
        assert _verdict_filename(a) != _verdict_filename(b)

    def test_no_collision_across_dataflow(self):
        # Same rule/file/line but different dataflow -> distinct findings.
        a = _make_finding(dataflow_path=["line 10: x", "line 12: y"])
        b = _make_finding(dataflow_path=["line 20: a", "line 22: b"])
        assert _verdict_filename(a) != _verdict_filename(b)

    def test_deterministic(self):
        a = _make_finding()
        assert _verdict_filename(a) == _verdict_filename(_make_finding())

    def test_identical_findings_collapse(self):
        # Two Findings identical in every identity field share a filename.
        assert _verdict_filename(_make_finding()) == _verdict_filename(_make_finding())

    def test_filename_is_safe(self):
        fn = _verdict_filename(_make_finding(file="src/a b/weird:name*.go"))
        assert fn.endswith(".json")
        assert not fn.startswith("summary_")
        # Only filesystem-safe characters.
        assert re.fullmatch(r"[A-Za-z0-9._-]+", fn)

    def test_length_bounded_for_long_paths(self):
        long_file = "/".join(f"very-long-directory-segment-{i}" for i in range(40))
        fn = _verdict_filename(_make_finding(file=long_file))
        assert len(fn) <= 170
        assert fn.endswith(".json")

    def test_empty_fields_fallback(self):
        f = _make_finding(rule_id="", file="")
        fn = _verdict_filename(f)
        assert fn.endswith(".json")
        assert re.fullmatch(r"[A-Za-z0-9._-]+", fn)


class TestSaveResultsNoOverwrite:
    """save_results writes one file per distinct finding (regression guard)."""

    def _verdict(self, finding: Finding) -> Verdict:
        return Verdict(
            finding=finding,
            verdict="True Positive",
            confidence="High",
            reasoning="r",
            answers=[],
            raw_response="",
            model="test-model",
        )

    def test_distinct_findings_yield_distinct_files(self, tmp_path):
        findings = [
            _make_finding(file="merchant-gateway/pkg/utils/signature.go", start_line=66),
            _make_finding(file="token-payment/pkg/token/pci_bound.go", start_line=66),
            _make_finding(file="order/internal/service/order_service.go", start_line=66),
        ]
        result = VerificationResult(
            verdicts=[self._verdict(f) for f in findings],
            stats={"True Positive": 3, "False Positive": 0, "Needs More Data": 0},
            model="test-model",
            provider="test",
        )
        engine = VerificationEngine.__new__(VerificationEngine)
        engine.save_results(result, output_dir=tmp_path)

        ver_dir = tmp_path / "go" / "demo-repo" / "verification_results"
        per_finding = [p for p in ver_dir.glob("*.json") if not p.name.startswith("summary_")]
        # All three survive (old scheme would have collapsed them to one file).
        assert len(per_finding) == 3
