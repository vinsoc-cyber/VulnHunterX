# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for verification engine (e.g. test path exclusion)."""

from __future__ import annotations

import re

from vuln_hunter_x.core.types import Finding, Verdict, VerificationResult
from vuln_hunter_x.verification.engine import (
    VerificationEngine,
    _downgrade_local_prototype_pollution,
    _is_nonproduction_path,
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
    cwe_ids: list[str] | None = None,
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
        cwe_ids=cwe_ids or [],
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


class TestIsNonProductionPath:
    """Tests for _is_nonproduction_path (flag, not drop)."""

    def test_test_bench_fuzz_stems(self):
        assert _is_nonproduction_path("test_foo.c") is True
        assert _is_nonproduction_path("src/foo_test.c") is True
        assert _is_nonproduction_path("src/decode_fuzzer.c") is True
        assert _is_nonproduction_path("benches/bench_main.c") is True

    def test_explicit_harness_filenames(self):
        # libjpeg-turbo harnesses live directly in src/ with no test/ segment
        assert _is_nonproduction_path("src/tjunittest.c") is True
        assert _is_nonproduction_path("src/tjbench.c") is True
        assert _is_nonproduction_path("src/tjdecomp.c") is True

    def test_vendored_segments(self):
        assert _is_nonproduction_path("src/spng/zlib/zutil.c") is True
        assert _is_nonproduction_path("third_party/foo/bar.c") is True
        assert _is_nonproduction_path("deps/zlib/inflate.c") is True

    def test_production_code_not_matched(self):
        assert _is_nonproduction_path("src/jdlhuff.c") is False
        assert _is_nonproduction_path("src/jidctint.c") is False
        assert _is_nonproduction_path("parser.c") is False
        assert _is_nonproduction_path("") is False

    def test_does_not_overmatch_production_lookalikes(self):
        # Must not match production files that merely contain the substring.
        assert _is_nonproduction_path("src/contest.c") is False
        assert _is_nonproduction_path("unittest_utils.py") is False
        assert _is_nonproduction_path("src/attestation.c") is False

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


class TestCategoryFilterLoads:
    """Regression: the engine must load rule_categories.yaml so --category
    filtering works. It previously referenced a non-existent
    PathsConfig.base_dir, the bare except swallowed the AttributeError, and
    --category became a silent no-op (every finding processed unfiltered)."""

    def _engine(self):
        from vuln_hunter_x.core.config import load_config
        return VerificationEngine(load_config())

    def test_profile_manager_loads(self):
        engine = self._engine()
        assert engine._profile_manager is not None

    def test_file_security_category_resolves_to_cwes(self):
        engine = self._engine()
        cwes = engine._profile_manager.get_cwes_for_categories(["file-security"])
        # canonical zero-stripped ids (see _normalize_cwe) — CWE-22, not CWE-022
        assert "CWE-22" in cwes

    def test_filter_keeps_only_matching_cwes(self):
        engine = self._engine()
        target = engine._profile_manager.get_cwes_for_categories(["file-security"])
        findings = [
            _make_finding(file="src/cjpeg.c", start_line=741, cwe_ids=["CWE-22", "CWE-73"]),
            _make_finding(file="src/jidctint.c", start_line=234, cwe_ids=["CWE-190"]),
        ]
        kept = [f for f in findings if not f.cwe_ids or target.intersection(f.cwe_ids)]
        assert [f.file for f in kept] == ["src/cjpeg.c"]


class TestBuildPrefetchRequests:
    """_build_prefetch_requests maps additional_context hints to request strings."""

    def test_caller_hint(self):
        reqs = VerificationEngine._build_prefetch_requests(["caller"], "wrap")
        assert reqs == ["caller:wrap"]

    def test_callees_hint_maps_to_callee_bodies(self):
        # The 'callees' hint must prefetch BODIES (not just names) so the sink
        # helper implementation is present on turn 1.
        reqs = VerificationEngine._build_prefetch_requests(["caller", "callees"], "wrap")
        assert reqs == ["caller:wrap", "callee_bodies:wrap"]

    def test_callee_bodies_hint(self):
        reqs = VerificationEngine._build_prefetch_requests(["callee_bodies"], "wrap")
        assert reqs == ["callee_bodies:wrap"]

    def test_empty_func_name_yields_no_requests(self):
        assert VerificationEngine._build_prefetch_requests(["caller", "callees"], "") == []

    def test_class_hint_is_not_prefetched(self):
        # 'class' needs a specific type name, so it stays reactive (not prefetched).
        reqs = VerificationEngine._build_prefetch_requests(["caller", "class"], "fn")
        assert reqs == ["caller:fn"]


class _Ctx:
    """Minimal CodeContext stand-in for _extract_sink_callees tests."""
    def __init__(self, code, start_line, end_line):
        self.code = code
        self.start_line = start_line
        self.end_line = end_line


class TestExtractSinkCallees:
    def test_extracts_method_call_on_sink_line(self):
        code = (
            "async wrap(key) {\n"            # line 86
            "  const cached = await this.get(key);\n"  # 87
            "  if (cached) return cached;\n"  # 88
            "  const result = await fn();\n"  # 89
            "  await this.set<T>(key, result, ttl, options);\n"  # 90
            "}\n"
        )
        f = _make_finding(rule_id="js/prototype-pollution", file="cache.ts", start_line=90, end_line=90)
        callees = VerificationEngine._extract_sink_callees(f, _Ctx(code, 86, 91))
        assert callees == ["set"]

    def test_skips_control_flow_keywords(self):
        code = "fn() {\n  if (cond) doThing(x);\n}\n"
        f = _make_finding(file="a.ts", start_line=2, end_line=2)
        callees = VerificationEngine._extract_sink_callees(f, _Ctx(code, 1, 3))
        assert "if" not in callees
        assert "doThing" in callees

    def test_returns_empty_when_sink_line_out_of_range(self):
        f = _make_finding(file="a.ts", start_line=999, end_line=999)
        assert VerificationEngine._extract_sink_callees(f, _Ctx("fn() {}\n", 1, 1)) == []

    def test_returns_empty_without_context(self):
        f = _make_finding(file="a.ts", start_line=5, end_line=5)
        assert VerificationEngine._extract_sink_callees(f, _Ctx("", 0, 0)) == []


class TestBuildPrefetchRequestsFramework:
    """Framework context hints map to repo-grep request strings."""

    def test_framework_sanitizers_hint(self):
        reqs = VerificationEngine._build_prefetch_requests(
            ["caller", "framework_sanitizers"], "createFromSfsc"
        )
        assert "framework_sanitizers:repo" in reqs

    def test_framework_guards_hint(self):
        reqs = VerificationEngine._build_prefetch_requests(
            ["framework_guards"], "handler"
        )
        assert reqs == ["framework_guards:repo"]


class TestExtractSourceTypes:
    """_extract_source_types resolves the DTO type of the taint source."""

    def test_resolves_dto_type_from_signature(self):
        code = (
            "async createFromSfsc(dto: CreateRescueDto) {\n"
            "  const req = Object.assign(new RescueRequest(), { ...dto });\n"
            "}\n"
        )
        f = _make_finding(
            rule_id="js/prototype-pollution-ext",
            file="rescue.service.ts",
            start_line=2,
            end_line=2,
            dataflow_path=["line 1: dto", "line 2: dto"],
        )
        types = VerificationEngine._extract_source_types(f, _Ctx(code, 1, 3))
        assert types == ["CreateRescueDto"]

    def test_skips_builtin_types(self):
        code = "function f(name: string, count: number) {\n  return name[count];\n}\n"
        f = _make_finding(
            file="a.ts", start_line=2, end_line=2,
            dataflow_path=["line 1: name", "line 1: count"],
        )
        assert VerificationEngine._extract_source_types(f, _Ctx(code, 1, 3)) == []

    def test_empty_without_dataflow(self):
        code = "function f(dto: SomeDto) {}\n"
        f = _make_finding(file="a.ts", start_line=1, end_line=1, dataflow_path=[])
        assert VerificationEngine._extract_source_types(f, _Ctx(code, 1, 2)) == []


def _make_verdict(finding, verdict, confidence, reasoning, score=0.9):
    return Verdict(
        finding=finding,
        verdict=verdict,
        confidence=confidence,
        reasoning=reasoning,
        answers=[],
        raw_response="",
        model="test",
        confidence_score=score,
    )


class TestDowngradeLocalPrototypePollution:
    """TP prototype-pollution verdicts that are only LOCAL must not ride High."""

    def _pp_finding(self):
        return _make_finding(
            rule_id="js/prototype-pollution-ext",
            file="rescue.service.ts",
            start_line=287,
            end_line=287,
            cwe_ids=["CWE-1321"],
        )

    def test_local_only_is_downgraded(self):
        v = _make_verdict(
            self._pp_finding(), "True Positive", "High",
            "An attacker can set __proto__ on the instance (local prototype "
            "pollution), changing its prototype chain.",
        )
        out = _downgrade_local_prototype_pollution(v)
        assert out.confidence == "Low"
        assert out.confidence_score <= 0.3
        assert "LOCAL instance prototype" in out.reasoning

    def test_global_pollution_is_preserved(self):
        v = _make_verdict(
            self._pp_finding(), "True Positive", "High",
            "User key reaches obj[key]=val and pollutes Object.prototype "
            "globally, affecting all objects.",
        )
        out = _downgrade_local_prototype_pollution(v)
        assert out.confidence == "High"

    def test_non_prototype_rule_untouched(self):
        f = _make_finding(rule_id="js/sql-injection", cwe_ids=["CWE-89"])
        v = _make_verdict(f, "True Positive", "High", "local instance prototype only")
        out = _downgrade_local_prototype_pollution(v)
        assert out.confidence == "High"

    def test_false_positive_untouched(self):
        v = _make_verdict(
            self._pp_finding(), "False Positive", "High",
            "local prototype pollution only",
        )
        out = _downgrade_local_prototype_pollution(v)
        assert out.confidence == "High"
