# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P3b Task 3 — verify-once + projection at the engine seam (#122).

Genuine exact-duplicate observations are verified with ONE model invocation and
the single decision is projected back to one verdict per observation (each keeps
its own reported finding + a shared case_id). Snippet-less findings never merge;
policy-routed findings stay one-to-one. Deterministic (mocked LLM), serial.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

from vuln_hunter_x.core.types import Finding, Verdict, VerdictType
from vuln_hunter_x.verification import engine as eng

# Source whose line 3 contains the flagged construct → anchors resolve `exact`.
_SOURCE = "<?php\n$id = $_GET['x'];\nfile_get_contents($id);\n"


def _finding(*, tool, snippet="file_get_contents($id);", rule="tainted-filename",
             file="a/b.php", line=3, lang="php"):
    return Finding(rule_id=rule, message="m", file=file, start_line=line,
                   end_line=line, repo_name="repo", lang=lang, tool=tool,
                   sink_snippet=snippet, start_column=1, end_column=5)


def _stub_engine(source, analyze_calls):
    """A VerificationEngine stubbed down to the verify-once loop seam."""
    e = eng.VerificationEngine.__new__(eng.VerificationEngine)
    e._jobs = 1
    e._callback_lock = threading.Lock()
    e._on_finding_start = None
    e._on_finding_complete = None
    e._log_fh = None
    e._policy_registry = MagicMock(families=[])  # no policy → all legacy

    e.questions_loader = MagicMock()
    e.questions_loader.get_questions.return_value = MagicMock(
        additional_context=[], min_iterations=1, rule_id="tainted-filename",
    )
    ctx = MagicMock(code="file_get_contents($id);", function_name="", start_line=3)
    e.context_extractor = MagicMock()
    e.context_extractor.get_context.return_value = ctx
    e.context_extractor.read_source.return_value = source
    e.context_provider = MagicMock()

    def _analyze(**kwargs):
        analyze_calls.append(kwargs["finding"])
        f = kwargs["finding"]
        return Verdict(finding=f, verdict=VerdictType.NEEDS_MORE_DATA.value,
                       confidence="Low", reasoning="stub", answers=[],
                       raw_response="", model="gpt-test", confidence_score=0.3)

    e.llm_client = MagicMock()
    e.llm_client.analyze.side_effect = _analyze

    e.config = MagicMock()
    e.config.verification.self_consistency_samples = 1
    e.config.verification.max_iterations = 1
    e.config.verification.force_decision = False
    e.config.output.is_verbose = False
    e.config.output.is_quiet = True
    e.config.llm.model = "gpt-test"
    e.config.llm.provider = "test"
    return e


def test_exact_duplicate_verified_once_and_projected():
    calls = []
    e = _stub_engine(_SOURCE, calls)
    a = _finding(tool="semgrep")
    b = _finding(tool="opengrep")  # identical sink, different tool
    result = e.verify_findings([a, b])
    # Only the representative (a, lower index) is analyzed; b is projected.
    assert any(f is a for f in calls)
    assert not any(f is b for f in calls)
    assert len(result.verdicts) == 2
    assert result.verdicts[0].verdict == result.verdicts[1].verdict
    assert result.verdicts[0].case_id == result.verdicts[1].case_id != ""
    # Each projection keeps its own reported observation.
    assert [v.finding.tool for v in result.verdicts] == ["semgrep", "opengrep"]


def test_snippetless_findings_not_merged():
    calls = []
    e = _stub_engine(_SOURCE, calls)
    a = _finding(tool="semgrep", snippet="")
    b = _finding(tool="opengrep", snippet="")
    result = e.verify_findings([a, b])
    assert any(f is a for f in calls) and any(f is b for f in calls)  # both analyzed
    assert len(result.verdicts) == 2
    assert result.verdicts[0].case_id == "" and result.verdicts[1].case_id == ""


def test_output_order_preserved_with_mixed_dups():
    calls = []
    e = _stub_engine(_SOURCE, calls)
    a = _finding(tool="semgrep")                          # case 1
    other = _finding(tool="semgrep", rule="other-rule")   # distinct obligation
    b = _finding(tool="opengrep")                         # duplicate of a
    result = e.verify_findings([a, other, b])
    assert len(result.verdicts) == 3
    assert [v.finding.rule_id for v in result.verdicts] == [
        "tainted-filename", "other-rule", "tainted-filename"]
    assert result.verdicts[0].case_id == result.verdicts[2].case_id != ""
    assert result.verdicts[1].case_id == ""
    assert not any(f is b for f in calls)  # b still projected, never analyzed


def test_policy_routed_findings_stay_singletons():
    calls = []
    e = _stub_engine(_SOURCE, calls)
    reg = MagicMock(families=[object()])
    reg.resolve_family.return_value = object()  # a policy family selects the rule
    e._policy_registry = reg
    cases = e._cases_for([_finding(tool="semgrep"), _finding(tool="opengrep")])
    assert len(cases) == 2  # never merged — policy findings are one-to-one
    assert all(len(c.observation_indices) == 1 and c.case_id == "" for c in cases)


def test_verdict_case_id_roundtrips():
    v = Verdict(finding=_finding(tool="semgrep"), verdict="True Positive",
                confidence="High", reasoning="r", answers=[], raw_response="",
                model="m", case_id="abc123def456")
    d = v.to_dict()
    assert d["case_id"] == "abc123def456"
    assert Verdict.from_dict(d).case_id == "abc123def456"


def test_verdict_case_id_defaults_empty_and_roundtrips():
    v = Verdict(finding=_finding(tool="semgrep"), verdict="True Positive",
                confidence="High", reasoning="r", answers=[], raw_response="", model="m")
    assert v.case_id == ""
    assert Verdict.from_dict(v.to_dict()).case_id == ""
