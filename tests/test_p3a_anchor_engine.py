# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P3a — structured observation + anchor fidelity (closes #118).

Covers the reported-snippet retention, the re-aligned analysis anchor, the
structural-gate Needs-More-Data for unplaceable anchors, and finalizer isolation.
Deterministic — no LLM.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from vuln_hunter_x.context.anchor import ABSENT, REANCHORED_UNIQUE
from vuln_hunter_x.core.types import Finding, Verdict, VerdictType
from vuln_hunter_x.sarif.parser import SarifParser
from vuln_hunter_x.verification import engine as eng


# --------------------------------------------------------------------------- #
# Task 1 — reported snippet retention
# --------------------------------------------------------------------------- #
def test_finding_snippet_fields_default_empty_and_roundtrip():
    f = Finding(
        rule_id="cpp/double-free", message="m", file="imgRead.c",
        start_line=62, end_line=62, repo_name="dvcp", lang="cpp",
    )
    assert f.sink_snippet == ""
    assert f.start_column == 0 and f.end_column == 0

    f2 = Finding(
        rule_id="cpp/double-free", message="m", file="imgRead.c",
        start_line=62, end_line=62, repo_name="dvcp", lang="cpp",
        sink_snippet="free(buff1);", start_column=5, end_column=17,
    )
    restored = Finding.from_dict(f2.to_dict())
    assert restored.sink_snippet == "free(buff1);"
    assert restored.start_column == 5 and restored.end_column == 17


def _write_sarif(tmp_path: Path, region: dict) -> Path:
    doc = {
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": [
                {"id": "cpp/double-free",
                 "properties": {"tags": ["external/cwe/cwe-415"]}}
            ]}},
            "results": [{
                "ruleId": "cpp/double-free",
                "message": {"text": "double free of buff1"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "imgRead.c"},
                    "region": region,
                }}],
            }],
        }],
    }
    p = tmp_path / "codeql.sarif"
    p.write_text(json.dumps(doc))
    return p


def test_parser_retains_region_snippet(tmp_path):
    p = _write_sarif(tmp_path, {
        "startLine": 34, "startColumn": 5, "endColumn": 17,
        "snippet": {"text": "free(buff1);"},
    })
    findings = SarifParser(p).parse_findings("cpp", "dvcp")
    assert findings[0].sink_snippet == "free(buff1);"
    assert findings[0].start_column == 5 and findings[0].end_column == 17


def test_parser_snippet_absent_is_empty(tmp_path):
    p = _write_sarif(tmp_path, {"startLine": 34})
    findings = SarifParser(p).parse_findings("cpp", "dvcp")
    assert findings[0].sink_snippet == ""


# --------------------------------------------------------------------------- #
# Task 3/4 — anchor wiring in the legacy verify path
# --------------------------------------------------------------------------- #
def _nmd_verdict(finding):
    return Verdict(
        finding=finding, verdict=VerdictType.NEEDS_MORE_DATA.value,
        confidence="Low", reasoning="model", answers=[], raw_response="",
        model="gpt-test", iterations=1,
    )


def _legacy_engine(source, capture):
    """A VerificationEngine stubbed down to the legacy verify seam."""
    e = eng.VerificationEngine.__new__(eng.VerificationEngine)
    e.questions_loader = MagicMock()
    e.questions_loader.get_questions.return_value = MagicMock(
        additional_context=[], min_iterations=1, rule_id="cpp/double-free",
    )

    ctx = MagicMock(code="free(buff1);", function_name="ProcessImage", start_line=3)

    def _get_context(file, line, lang, repo_name=""):
        capture["ctx_line"] = line
        return ctx

    e.context_extractor = MagicMock()
    e.context_extractor.get_context.side_effect = _get_context
    e.context_extractor.read_source.return_value = source

    e.context_provider = MagicMock()

    def _analyze(**kwargs):
        capture["analyze_kwargs"] = kwargs
        return _nmd_verdict(kwargs["finding"])

    e.llm_client = MagicMock()
    e.llm_client.analyze.side_effect = _analyze
    e._log_fh = None

    e.config = MagicMock()
    e.config.verification.self_consistency_samples = 1
    e.config.verification.max_iterations = 1
    e.config.verification.force_decision = False
    e.config.output.is_verbose = False
    e.config.output.is_quiet = True
    e.config.llm.model = "gpt-test"
    return e


def _f(file, line, snippet="", lang="cpp"):
    return Finding(
        rule_id="cpp/double-free", message="m", file=file, start_line=line,
        end_line=line, repo_name="dvcp", lang=lang, sink_snippet=snippet,
    )


def test_reanchor_uses_resolved_line_and_notes_shift():
    src = (
        "void ProcessImage() {\n"
        "  char *buff1 = malloc(n);\n"
        "  free(buff1);\n"            # 3  <- the unique free
        "  int size3 = get();\n"
        "  char OOBR = buff3[size3];\n"  # 5  <- reported
        "  puts(buff1);\n"
        "}\n"
    )
    capture: dict = {}
    e = _legacy_engine(src, capture)
    f = _f("imgRead.c", 5, "free(buff1);")
    v = e._verify_legacy_finding(f)
    assert capture["ctx_line"] == 3                      # re-anchored
    note = capture["analyze_kwargs"]["prefetched_context"]
    assert any("re-aligned" in k for k in note)          # shift disclosed to model
    assert v.decision_source == "legacy_model"           # normal model path
    assert f.start_line == 5                             # reported anchor untouched


def test_exact_anchor_is_neutral():
    capture: dict = {}
    e = _legacy_engine("a\nb\nfree(buff1);\n", capture)
    e._verify_legacy_finding(_f("imgRead.c", 3, "free(buff1);"))
    assert capture["ctx_line"] == 3
    note = capture["analyze_kwargs"]["prefetched_context"]
    assert not any("re-aligned" in k for k in note)


def test_snippetless_finding_does_no_source_read():
    capture: dict = {}
    e = _legacy_engine("unused\n", capture)
    e._verify_legacy_finding(_f("imgRead.c", 42))        # no snippet
    assert capture["ctx_line"] == 42                     # unchanged
    e.context_extractor.read_source.assert_not_called()  # neutral, no IO


def test_verdict_anchor_fields_roundtrip():
    f = _f("a.c", 1)
    v = Verdict(
        finding=f, verdict="Needs More Data", confidence="Low", reasoning="",
        answers=[], raw_response="", model="gpt", decision_source="structural_gate",
        anchor_resolution="absent", analysis_line=1,
    )
    r = Verdict.from_dict(v.to_dict())
    assert r.decision_source == "structural_gate"
    assert r.anchor_resolution == "absent" and r.analysis_line == 1


def test_structural_gate_absent_returns_nmd_without_model_call():
    capture: dict = {}
    e = _legacy_engine("int main(){return 0;}\n", capture)
    v = e._verify_legacy_finding(_f("a.c", 5, "free(buff1);"))  # absent from source
    assert v.verdict == VerdictType.NEEDS_MORE_DATA.value
    assert v.decision_source == "structural_gate"
    assert v.anchor_resolution == ABSENT
    e.llm_client.analyze.assert_not_called()
    e.context_extractor.get_context.assert_not_called()
