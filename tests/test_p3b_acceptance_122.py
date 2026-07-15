# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic #122 acceptance panel (no LLM).

Same canonical sink + same obligation = one case; everything else may legitimately
differ. The four cited #122 contradiction shapes are reproduced on real line
numbers: cross-rule/same-line pairs stay DISTINCT cases (different security
questions, verdicts left independent — no manufactured Needs-More-Data), a
same-rule construct repeated on different lines stays distinct, and only a genuine
same-sink duplicate is verified once.
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

from vuln_hunter_x.context.anchor import resolve_anchor
from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification import engine as eng
from vuln_hunter_x.verification.case import build_cases, case_key


def _f(file, lang, line, snippet, rule, *, cwe=None, flow=None, sc=1, ec=9):
    return Finding(rule_id=rule, message="m", file=file, start_line=line,
                   end_line=line, repo_name="panel", lang=lang, sink_snippet=snippet,
                   cwe_ids=list(cwe or []), dataflow_path=list(flow or []),
                   start_column=sc, end_column=ec)


def _key(finding, source):
    return case_key(finding, resolve_anchor(finding, source), norm_path=finding.file)


# --- Row 1: fuzzgoat main.c:135 — TOCTOU vs path-injection on one fopen line --
_C = 'int main(int c, char** v){\n  char* filename = v[1];\n  fp = fopen(filename, "rt");\n}\n'


def test_row1_toctou_vs_path_injection_are_distinct_cases():
    snip = 'fp = fopen(filename, "rt");'
    toctou = _f("main.c", "cpp", 3, snip, "cpp/toctou-race-condition", cwe=["CWE-367"])
    pathinj = _f("main.c", "cpp", 3, snip, "cpp/path-injection", cwe=["CWE-22"])
    cases = build_cases([_key(toctou, _C), _key(pathinj, _C)])
    assert len(cases) == 2  # different obligations → never merged, free to differ


# --- Row 2: DVWA exec/low.php:14 — code-injection vs command-injection ---------
_PHP = "<?php\n$target = $_REQUEST['ip'];\n$cmd = shell_exec('ping ' . $target);\n"


def test_row2_code_vs_command_injection_are_distinct_cases():
    snip = "$cmd = shell_exec('ping ' . $target);"
    exec_use = _f("low.php", "php", 3, snip, "exec-use", cwe=["CWE-94"])
    tainted = _f("low.php", "php", 3, snip, "tainted-exec", cwe=["CWE-78"])
    cases = build_cases([_key(exec_use, _PHP), _key(tainted, _PHP)])
    assert len(cases) == 2


def test_row2_end_to_end_keeps_fp_and_tp_no_manufactured_nmd():
    # The reconciler used to rewrite the (correct) code-injection FP to a hedged
    # NMD because the command-injection rule was TP on the same line. Now each is
    # its own case, verified independently; both verdicts survive verbatim.
    calls = []
    e = _engine(_PHP, calls, {"exec-use": "False Positive", "tainted-exec": "True Positive"})
    snip = "$cmd = shell_exec('ping ' . $target);"
    result = e.verify_findings([
        _f("low.php", "php", 3, snip, "exec-use", cwe=["CWE-94"]),
        _f("low.php", "php", 3, snip, "tainted-exec", cwe=["CWE-78"]),
    ])
    assert len(calls) == 2  # two distinct cases → two verifications
    assert [v.verdict for v in result.verdicts] == ["False Positive", "True Positive"]
    assert "Needs More Data" not in [v.verdict for v in result.verdicts]
    assert all(v.case_id == "" for v in result.verdicts)  # singletons, not merged


# --- Row 3: DVWA view_source.php — same rule, one construct on three lines -----
_VS = (
    "<?php\n"                                                       # 1
    '$s = @file_get_contents(BASE . "a/{$id}/x/{$sec}.php");\n'     # 2
    "echo $s;\n"                                                    # 3
    '$t = @file_get_contents(BASE . "a/{$id}/y/{$sec}.php");\n'     # 4
    '$u = @file_get_contents(BASE . "a/{$id}/z/{$sec}.js");\n'      # 5
)


def test_row3_same_rule_different_lines_stay_three_cases():
    r = "tainted-filename"
    a = _f("view_source.php", "php", 2, '$s = @file_get_contents(BASE . "a/{$id}/x/{$sec}.php");', r)
    b = _f("view_source.php", "php", 4, '$t = @file_get_contents(BASE . "a/{$id}/y/{$sec}.php");', r)
    c = _f("view_source.php", "php", 5, '$u = @file_get_contents(BASE . "a/{$id}/z/{$sec}.js");', r)
    cases = build_cases([_key(a, _VS), _key(b, _VS), _key(c, _VS)])
    assert len(cases) == 3  # three distinct sinks; no cross-line contagion


# --- Row 4: if_constexpr.cpp:15 — two buffer rules on one memcpy line ----------
_CPP = "void f(){\n  char buf[256];\n  memcpy(buf, first, first_len);\n}\n"


def test_row4_two_buffer_rules_stay_distinct_in_v1():
    snip = "memcpy(buf, first, first_len);"
    static_bo = _f("if_constexpr.cpp", "cpp", 3, snip, "cpp/static-buffer-overflow",
                   cwe=["CWE-119", "CWE-131"])
    overflow = _f("if_constexpr.cpp", "cpp", 3, snip, "cpp/overflow-buffer",
                  cwe=["CWE-119", "CWE-121"])
    cases = build_cases([_key(static_bo, _CPP), _key(overflow, _CPP)])
    assert len(cases) == 2  # shared CWE-119 is not obligation equivalence (deferred)


# --- discriminators + genuine duplicate ---------------------------------------
def test_same_rule_same_anchor_different_flow_are_distinct():
    snip = "$cmd = shell_exec('ping ' . $target);"
    a = _f("low.php", "php", 3, snip, "tainted-exec", flow=["src:2", "sink:3"])
    b = _f("low.php", "php", 3, snip, "tainted-exec", flow=["src:1", "sink:3"])
    assert len(build_cases([_key(a, _PHP), _key(b, _PHP)])) == 2


def test_same_line_different_columns_are_distinct():
    snip = "$cmd = shell_exec('ping ' . $target);"
    a = _f("low.php", "php", 3, snip, "tainted-exec", sc=1, ec=9)
    b = _f("low.php", "php", 3, snip, "tainted-exec", sc=20, ec=28)
    assert len(build_cases([_key(a, _PHP), _key(b, _PHP)])) == 2


def test_genuine_sibling_tool_duplicate_is_one_case():
    snip = "$cmd = shell_exec('ping ' . $target);"
    a = _f("low.php", "php", 3, snip, "tainted-exec")
    b = _f("low.php", "php", 3, snip, "tainted-exec")  # same everything, other tool
    cases = build_cases([_key(a, _PHP), _key(b, _PHP)])
    assert len(cases) == 1 and cases[0].observation_indices == [0, 1]


# --- stub engine (verdict decided by rule id) ---------------------------------
def _engine(source, calls, verdict_by_rule):
    e = eng.VerificationEngine.__new__(eng.VerificationEngine)
    e._jobs = 1
    e._callback_lock = threading.Lock()
    e._on_finding_start = None
    e._on_finding_complete = None
    e._log_fh = None
    e._policy_registry = MagicMock(families=[])
    e.questions_loader = MagicMock()
    e.questions_loader.get_questions.return_value = MagicMock(
        additional_context=[], min_iterations=1, rule_id="r")
    e.context_extractor = MagicMock()
    e.context_extractor.get_context.return_value = MagicMock(
        code="x", function_name="", start_line=3)
    e.context_extractor.read_source.return_value = source
    e.context_provider = MagicMock()

    def _analyze(**kwargs):
        f = kwargs["finding"]
        calls.append(f)
        return Verdict(finding=f, verdict=verdict_by_rule[f.rule_id], confidence="High",
                       reasoning="stub", answers=[], raw_response="", model="gpt-test",
                       confidence_score=0.9)

    e.llm_client = MagicMock()
    e.llm_client.analyze.side_effect = _analyze
    # A 1-iteration high-confidence FP triggers the (orthogonal) legacy second
    # opinion; model it as confirming the prior verdict unchanged.
    e.llm_client.request_second_opinion.side_effect = lambda **kw: kw["previous_verdict"]
    e.config = MagicMock()
    e.config.verification.self_consistency_samples = 1
    e.config.verification.max_iterations = 1
    e.config.verification.force_decision = False
    e.config.output.is_verbose = False
    e.config.output.is_quiet = True
    e.config.llm.model = "gpt-test"
    e.config.llm.provider = "test"
    return e
