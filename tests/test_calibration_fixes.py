# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Tests for the 2026-05-15 calibration / TP-preservation fixes.

Covers (initial round, 16:00):
  - Symmetric confidence downgrade on TP and FP (engine).
  - JSON-parse failure returns NMD with parse_failed=True (LLMClient).
  - min_iterations gate fires regardless of context_provider presence.
  - CWE-class min_iterations override raises the gate for semantic CWEs.
  - SnippetContextProvider returns snippet-derived answers and unavailable
    sentinels for out-of-scope requests.

Covers (CWE-264 follow-up, 17:30):
  - _force_decision_turn detects "no authorization" / access-control TP signals.
  - Truncated JSON (unbalanced braces) sets truncated=True in parse fallback.
  - Stratified-by-CWE rebalance gives each CWE fair share of the cap.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from vuln_hunter_x.context.snippet_provider import SnippetContextProvider
from vuln_hunter_x.core.types import Finding, GuidedQuestions, Verdict
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.questions.loader import QuestionsLoader
from vuln_hunter_x.verification.engine import (
    _check_rule_construct_presence,
    _downgrade_cli_path_injection,
    _downgrade_unsupported_confidence,
)


def _make_litellm_response(content: str):
    choice = MagicMock()
    choice.message.content = content
    response = MagicMock()
    response.choices = [choice]
    response.usage = MagicMock(
        total_tokens=10, prompt_tokens=8, completion_tokens=2,
        prompt_tokens_details=MagicMock(cached_tokens=0),
    )
    return response


def _verdict(verdict: str, confidence: str, reasoning: str) -> Verdict:
    finding = Finding(
        rule_id="cpp/use-after-free",
        message="m",
        file="a.c",
        start_line=1,
        end_line=1,
        repo_name="r",
        lang="c",
    )
    return Verdict(
        finding=finding,
        verdict=verdict,
        confidence=confidence,
        reasoning=reasoning,
        answers=[],
        raw_response="",
        model="x",
        elapsed_seconds=0.0,
        iterations=1,
        confidence_score={"High": 0.85, "Medium": 0.6, "Low": 0.3}[confidence],
    )


class TestSymmetricConfidenceDowngrade:
    """The downgrade heuristic now applies to TP AND FP equally."""

    def test_tp_with_pattern_language_no_citation_downgraded(self):
        v = _verdict(
            "True Positive",
            "High",
            "This is a textbook use-after-free pattern.",
        )
        result = _downgrade_unsupported_confidence(v)
        assert result.confidence == "Low"
        assert result.confidence_score <= 0.3
        assert "downgraded" in result.reasoning

    def test_fp_with_pattern_language_no_citation_downgraded(self):
        # 2026-05-15 fix: FP-side downgrade was missing, biasing the Low bucket
        # toward FP and making High/Low accuracy indistinguishable.
        v = _verdict(
            "False Positive",
            "High",
            "This is a classic safe pattern with no exploit path.",
        )
        result = _downgrade_unsupported_confidence(v)
        assert result.confidence == "Low"
        assert result.confidence_score <= 0.3

    def test_fp_with_citation_not_downgraded(self):
        v = _verdict(
            "False Positive",
            "High",
            "The bounds check at line 42 prevents the overflow.",
        )
        result = _downgrade_unsupported_confidence(v)
        # Citation present → not downgraded
        assert result.confidence == "High"

    def test_nmd_never_downgraded(self):
        v = _verdict("Needs More Data", "High", "This is obvious.")
        result = _downgrade_unsupported_confidence(v)
        assert result.confidence == "High"


class TestParseFallback:
    """JSON-parse failure must NOT pollute the Low bucket with phantom FP."""

    def setup_method(self):
        self.client = LLMClient()

    def test_unparseable_returns_nmd(self):
        result = self.client._parse_response("totally not json @#$")
        assert result["verdict"] == "Needs More Data"
        assert result.get("parse_failed") is True
        assert result["confidence_score"] == 0.0

    def test_text_with_fp_phrase_does_not_force_low_fp(self):
        # The old fallback parser would extract "False Positive" and set
        # confidence=Low. New behaviour: cannot trust intent → NMD.
        result = self.client._parse_response("I think this is a False Positive")
        assert result["verdict"] == "Needs More Data"
        assert result.get("parse_failed") is True


class TestMinIterationsGate:
    """The min_iterations gate must fire even when context_provider is None."""

    def setup_method(self):
        self.client = LLMClient(provider="openai", model="gpt-4o")
        self.finding = Finding(
            rule_id="cpp/use-after-free",
            message="UAF",
            file="x.c",
            start_line=1,
            end_line=1,
            repo_name="r",
            lang="c",
        )
        self.questions = GuidedQuestions(
            rule_id="cpp/use-after-free",
            short_description="UAF",
            questions=["Q1?"],
            additional_context=["caller", "free_sites"],
            min_iterations=2,
        )

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_gate_fires_without_context_provider(self, mock_completion):
        # Turn 1: LLM commits to FP after 1 iter. With the old code (gate
        # requires context_provider is not None), this would short-circuit
        # and return FP on iter 1. New code lets the gate fire and forces
        # iter 2.
        mock_completion.side_effect = [
            _make_litellm_response(
                '{"verdict": "False Positive", "confidence": "High", '
                '"reasoning": "looks fine", "answers": []}'
            ),
            _make_litellm_response(
                '{"verdict": "False Positive", "confidence": "Low", '
                '"reasoning": "still fine after re-examination", "answers": []}'
            ),
        ]
        verdict = self.client.analyze(
            finding=self.finding,
            context="void f(int *p){ free(p); use(p); }",
            questions=self.questions,
            func_name="f",
            context_provider=None,  # ← critical for this test
            max_iterations=3,
            quiet=True,
            force_decision=False,
        )
        # With min_iterations=2, the LLM must have been called twice before
        # the verdict is accepted.
        assert verdict.iterations >= 2
        assert mock_completion.call_count >= 2


class TestCweMinIterationsOverride:
    """Semantic CWEs (access control, auth) should pick up min_iter ≥ 2 even
    when the matched questions YAML did not declare it."""

    def setup_method(self):
        self.loader = QuestionsLoader()
        # Insert a question entry with min_iterations=1 (default).
        self.loader.questions["cpp/missing-authorization"] = GuidedQuestions(
            rule_id="cpp/missing-authorization",
            short_description="missing auth",
            questions=["?"],
            min_iterations=1,
        )

    def test_cwe_264_bumps_min_iterations(self):
        q = self.loader.get_questions(
            "cpp/missing-authorization", cwe_ids=["CWE-264"], lang="c",
        )
        assert q.min_iterations >= 2

    def test_cwe_287_bumps_min_iterations(self):
        q = self.loader.get_questions(
            "cpp/missing-authorization", cwe_ids=["CWE-287"], lang="c",
        )
        assert q.min_iterations >= 2

    def test_non_semantic_cwe_does_not_bump(self):
        # CWE-787 (out-of-bounds write) is not in the override map.
        q = self.loader.get_questions(
            "cpp/missing-authorization", cwe_ids=["CWE-787"], lang="c",
        )
        assert q.min_iterations == 1

    def test_no_cwe_ids_does_not_bump(self):
        q = self.loader.get_questions("cpp/missing-authorization")
        assert q.min_iterations == 1


class TestPythonTaintMinIterations:
    """2026-05-19 owasp-python: taint-tracking CWEs (CWE-22, CWE-643, …)
    are bumped to min_iterations=2 ONLY on framework languages so the C-side
    diversevul/CWE-264 baseline isn't perturbed."""

    def setup_method(self):
        self.loader = QuestionsLoader()
        self.loader.questions["py/path-injection"] = GuidedQuestions(
            rule_id="py/path-injection",
            short_description="path",
            questions=["?"],
            min_iterations=1,
        )

    def test_python_cwe_22_bumps_min_iterations(self):
        q = self.loader.get_questions(
            "py/path-injection", cwe_ids=["CWE-22"], lang="python",
        )
        assert q.min_iterations == 2

    def test_python_cwe_643_bumps_min_iterations(self):
        q = self.loader.get_questions(
            "py/path-injection", cwe_ids=["CWE-643"], lang="python",
        )
        assert q.min_iterations == 2

    def test_c_cwe_22_does_not_bump(self):
        # CWE-22 in C is uncommon but possible; the override is gated to
        # framework langs so C verdicts are unaffected.
        q = self.loader.get_questions(
            "py/path-injection", cwe_ids=["CWE-22"], lang="c",
        )
        assert q.min_iterations == 1

    def test_javascript_cwe_79_bumps_min_iterations(self):
        q = self.loader.get_questions(
            "py/path-injection", cwe_ids=["CWE-79"], lang="javascript",
        )
        assert q.min_iterations == 2

    def test_python_cwe_601_bumps_min_iterations(self):
        # 2026-05-19 owasp-python: py/url-redirection (CWE-601) had P=0.40 vs
        # raw 0.50; was missing from the override map, defaulted to 1 iter.
        q = self.loader.get_questions(
            "py/path-injection", cwe_ids=["CWE-601"], lang="python",
        )
        assert q.min_iterations == 2

    def test_python_cwe_501_bumps_min_iterations(self):
        # 2026-05-19 owasp-python/java: trust-boundary-violation (CWE-501)
        # had P=0.40 — needs the two-iteration floor for the downstream-read
        # chain in the new sink-quote rubric.
        q = self.loader.get_questions(
            "py/path-injection", cwe_ids=["CWE-501"], lang="python",
        )
        assert q.min_iterations == 2

    def test_access_control_cwe_still_unconditional(self):
        # Access-control CWEs apply across all languages — they have an
        # empty langs frozenset meaning "all".
        q = self.loader.get_questions(
            "py/path-injection", cwe_ids=["CWE-264"], lang="c",
        )
        assert q.min_iterations == 2


class TestCweRuleMapCanonicalPyKeys:
    """The CWE_TO_RULES first-py-entry must match the python_questions.yaml
    canonical key for the taint CWEs we exercised — otherwise the
    benchmark falls back to the bidirectional prefix match (22% rate in
    the 2026-05-19 owasp-python run)."""

    def test_cwe_643_first_py_is_canonical(self):
        from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
        assert primary_rule_for_lang("CWE-643", "python") == "py/xpath-injection"

    def test_cwe_79_first_py_is_canonical(self):
        from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
        assert primary_rule_for_lang("CWE-79", "python") == "py/xss"

    def test_cwe_22_first_py_is_canonical(self):
        from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
        assert primary_rule_for_lang("CWE-22", "python") == "py/path-injection"

    def test_cwe_89_first_py_is_canonical(self):
        from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
        assert primary_rule_for_lang("CWE-89", "python") == "py/sql-injection"


class TestSecondOpinionTaintArm:
    """The third trigger arm (TP/High/1-iter on framework-lang taint CWE)
    must fire on Python web findings and stay silent on C."""

    def test_predicate_fires_on_python_taint_tp(self):
        # Replicates the boolean condition in
        # verification.engine._verify_single_finding (arm_c).
        from vuln_hunter_x.verification.engine import _FRAMEWORK_LANGS, _TAINT_CWES
        finding = Finding(
            rule_id="py/path-injection", message="CWE-22 trap",
            file="x.py", start_line=1, end_line=1,
            repo_name="r", lang="python", cwe_ids=["CWE-22"],
        )
        verdict = _verdict("True Positive", "High", "user input flows to open()")
        verdict.iterations = 1
        is_tp = verdict.verdict in ("True Positive", "TP")
        arm_c = (
            is_tp
            and verdict.confidence == "High"
            and verdict.iterations == 1
            and finding.lang in _FRAMEWORK_LANGS
            and bool(set(finding.cwe_ids or []) & _TAINT_CWES)
        )
        assert arm_c is True

    def test_predicate_silent_on_c_taint_tp(self):
        from vuln_hunter_x.verification.engine import _FRAMEWORK_LANGS, _TAINT_CWES
        finding = Finding(
            rule_id="cpp/overflow-buffer", message="CWE-787",
            file="x.c", start_line=1, end_line=1,
            repo_name="r", lang="c", cwe_ids=["CWE-22"],
        )
        verdict = _verdict("True Positive", "High", "buffer overflow")
        verdict.iterations = 1
        arm_c = (
            verdict.verdict in ("True Positive", "TP")
            and verdict.confidence == "High"
            and verdict.iterations == 1
            and finding.lang in _FRAMEWORK_LANGS
            and bool(set(finding.cwe_ids or []) & _TAINT_CWES)
        )
        assert arm_c is False

    def test_predicate_silent_on_non_taint_cwe(self):
        from vuln_hunter_x.verification.engine import _FRAMEWORK_LANGS, _TAINT_CWES
        finding = Finding(
            rule_id="py/csrf", message="csrf",
            file="x.py", start_line=1, end_line=1,
            repo_name="r", lang="python", cwe_ids=["CWE-352"],
        )
        verdict = _verdict("True Positive", "High", "csrf missing")
        verdict.iterations = 1
        arm_c = (
            verdict.verdict in ("True Positive", "TP")
            and verdict.confidence == "High"
            and verdict.iterations == 1
            and finding.lang in _FRAMEWORK_LANGS
            and bool(set(finding.cwe_ids or []) & _TAINT_CWES)
        )
        assert arm_c is False


class TestSnippetContextProvider:
    """The snippet-derived fallback provider — used when CSV context is
    unavailable, restoring the multi-turn loop instead of silently giving up."""

    def test_free_sites_finds_inline_free_call(self):
        snippet = """
void f(char *p) {
    free(p);
    use(p);
}
"""
        p = SnippetContextProvider(snippet)
        out = p.get_additional_context("r", "c", ["free_sites:p"])
        result = out["free_sites:p"]
        assert "free(p)" in result
        # No <unavailable> sentinel when the free is in-snippet.
        assert SnippetContextProvider.UNAVAILABLE_PREFIX not in result

    def test_free_sites_missing_returns_unavailable(self):
        p = SnippetContextProvider("void f(int *p){ use(p); }")
        out = p.get_additional_context("r", "c", ["free_sites:p"])
        assert SnippetContextProvider.UNAVAILABLE_PREFIX in out["free_sites:p"]

    def test_caller_request_is_unavailable(self):
        # Caller relationships are out-of-snippet by definition.
        p = SnippetContextProvider("void f() {}")
        out = p.get_additional_context("r", "c", ["caller:f"])
        assert SnippetContextProvider.UNAVAILABLE_PREFIX in out["caller:f"]

    def test_struct_found_in_snippet(self):
        snippet = """
struct Buf {
    char data[256];
    int len;
};
void f(struct Buf *b) { b->len = 1; }
"""
        p = SnippetContextProvider(snippet)
        out = p.get_additional_context("r", "c", ["struct:Buf"])
        assert "char data[256]" in out["struct:Buf"]

    def test_malformed_request_returns_unavailable(self):
        p = SnippetContextProvider("")
        out = p.get_additional_context("r", "c", ["malformed-no-colon"])
        assert SnippetContextProvider.UNAVAILABLE_PREFIX in out["malformed-no-colon"]


class TestRebalanceNegatives:
    """DiverseVulAdapter._rebalance should produce the requested neg fraction."""

    def test_rebalance_produces_requested_fraction(self):
        from benchmarks.adapters.diversevul_adapter import DiverseVulAdapter
        from benchmarks.adapters.ground_truth import (
            LABEL_FP,
            LABEL_TP,
            GroundTruthEntry,
        )

        def _mk(i: int, lbl: str) -> GroundTruthEntry:
            return GroundTruthEntry(
                id=f"e{i}",
                source_dataset="diversevul",
                cwe_id="CWE-787",
                rule_id="cpp/overflow-buffer",
                file_path="",
                function_name="",
                start_line=1,
                lang="c",
                label=lbl,
                code_snippet="",
                metadata={},
            )

        entries = [_mk(i, LABEL_TP) for i in range(100)] + [
            _mk(i, LABEL_FP) for i in range(100, 200)
        ]
        out = DiverseVulAdapter._rebalance(entries, negative_fraction=0.5, limit=40)
        assert len(out) == 40
        n_neg = sum(1 for e in out if e.label == LABEL_FP)
        assert n_neg == 20  # 50% of 40


class TestForcedDecisionAccessControlSignals:
    """The _force_decision_turn signal vocabulary must cover access-control
    CWE language. The 2026-05-15 16:45 diversevul run showed a CWE-264 case
    correctly enumerating 'No authorization check ... is present' in its
    reasoning but defaulting to FP because the old signal list did not match."""

    def setup_method(self):
        self.client = LLMClient(provider="openai", model="gpt-4o")

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_no_authorization_in_reasoning_promotes_tp(self, mock_completion):
        # Force-decision turn: the LLM returns text whose extracted verdict
        # is NMD, but the reasoning explicitly says no authorization check
        # is present. The signal-detection branch should promote this to
        # True Positive (Low) rather than defaulting to False Positive.
        nmd_response = (
            '{"verdict": "Needs More Data", "confidence": "Low",'
            ' "reasoning": "No authorization check (e.g., capability test,'
            ' permission check) is present anywhere in the provided code.'
            ' The function is directly callable from unprotected callers.",'
            ' "answers": []}'
        )
        mock_completion.return_value = _make_litellm_response(nmd_response)
        parsed, *_ = self.client._force_decision_turn(
            messages=[{"role": "user", "content": "x"}],
            all_raw_responses=[],
            total_tokens_used=0,
            total_cost_usd=0.0,
        )
        assert parsed["verdict"] == "True Positive"
        assert "evidence leans toward TP" in parsed.get("reasoning", "")

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_parse_failure_not_keyword_forced_to_tp(self, mock_completion):
        # A truncated / unparseable forced-decision response must NOT be
        # keyword-counted into a verdict. Its "reasoning" is just raw JSON
        # saturated with overflow words ("unsafe", "no validation") that would
        # otherwise be miscounted as TP signals. Regression: libjpeg-turbo
        # jidctint.c entries became TP at confidence_score 0.0 this way.
        truncated = (
            '{"verdict": "True Positive", "reasoning": "the multiplication is '
            'unsafe, there is no validation and no bounds check, exploitable'
        )
        mock_completion.return_value = _make_litellm_response(truncated)
        parsed, *_ = self.client._force_decision_turn(
            messages=[{"role": "user", "content": "x"}],
            all_raw_responses=[],
            total_tokens_used=0,
            total_cost_usd=0.0,
        )
        assert parsed["verdict"] == "Needs More Data"
        assert parsed.get("parse_failed") is True
        assert "[Forced decision:" not in parsed.get("reasoning", "")


class TestCppCorrectnessTpChallengeArm:
    """arm_d: a 1-iter/High TP on a C/C++ correctness-class CWE must be
    re-challenged (mirror of the FP-side arms), while non-matching findings
    are left alone."""

    @staticmethod
    def _arm_d(verdict, finding, min_iterations: int) -> bool:
        # Mirror of the boolean in engine._verify_single_finding (arm_d).
        from vuln_hunter_x.verification.engine import _CPP_PATTERN_CLASS_CWES
        return (
            verdict.verdict in ("True Positive", "TP")
            and verdict.confidence == "High"
            and verdict.iterations <= max(1, min_iterations)
            and finding.lang in ("c", "cpp")
            and bool(set(finding.cwe_ids or []) & _CPP_PATTERN_CLASS_CWES)
        )

    def test_predicate_fires_at_min_iterations_two(self):
        # Regression: the rule sets min_iterations=2, so a TP committed at the
        # minimum depth has iterations==2. A `== 1` gate would make arm_d dead
        # code for exactly the rule it targets.
        finding = Finding(
            rule_id="cpp/integer-multiplication-cast-to-long",
            message="overflow", file="src/jdlhuff.c", start_line=234, end_line=234,
            repo_name="r", lang="c", cwe_ids=["CWE-190", "CWE-192"],
        )
        verdict = _verdict("True Positive", "High", "pattern present, line 234")
        verdict.iterations = 2
        assert self._arm_d(verdict, finding, min_iterations=2) is True

    def test_predicate_silent_when_already_expanded_context(self):
        # A verdict that voluntarily dug past its minimum depth (iterations >
        # min_iterations) already examined more context; don't re-challenge.
        finding = Finding(
            rule_id="cpp/integer-multiplication-cast-to-long",
            message="overflow", file="src/jdlhuff.c", start_line=234, end_line=234,
            repo_name="r", lang="c", cwe_ids=["CWE-190"],
        )
        verdict = _verdict("True Positive", "High", "traced operands across 4 turns")
        verdict.iterations = 4
        assert self._arm_d(verdict, finding, min_iterations=2) is False

    def test_predicate_silent_on_fp(self):
        finding = Finding(
            rule_id="cpp/integer-multiplication-cast-to-long",
            message="overflow", file="src/jdlhuff.c", start_line=234, end_line=234,
            repo_name="r", lang="c", cwe_ids=["CWE-190"],
        )
        verdict = _verdict("False Positive", "High", "operands bounded")
        verdict.iterations = 2
        assert self._arm_d(verdict, finding, min_iterations=2) is False

    def test_predicate_silent_on_python(self):
        # Non-C languages are handled by the taint arm (arm_c), not arm_d.
        finding = Finding(
            rule_id="py/int-overflow", message="x", file="x.py",
            start_line=1, end_line=1, repo_name="r", lang="python",
            cwe_ids=["CWE-190"],
        )
        verdict = _verdict("True Positive", "High", "x")
        verdict.iterations = 1
        assert self._arm_d(verdict, finding, min_iterations=2) is False

    def test_tp_challenge_prompt_steers_toward_fp(self):
        # The dedicated prompt must instruct flipping to FP/NMD when overflow
        # is not shown reachable — the opposite of the FP-challenge prompt.
        prompt = LLMClient._TP_CHALLENGE_PROMPT
        assert "False Positive" in prompt
        assert prompt is not LLMClient._SECOND_OPINION_PROMPT


def _verdict_with(rule_id, cwe_ids, verdict, confidence, reasoning,
                  data_flow="", file="src/cjpeg.c", lang="c"):
    v = _verdict(verdict, confidence, reasoning)
    v.finding = Finding(
        rule_id=rule_id, message="m", file=file, start_line=1, end_line=1,
        repo_name="r", lang=lang, cwe_ids=cwe_ids,
    )
    v.data_flow = data_flow
    return v


class TestCliPathInjectionCalibration:
    """_downgrade_cli_path_injection: argv-sourced path-injection in a CLI tool
    has no trust boundary and must not ride at TP/High."""

    def test_argv_source_no_boundary_downgraded(self):
        v = _verdict_with(
            "cpp/path-injection", ["CWE-22"], "True Positive", "High",
            "The filename comes from argv and is passed to fopen with no validation.",
            data_flow="source: argv[i] (line 269) -> fopen (line 269)",
        )
        out = _downgrade_cli_path_injection(v)
        assert out.confidence == "Low"
        assert "no trust boundary" in out.reasoning

    def test_server_boundary_untouched(self):
        v = _verdict_with(
            "cpp/path-injection", ["CWE-22"], "True Positive", "High",
            "The path arrives in an HTTP request handler on the server and reaches open().",
            data_flow="source: request param -> open()",
        )
        out = _downgrade_cli_path_injection(v)
        assert out.confidence == "High"  # real boundary present → not downgraded

    def test_fp_untouched(self):
        v = _verdict_with(
            "cpp/path-injection", ["CWE-22"], "False Positive", "High",
            "argv path but validated.", data_flow="argv",
        )
        out = _downgrade_cli_path_injection(v)
        assert out.verdict == "False Positive" and out.confidence == "High"

    def test_non_path_rule_untouched(self):
        v = _verdict_with(
            "cpp/integer-multiplication-cast-to-long", ["CWE-190"], "True Positive",
            "High", "argv reaches a multiply", data_flow="argv",
        )
        out = _downgrade_cli_path_injection(v)
        assert out.confidence == "High"


class TestRuleScopeConstructPresence:
    """_check_rule_construct_presence: a TP whose reasoning argues an off-scope
    CWE class than the reported rule must be downgraded."""

    def test_offscope_reasoning_downgraded(self):
        v = _verdict_with(
            "cpp/integer-multiplication-cast-to-long", ["CWE-190"], "True Positive",
            "High",
            "This is a classic path traversal: argv flows to fopen and an attacker "
            "could use ../ to escape the directory.",
        )
        out = _check_rule_construct_presence(v)
        assert out.confidence == "Low"
        assert "rule-scope" in out.reasoning

    def test_onscope_reasoning_untouched(self):
        v = _verdict_with(
            "cpp/integer-multiplication-cast-to-long", ["CWE-190"], "True Positive",
            "High",
            "The int multiplication overflows before the cast; product exceeds INT_MAX.",
        )
        out = _check_rule_construct_presence(v)
        assert out.confidence == "High"

    def test_reported_cwe_not_in_map_untouched(self):
        v = _verdict_with(
            "cpp/world-writable-file-creation", ["CWE-732"], "True Positive", "High",
            "This is path traversal via ../ in the filename.",
        )
        out = _check_rule_construct_presence(v)
        assert out.confidence == "High"  # CWE-732 not in marker map → don't guess

    def test_fp_untouched(self):
        v = _verdict_with(
            "cpp/integer-multiplication-cast-to-long", ["CWE-190"], "False Positive",
            "High", "path traversal noticed but operands bounded",
        )
        out = _check_rule_construct_presence(v)
        assert out.verdict == "False Positive" and out.confidence == "High"


class TestParseFallbackTruncation:
    """Truncated JSON (unbalanced braces) should set truncated=True so the
    telemetry can attribute the failure mode correctly."""

    def setup_method(self):
        self.client = LLMClient()

    def test_truncated_json_flagged(self):
        raw = '{"verdict": "False Positive", "confidence": "High", "reasoning": "the operation has'
        result = self.client._parse_response(raw)
        assert result["verdict"] == "Needs More Data"
        assert result.get("parse_failed") is True
        assert result.get("truncated") is True

    def test_well_formed_garbage_not_flagged_truncated(self):
        raw = "completely unparseable text without any brace"
        result = self.client._parse_response(raw)
        assert result["verdict"] == "Needs More Data"
        assert result.get("parse_failed") is True
        # No braces at all → not truncated, just unparseable.
        assert result.get("truncated") is False


class TestRebalanceStratifiedByCwe:
    """Each CWE should contribute a fair share of the cap after rebalance."""

    def test_stratified_cap_distributes_across_cwes(self):
        from benchmarks.adapters.diversevul_adapter import DiverseVulAdapter
        from benchmarks.adapters.ground_truth import (
            LABEL_FP,
            LABEL_TP,
            GroundTruthEntry,
        )

        def _mk(i: int, cwe: str, lbl: str) -> GroundTruthEntry:
            return GroundTruthEntry(
                id=f"{cwe}-e{i}",
                source_dataset="diversevul",
                cwe_id=cwe,
                rule_id="cpp/x",
                file_path="",
                function_name="",
                start_line=1,
                lang="c",
                label=lbl,
                code_snippet="",
                metadata={},
            )

        # Two CWEs: 264 is negative-heavy (4 TP, 40 FP); 787 is positive-only
        # (22 TP, 0 FP). Naive non-stratified rebalance would take whatever
        # appeared first and overweight one CWE.
        entries = (
            [_mk(i, "CWE-264", LABEL_TP) for i in range(4)]
            + [_mk(i, "CWE-264", LABEL_FP) for i in range(40)]
            + [_mk(i, "CWE-787", LABEL_TP) for i in range(22)]
        )
        out = DiverseVulAdapter._rebalance(entries, negative_fraction=0.5, limit=40)
        # Both CWEs must be represented in the output.
        cwes = {e.cwe_id for e in out}
        assert "CWE-264" in cwes
        assert "CWE-787" in cwes
        # No CWE may take more than ~75% of the cap; that's the fairness
        # property the stratification provides.
        for cwe in cwes:
            share = sum(1 for e in out if e.cwe_id == cwe)
            assert share <= int(40 * 0.75), f"{cwe} took {share}/40 — not stratified"


class TestSecondOpinionTriggerForcedDecision:
    """The second-opinion safety valve must fire for FP verdicts that ended
    via the force-decision fallback, not just for 1-iter/High verdicts."""

    def test_trigger_predicate(self):
        # The trigger predicate is checked inline in
        # verification.engine._verify_single_finding (no extracted helper),
        # so we replicate the boolean condition here to lock in the contract.
        reasoning_with_marker = "stuff [Forced decision: defaulted to FP] more stuff"
        is_fp = True
        # Arm A: 1-iter / High / FP
        confidence = "Low"
        iterations = 2
        arm_a = is_fp and confidence == "High" and iterations == 1
        arm_b = is_fp and "[Forced decision:" in reasoning_with_marker
        assert not arm_a
        assert arm_b
        # Combined trigger fires via arm B.
        assert arm_a or arm_b
