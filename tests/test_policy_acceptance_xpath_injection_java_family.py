# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic XPath-injection (CWE-643) acceptance panel — Java.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

All fixtures are synthetic. The panel covers: a value concatenated into the
expression that gates a login (TP), a resolver that binds one value while another
is concatenated (TP), a filter for the wrong quote character (TP), a fixed
expression with an XPathVariableResolver (FP), a tainted document queried by a
constant expression (FP), a full-string allowlist (FP), a constant expression
(FP), a result that is never read (FP), a call that takes no XPath expression
(FP), and an off-slice validation helper whose body is not in evidence (NMD).

Scripted tests prove policy/control correctness, NOT model semantic quality.
"""

from __future__ import annotations

import json
import re
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
)
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.verification.policy.closure import PolicyClosureController
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import load_policy_registry

_REG = load_policy_registry()
_FAMILIES = {"java": "xpath_injection_java"}

# A fully-resolved True-Positive assessment. Individual cases flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_XPATH_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "query_position": {"value": "EXPRESSION_PATH_FOUND", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
    "security_effect": {"value": "SECURITY_RELEVANT_EFFECT", "evidence": ["L1"]},
}


def _flip(slot, value, evidence=("L1",)):
    return {slot: {"value": value, "evidence": list(evidence)}}


_UNRESOLVED_COVERAGE = {"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}}

# (id, lang, rule, cwes, snippet, dataflow, overrides, expected verdict)
_PANEL = [
    (
        "java-login-expression-concat",
        "java",
        "java/xml/xpath-injection",
        ["CWE-643"],
        'String q = "//user[name=\'" + request.getParameter("user") + "\' and pass=\'" + hash + "\']";\n'
        "NodeList hits = (NodeList) xpath.evaluate(q, doc, XPathConstants.NODESET);\n"
        'if (hits.getLength() == 1) session.setAttribute("auth", true);',
        'request.getParameter("user") -> XPath.evaluate',
        None,
        "True Positive",
    ),
    (
        "java-resolver-binds-one-value-another-is-concatenated",
        "java",
        "config.opengrep-rules.java.lang.security.audit.tainted-xpath-from-http-request",
        ["CWE-643"],
        "xpath.setXPathVariableResolver(resolver);\n"
        'String q = "/orders/order[@owner=$owner and @status=\'" + status + "\']";\n'
        "return xpath.compile(q).evaluate(doc);",
        'request.getParameter("status") -> XPath.compile',
        None,
        "True Positive",
    ),
    (
        "java-double-quote-filter-on-single-quoted-literal",
        "java",
        "java/xml/xpath-injection",
        ["CWE-643"],
        'String id = request.getParameter("id").replace("\\"", "");\n'
        'Node n = doc.selectSingleNode("//item[@id=\'" + id + "\']");\n'
        "response.getWriter().write(n.asXML());",
        'request.getParameter("id") -> Node.selectSingleNode',
        None,
        "True Positive",
    ),
    (
        "java-variable-resolver-fixed-expression",
        "java",
        "java/xml/xpath-injection",
        ["CWE-643"],
        'xpath.setXPathVariableResolver(name -> request.getParameter("user"));\n'
        'XPathExpression e = xpath.compile("//user[name=$user]/role");\n'
        "return e.evaluate(doc);",
        'request.getParameter("user") -> XPathVariableResolver',
        _flip("query_position", "BOUND_DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "java-tainted-document-constant-expression",
        "java",
        "java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request",
        ["CWE-643"],
        "InputSource body = new InputSource(request.getInputStream());\n"
        'String title = xpath.evaluate("/feed/title", body);',
        "request.getInputStream() -> XPath.evaluate",
        _flip("query_position", "BOUND_DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "java-full-string-allowlist",
        "java",
        "java/xml/xpath-injection",
        ["CWE-643"],
        'if (!code.matches("[A-Za-z0-9]{1,16}")) throw new BadRequest();\n'
        'return xpath.evaluate("//product[@code=\'" + code + "\']/price", doc);',
        "@RequestParam code -> XPath.evaluate",
        _flip("neutralization_coverage", "ALL_REACHING_PATHS"),
        "False Positive",
    ),
    (
        "java-constant-expression",
        "java",
        "java/xpath-injection",
        [],
        "private static final String ACTIVE = \"//user[@active='true']\";\n"
        "NodeList users = (NodeList) xpath.evaluate(ACTIVE, doc, XPathConstants.NODESET);",
        "ACTIVE -> XPath.evaluate",
        _flip("attacker_control", "REFUTED"),
        "False Positive",
    ),
    (
        "java-result-never-read",
        "java",
        "java/xml/xpath-injection",
        ["CWE-643"],
        'xpath.evaluate("//probe[@id=\'" + request.getParameter("id") + "\']", doc);\n'
        "return ResponseEntity.noContent().build();",
        'request.getParameter("id") -> XPath.evaluate',
        _flip("security_effect", "NO_SECURITY_EFFECT"),
        "False Positive",
    ),
    (
        "java-regex-compile-is-not-an-xpath-sink",
        "java",
        "java/xml/xpath-injection",
        ["CWE-643"],
        'Pattern p = Pattern.compile(request.getParameter("q"));',
        'request.getParameter("q") -> Pattern.compile',
        _flip("sink_binding", "NOT_XPATH_SINK"),
        "False Positive",
    ),
    (
        "java-project-validator-not-in-evidence",
        "java",
        "java/xml/xpath-injection",
        ["CWE-643"],
        'String name = XmlInputs.requireSafe(request.getParameter("name"));\n'
        'return xpath.evaluate("//user[name=\'" + name + "\']/mail", doc);',
        'request.getParameter("name") -> XPath.evaluate',
        _UNRESOLVED_COVERAGE,
        "Needs More Data",
    ),
]

_SAMPLE = {"java": _PANEL[0]}
_EXT = {"java": "java", "python": "py"}


def _finding(lang, rule, cwes, dataflow):
    source, sink = dataflow.split(" -> ")
    return Finding(
        rule_id=rule,
        message="m",
        file=f"app/handler.{_EXT[lang]}",
        start_line=20,
        end_line=20,
        repo_name="synthetic",
        lang=lang,
        cwe_ids=list(cwes),
        dataflow_path=[source, sink],
    )


def _q(rule):
    return GuidedQuestions(rule_id=rule, short_description="d", questions=["q?"])


def _seeded(finding, snippet, dataflow):
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("synthetic", finding.lang, finding.file, 18, 24),
        snippet,
    )
    led.add_scanner_dataflow(dataflow)
    return led


def _assess(overrides=None, requests=None):
    slots = {k: dict(v) for k, v in _BASE.items()}
    for k, v in (overrides or {}).items():
        slots[k] = v
    raw = {"fact_slots": slots, "reasoning": "assessed"}
    if requests:
        raw["evidence_requests"] = requests
    return json.dumps(raw)


def _resp(content):
    choice = MagicMock()
    choice.message.content = content
    r = MagicMock()
    r.choices = [choice]
    return r


class _FakeProvider:
    def __init__(self, status, *, exhaustive=True, kind=EvidenceKind.FUNCTION):
        self._status, self._exhaustive, self._kind = status, exhaustive, kind

    def resolve_evidence(self, repo_name, lang, requests):
        out = {}
        for r in requests:
            out[r.raw_request] = EvidenceResult(
                request=r,
                status=self._status,
                prompt_content="// helper",
                scope=EvidenceScope.REPOSITORY_INDEX,
                exhaustive=self._exhaustive,
            )
        return out


def _controller(case, provider=None):
    _id, lang, rule, cwes, snippet, dataflow, _overrides, _expected = case
    finding = _finding(lang, rule, cwes, dataflow)
    policy = _REG.resolve_family(cwe_ids=finding.cwe_ids, rule_id=rule, lang=lang)
    assert policy is not None and policy.family == _FAMILIES[lang], rule
    controller = PolicyClosureController(
        policy=policy,
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(finding, snippet, dataflow),
        max_retrieval_rounds=2,
    )
    return finding, controller


def _run(mock_completion, responses, case, *, provider=None, max_iterations=5):
    mock_completion.side_effect = [_resp(r) for r in responses]
    finding, controller = _controller(case, provider)
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=finding,
        context=case[4],
        questions=_q(case[2]),
        func_name="h",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=max_iterations,
        quiet=True,
    )


# ── the synthetic panel ───────────────────────────────────────────────


@pytest.mark.parametrize("case", _PANEL, ids=[c[0] for c in _PANEL])
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_panel(mc, case):
    verdict = _run(mc, [_assess(overrides=case[6])], case)
    assert verdict.verdict == case[7]
    assert f"[policy:{_FAMILIES[case[1]]} " in verdict.reasoning


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_panel_has_every_outcome(lang):
    outcomes = {c[7] for c in _PANEL if c[1] == lang}
    assert outcomes == {"True Positive", "False Positive", "Needs More Data"}


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_is_ignored(mc, lang):
    # The model asserts a verdict; only the fact table decides.
    raw = json.loads(_assess(overrides=_flip("query_position", "BOUND_DATA_ONLY_ALL_PATHS")))
    raw["verdict"] = "True Positive"
    assert _run(mc, [json.dumps(raw)], _SAMPLE[lang]).verdict == "False Positive"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_bound_data_claim_cited_to_dataflow_only_is_nmd(mc, lang):
    # "Safe on all paths" needs the construction itself (local slice or an
    # exhaustive retrieval); the scanner dataflow witnesses one path only.
    overrides = _flip("query_position", "BOUND_DATA_ONLY_ALL_PATHS", evidence=("D1",))
    verdict = _run(mc, [_assess(overrides=overrides)] * 5, _SAMPLE[lang])
    assert verdict.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_validation_helper_non_exhaustive_is_nmd(mc, lang):
    # An ALL_REACHING_PATHS claim supported only by a non-exhaustive retrieved
    # helper is inadmissible -> stays Needs More Data.
    responses = [
        _assess(
            overrides=_UNRESOLVED_COVERAGE,
            requests=[
                {
                    "kind": "function",
                    "subject": "requireSafe",
                    "for_slot": "neutralization_coverage",
                }
            ],
        ),
        _assess(overrides=_flip("neutralization_coverage", "ALL_REACHING_PATHS", ("R1",))),
    ]
    verdict = _run(
        mc,
        responses,
        _SAMPLE[lang],
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False),
    )
    assert verdict.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_validation_helper_exhaustive_is_fp(mc, lang):
    responses = [
        _assess(
            overrides=_UNRESOLVED_COVERAGE,
            requests=[
                {
                    "kind": "function",
                    "subject": "requireSafe",
                    "for_slot": "neutralization_coverage",
                }
            ],
        ),
        _assess(overrides=_flip("neutralization_coverage", "ALL_REACHING_PATHS", ("R1",))),
    ]
    verdict = _run(
        mc,
        responses,
        _SAMPLE[lang],
        provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True),
    )
    assert verdict.verdict == "False Positive"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_nmd_with_reason(mc, lang):
    responses = [
        _assess(
            overrides={"flow_to_sink": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides=_flip("flow_to_sink", "REACHES", ("R1",))),
    ]
    verdict = _run(
        mc, responses, _SAMPLE[lang], provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX)
    )
    assert verdict.verdict == "Needs More Data"
    assert "flow_to_sink" in verdict.reasoning


# ── rendered prompt ───────────────────────────────────────────────────

_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct", re.IGNORECASE
)
_PAREN_LABEL = re.compile(r"\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)", re.IGNORECASE)
_BENCHMARK = re.compile(r"OWASP Benchmark|Juliet|BenchmarkTest|SecLLMHolmes|DVWA", re.IGNORECASE)
_LANGUAGE_MARKERS = {
    "java": ("XPathVariableResolver", "XPath.compile", "selectNodes", "XPath 1.0"),
}


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_overlay_carries_the_family_guidance_and_no_verdict_command(lang):
    _finding_, controller = _controller(_SAMPLE[lang])
    instr = controller.initial_instructions()
    for slot in _BASE:
        assert slot in instr
    assert "production_scope" in instr
    assert "lxml" not in instr  # the Python family's guidance must not leak in
    assert "[L1]" in instr and "[D1]" in instr
    for marker in _LANGUAGE_MARKERS[lang]:
        assert marker in instr, marker
    policy = _REG.resolve_family(cwe_ids=[], rule_id=_SAMPLE[lang][2], lang=lang)
    guidance = " ".join(policy.assessment_guidance)
    assert policy.assessment_guidance[0] in instr
    for text in (instr, guidance):
        assert not _VERDICT_CMD.search(text)
        assert not _PAREN_LABEL.search(text)
        assert not _BENCHMARK.search(text)
