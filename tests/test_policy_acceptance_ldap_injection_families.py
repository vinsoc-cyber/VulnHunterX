# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic LDAP-injection (CWE-90) acceptance panel — Java and Python.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

All fixtures are synthetic. Per language the panel covers: a value concatenated
into the search filter (TP), a value concatenated into a DN (TP), the wrong kind
of escaping for the position (TP: filter escaping does not protect a DN), an
encoding API on every path (FP), position-appropriate escaping (FP), a constant
filter (FP), a call that is not a directory query (FP), and an off-slice escaping
helper whose body is not in evidence (NMD).

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
_FAMILIES = {"java": "ldap_injection_java", "python": "ldap_injection_python"}

# A fully-resolved True-Positive assessment. Individual cases flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_LDAP_QUERY_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "filter_channel": {"value": "FILTER_OR_DN_TEXT_PATH_FOUND", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}


def _flip(slot, value, evidence=("L1",)):
    return {slot: {"value": value, "evidence": list(evidence)}}


_UNRESOLVED_COVERAGE = {"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}}

# (id, lang, rule, cwes, snippet, dataflow, overrides, expected verdict)
_PANEL = [
    # ── Java ──────────────────────────────────────────────────────────
    (
        "java-jndi-filter-concat",
        "java",
        "java/ldap-injection",
        ["CWE-90"],
        'String filter = "(&(objectClass=person)(uid=" + request.getParameter("uid") + "))";\n'
        'NamingEnumeration<SearchResult> r = ctx.search("ou=people,dc=example,dc=org", filter, sc);',
        'request.getParameter("uid") -> DirContext.search',
        None,
        "True Positive",
    ),
    (
        "java-dn-concat-with-filter-args",
        "java",
        "config.opengrep-rules.java.lang.security.audit.tainted-ldapi-from-http-request",
        ["CWE-90"],
        'String base = "ou=" + request.getParameter("dept") + ",dc=example,dc=org";\n'
        'ctx.search(base, "(uid={0})", new Object[] {user}, sc);',
        'request.getParameter("dept") -> DirContext.search',
        None,
        "True Positive",
    ),
    (
        "java-filter-escape-applied-to-a-dn",
        "java",
        "java.lang.security.audit.ldap-injection.ldap-injection",
        ["CWE-90"],
        'String dn = "uid=" + LdapEncoder.filterEncode(name) + ",ou=people,dc=example,dc=org";\n'
        "ldapTemplate.lookup(dn);",
        "@RequestParam name -> LdapTemplate.lookup",
        None,
        "True Positive",
    ),
    (
        "java-jndi-filter-args",
        "java",
        "java/ldap-injection",
        ["CWE-90"],
        'ctx.search("ou=people,dc=example,dc=org", "(&(objectClass=person)(uid={0}))",\n'
        '    new Object[] {request.getParameter("uid")}, sc);',
        'request.getParameter("uid") -> DirContext.search',
        _flip("filter_channel", "BOUND_DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "java-spring-query-builder",
        "java",
        "java/ldap-injection",
        ["CWE-90"],
        'LdapQuery q = LdapQueryBuilder.query().base("ou=people").where("uid").is(uid);\n'
        "return ldapTemplate.search(q, mapper);",
        "@PathVariable uid -> LdapTemplate.search",
        _flip("filter_channel", "BOUND_DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "java-filter-encode-in-filter-position",
        "java",
        "config.opengrep-rules.java.lang.security.audit.ldap-injection",
        ["CWE-90"],
        'String filter = "(mail=" + LdapEncoder.filterEncode(mail) + ")";\n'
        'ctx.search("ou=people,dc=example,dc=org", filter, sc);',
        "@RequestParam mail -> DirContext.search",
        _flip("neutralization_coverage", "ALL_REACHING_PATHS"),
        "False Positive",
    ),
    (
        "java-constant-filter",
        "java",
        "java.lang.security.audit.ldap-injection.ldap-injection",
        ["CWE-90"],
        'private static final String ADMINS = "(memberOf=cn=admins,ou=groups,dc=example,dc=org)";\n'
        "ctx.search(BASE_DN, ADMINS, sc);",
        "ADMINS -> DirContext.search",
        _flip("attacker_control", "REFUTED"),
        "False Positive",
    ),
    (
        "java-jndi-lookup-is-not-a-filter-or-dn-query",
        "java",
        "java/ldap-injection",
        ["CWE-90"],
        'Object ds = new InitialContext().lookup(request.getParameter("resource"));',
        'request.getParameter("resource") -> Context.lookup',
        _flip("sink_binding", "NOT_LDAP_QUERY_SINK"),
        "False Positive",
    ),
    (
        "java-project-helper-not-in-evidence",
        "java",
        "java/ldap-injection",
        ["CWE-90"],
        'String filter = "(uid=" + LdapUtil.clean(request.getParameter("uid")) + ")";\n'
        "ctx.search(BASE_DN, filter, sc);",
        'request.getParameter("uid") -> DirContext.search',
        _UNRESOLVED_COVERAGE,
        "Needs More Data",
    ),
    # ── Python ────────────────────────────────────────────────────────
    (
        "py-python-ldap-percent-format",
        "python",
        "py/ldap-injection",
        ["CWE-90"],
        "flt = '(&(objectClass=person)(uid=%s))' % request.args['uid']\n"
        "rows = conn.search_s('ou=people,dc=example,dc=org', ldap.SCOPE_SUBTREE, flt)",
        "request.args['uid'] -> search_s",
        None,
        "True Positive",
    ),
    (
        "py-ldap3-fstring-filter",
        "python",
        "vulnhunterx.python.ldap-injection",
        ["CWE-90"],
        "conn.search('dc=example,dc=org', f\"(mail={request.form['mail']})\", attributes=['cn'])",
        "request.form['mail'] -> Connection.search",
        None,
        "True Positive",
    ),
    (
        "py-filter-escape-applied-to-a-dn",
        "python",
        "py/ldap-injection",
        ["CWE-90"],
        "dn = 'uid=%s,ou=people,dc=example,dc=org' % escape_filter_chars(request.form['user'])\n"
        "conn.simple_bind_s(dn, request.form['password'])",
        "request.form['user'] -> simple_bind_s",
        None,
        "True Positive",
    ),
    (
        "py-filter-format",
        "python",
        "py/ldap-injection",
        ["CWE-90"],
        "flt = ldap.filter.filter_format('(&(objectClass=person)(uid=%s))', [request.args['uid']])\n"
        "rows = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, flt)",
        "request.args['uid'] -> search_s",
        _flip("filter_channel", "BOUND_DATA_ONLY_ALL_PATHS"),
        "False Positive",
    ),
    (
        "py-ldap3-escape-filter-chars",
        "python",
        "config.semgrep-custom.vulnhunterx.python.ldap-injection",
        ["CWE-90"],
        "safe = ldap3.utils.conv.escape_filter_chars(request.args['cn'])\n"
        "conn.search(BASE_DN, f'(cn={safe})')",
        "request.args['cn'] -> Connection.search",
        _flip("neutralization_coverage", "ALL_REACHING_PATHS"),
        "False Positive",
    ),
    (
        "py-escape-dn-chars-in-dn-position",
        "python",
        "py/ldap-injection",
        ["CWE-90"],
        "dn = 'uid=%s,ou=people,dc=example,dc=org' % ldap.dn.escape_dn_chars(request.form['user'])\n"
        "conn.simple_bind_s(dn, request.form['password'])",
        "request.form['user'] -> simple_bind_s",
        _flip("neutralization_coverage", "ALL_REACHING_PATHS"),
        "False Positive",
    ),
    (
        "py-constant-filter",
        "python",
        "py/ldap-injection",
        ["CWE-90"],
        "rows = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, '(objectClass=groupOfNames)')",
        "literal -> search_s",
        _flip("attacker_control", "REFUTED"),
        "False Positive",
    ),
    (
        "py-regex-search-is-not-a-directory-query",
        "python",
        "py/ldap-injection",
        ["CWE-90"],
        "match = UID_PATTERN.search(request.args['uid'])",
        "request.args['uid'] -> Pattern.search",
        _flip("sink_binding", "NOT_LDAP_QUERY_SINK"),
        "False Positive",
    ),
    (
        "py-project-helper-not-in-evidence",
        "python",
        "py/ldap-injection",
        ["CWE-90"],
        "flt = '(uid=%s)' % clean_uid(request.args['uid'])\n"
        "rows = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, flt)",
        "request.args['uid'] -> search_s",
        _UNRESOLVED_COVERAGE,
        "Needs More Data",
    ),
]

_SAMPLE = {
    "java": next(c for c in _PANEL if c[0] == "java-jndi-filter-concat"),
    "python": next(c for c in _PANEL if c[0] == "py-python-ldap-percent-format"),
}
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
def test_panel_has_every_outcome_per_language(lang):
    outcomes = {c[7] for c in _PANEL if c[1] == lang}
    assert outcomes == {"True Positive", "False Positive", "Needs More Data"}


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_is_ignored(mc, lang):
    # The model asserts a verdict; only the fact table decides.
    raw = json.loads(_assess(overrides=_flip("filter_channel", "BOUND_DATA_ONLY_ALL_PATHS")))
    raw["verdict"] = "True Positive"
    assert _run(mc, [json.dumps(raw)], _SAMPLE[lang]).verdict == "False Positive"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_coverage_claim_without_text_path_is_nmd(mc, lang):
    overrides = {
        "filter_channel": {"value": "UNRESOLVED", "evidence": []},
        **_flip("neutralization_coverage", "ALL_REACHING_PATHS"),
    }
    verdict = _run(mc, [_assess(overrides=overrides)] * 5, _SAMPLE[lang])
    assert verdict.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_bound_data_claim_cited_to_dataflow_only_is_nmd(mc, lang):
    # "Safe on all paths" needs the construction itself (local slice or an
    # exhaustive retrieval); the scanner dataflow witnesses one path only.
    overrides = _flip("filter_channel", "BOUND_DATA_ONLY_ALL_PATHS", evidence=("D1",))
    verdict = _run(mc, [_assess(overrides=overrides)] * 5, _SAMPLE[lang])
    assert verdict.verdict == "Needs More Data"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_escaping_helper_non_exhaustive_is_nmd(mc, lang):
    # An ALL_REACHING_PATHS claim supported only by a non-exhaustive retrieved
    # helper is inadmissible -> stays Needs More Data.
    responses = [
        _assess(
            overrides=_UNRESOLVED_COVERAGE,
            requests=[
                {
                    "kind": "function",
                    "subject": "escape_ldap_value",
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
def test_offslice_escaping_helper_exhaustive_is_fp(mc, lang):
    responses = [
        _assess(
            overrides=_UNRESOLVED_COVERAGE,
            requests=[
                {
                    "kind": "function",
                    "subject": "escape_ldap_value",
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
    "java": ("LdapEncoder.filterEncode", "filterArgs", "LdapQueryBuilder"),
    "python": ("ldap.filter.filter_format", "escape_dn_chars", "ldap3.utils.conv"),
}


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_overlay_carries_the_family_guidance_and_no_verdict_command(lang):
    _finding_, controller = _controller(_SAMPLE[lang])
    instr = controller.initial_instructions()
    for slot in _BASE:
        assert slot in instr
    assert "production_scope" in instr
    assert "security_effect" not in instr
    assert "[L1]" in instr and "[D1]" in instr
    for marker in _LANGUAGE_MARKERS[lang]:
        assert marker in instr, marker
    for other in set(_LANGUAGE_MARKERS) - {lang}:
        assert _LANGUAGE_MARKERS[other][0] not in instr
    policy = _REG.resolve_family(cwe_ids=[], rule_id=_SAMPLE[lang][2], lang=lang)
    guidance = " ".join(policy.assessment_guidance)
    assert policy.assessment_guidance[0] in instr
    for text in (instr, guidance):
        assert not _VERDICT_CMD.search(text)
        assert not _PAREN_LABEL.search(text)
        assert not _BENCHMARK.search(text)
