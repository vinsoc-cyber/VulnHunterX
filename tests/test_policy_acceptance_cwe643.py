# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic CWE-643 (XPath-injection) acceptance panel — the P2c ship
criterion for the 2nd family.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM:
  1. direct expression concatenation w/ security effect  -> TP
  2. fixed expression + lxml variable binding             -> FP
  3. safe binding but a separately-tainted operand        -> TP
  4. enforced full-string allowlist on every path         -> FP
  5. apostrophe/prefix-only filter (incomplete)           -> TP
  6. off-slice helper found but coverage unresolved       -> NMD
  7. ignored / non-security-relevant query result         -> FP
  8. incomplete index                                     -> NMD w/ precise reason
Plus the assessment overlay carries the XPath fact slots + guidance.

Scripted tests prove policy/control correctness, NOT model semantic quality
(that is measured on real models at P6).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

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

_POLICY = load_policy_registry().resolve_family(
    cwe_ids=["CWE-643"], rule_id="py/xpath-injection", lang="python"
)

_BASE = {
    "sink_binding": {"value": "QUALIFYING_XPATH_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "query_position": {"value": "EXPRESSION_PATH_FOUND", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
    "security_effect": {"value": "SECURITY_RELEVANT_EFFECT", "evidence": ["L1"]},
}


def _finding():
    return Finding(
        rule_id="py/xpath-injection", message="m", file="app/auth.py",
        start_line=42, end_line=42, repo_name="synthetic", lang="python",
        cwe_ids=["CWE-643"], dataflow_path=["request.args['u']", "root.xpath"],
    )


def _q():
    return GuidedQuestions(rule_id="py/xpath-injection", short_description="d", questions=["q?"])


def _seeded():
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("synthetic", "python", "app/auth.py", 38, 46),
        "root.xpath(\"//user[name='\" + request.args['u'] + \"']\")",
    )
    led.add_scanner_dataflow("request.args['u'] -> root.xpath")
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
                request=r, status=self._status, prompt_content="// helper",
                scope=EvidenceScope.REPOSITORY_INDEX, exhaustive=self._exhaustive,
            )
        return out


def _run(mock_completion, responses, *, provider=None, max_iterations=5):
    mock_completion.side_effect = [_resp(r) for r in responses]
    controller = PolicyClosureController(
        policy=_POLICY, provider=provider or MagicMock(), finding=_finding(),
        model="gpt-4o", ledger=_seeded(), max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=_finding(), context="root.xpath(...)", questions=_q(), func_name="h",
        force_decision=False, decision_strategy=controller,
        max_iterations=max_iterations, quiet=True,
    )


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case1_direct_expression_concat_is_tp(mc):
    assert _run(mc, [_assess()]).verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case2_variable_binding_is_fp(mc):
    v = _run(mc, [_assess(overrides={
        "query_position": {"value": "BOUND_DATA_ONLY_ALL_PATHS", "evidence": ["L1"]}
    })])
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case3_binding_with_tainted_operand_is_tp(mc):
    # One operand is bound, but another is concatenated into the expression: the
    # bypass path is witnessed via the scanner dataflow.
    v = _run(mc, [_assess(overrides={
        "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["D1"]}
    })])
    assert v.verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case4_full_string_allowlist_is_fp(mc):
    v = _run(mc, [_assess(overrides={
        "neutralization_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["L1"]}
    })])
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case5_incomplete_filter_is_tp(mc):
    # An apostrophe-only filter leaves a bypass path -> still a witnessed bypass.
    assert _run(mc, [_assess()]).verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case6_offslice_helper_unresolved_is_nmd(mc):
    responses = [
        _assess(
            overrides={"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "sanitize_xpath",
                       "for_slot": "neutralization_coverage"}],
        ),
        # helper found but not exhaustive over paths -> ALL_REACHING_PATHS inadmissible
        _assess(overrides={
            "neutralization_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["R1"]}
        }),
    ]
    v = _run(mc, responses, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False))
    assert v.verdict == "Needs More Data"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case7_non_security_result_is_fp(mc):
    v = _run(mc, [_assess(overrides={
        "security_effect": {"value": "NO_SECURITY_EFFECT", "evidence": ["L1"]}
    })])
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case8_incomplete_index_is_nmd_with_reason(mc):
    responses = [
        _assess(
            overrides={"flow_to_sink": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "handler",
                       "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides={"flow_to_sink": {"value": "REACHES", "evidence": ["R1"]}}),
    ]
    v = _run(mc, responses, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert v.verdict == "Needs More Data"
    assert "flow_to_sink" in v.reasoning


def test_overlay_has_xpath_slots_and_guidance():
    controller = PolicyClosureController(
        policy=_POLICY, provider=MagicMock(), finding=_finding(), model="gpt-4o", ledger=_seeded()
    )
    instr = controller.initial_instructions()
    assert "query_position" in instr
    assert "security_effect" in instr
    assert "variable binding" in instr  # neutral assessment guidance
    assert "[L1]" in instr and "[D1]" in instr
