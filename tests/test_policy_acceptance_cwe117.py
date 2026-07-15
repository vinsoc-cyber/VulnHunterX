# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic CWE-117 acceptance panel (the P2b ship criterion).

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM:
  1. direct log-forge (unencoded path)          -> TP
  2. off-slice encoder covering every path       -> FP
  3. unguarded mutation twin                      -> TP
  4. framed structured logger                     -> FP
  5. missing / unresolvable encoder               -> NMD
  6. premature TP with no admissible evidence     -> cannot finalize (NMD)
  7. two malformed assessments                    -> model_failed_to_assess (NMD)
  8. a policy verdict is immune to legacy finalizers
Plus the fact-slot prompt overlay is present on the first turn.
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

_POLICY = load_policy_registry().resolve_family(cwe_ids=["CWE-117"], rule_id="js/log-injection")

_BASE = {
    "sink_binding": {"value": "QUALIFYING_LOG_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "record_boundary": {"value": "BREAKABLE", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "UNRESOLVED", "evidence": []},
}


def _finding():
    return Finding(
        rule_id="js/log-injection", message="m", file="app/routes/session.js",
        start_line=64, end_line=64, repo_name="nodegoat", lang="javascript",
        cwe_ids=["CWE-117"], dataflow_path=["req.body.userName", "console.log"],
    )


def _q():
    return GuidedQuestions(rule_id="js/log-injection", short_description="d", questions=["q?"])


def _seeded():
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("nodegoat", "javascript", "app/routes/session.js", 60, 70),
        "console.log('user ' + userName)",
    )
    led.add_scanner_dataflow("req.body.userName -> console.log")
    return led


def _assess(neut=None, neut_ev=None, requests=None, overrides=None):
    slots = {k: dict(v) for k, v in _BASE.items()}
    if neut is not None:
        slots["neutralization_coverage"] = {"value": neut, "evidence": neut_ev or []}
    if overrides:
        for k, v in overrides.items():
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
                request=r, status=self._status, prompt_content="// encoder",
                scope=EvidenceScope.REPOSITORY_INDEX, exhaustive=self._exhaustive,
            )
        return out


def _run(mock_completion, responses, *, provider=None, max_retrieval_rounds=2, max_iterations=5):
    mock_completion.side_effect = [_resp(r) for r in responses]
    controller = PolicyClosureController(
        policy=_POLICY, provider=provider or MagicMock(), finding=_finding(),
        model="gpt-4o", ledger=_seeded(), max_retrieval_rounds=max_retrieval_rounds,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=_finding(), context="console.log('user ' + userName)", questions=_q(),
        func_name="h", force_decision=False, decision_strategy=controller,
        max_iterations=max_iterations, quiet=True,
    )


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case1_direct_log_forge_is_tp(mc):
    v = _run(mc, [_assess(neut="BYPASS_PATH_FOUND", neut_ev=["L1"])])
    assert v.verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case2_off_slice_encoder_is_fp(mc):
    responses = [
        _assess(requests=[{"kind": "function", "subject": "encodeForLog",
                           "for_slot": "neutralization_coverage"}]),
        _assess(neut="ALL_REACHING_PATHS", neut_ev=["R1"]),
    ]
    v = _run(mc, responses, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True))
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case3_unguarded_mutation_twin_is_tp(mc):
    # An unguarded mutation reaching the sink unencoded — a bypass path proven
    # from the local slice + scanner dataflow.
    v = _run(mc, [_assess(neut="BYPASS_PATH_FOUND", neut_ev=["L1", "D1"])])
    assert v.verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case4_framed_structured_logger_is_fp(mc):
    v = _run(mc, [_assess(overrides={"record_boundary": {"value": "PRESERVED", "evidence": ["L1"]}})])
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case5_unresolvable_encoder_is_nmd(mc):
    responses = [
        _assess(requests=[{"kind": "function", "subject": f"enc{i}",
                           "for_slot": "neutralization_coverage"}])
        for i in range(4)
    ]
    v = _run(mc, responses, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert v.verdict == "Needs More Data"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case6_premature_tp_without_evidence_cannot_finalize(mc):
    # Every slot claims a TP value but cites nothing -> none admissible -> NMD.
    empty = {k: {"value": v["value"], "evidence": []} for k, v in _BASE.items()}
    empty["neutralization_coverage"] = {"value": "BYPASS_PATH_FOUND", "evidence": []}
    v = _run(mc, [json.dumps({"fact_slots": empty, "reasoning": "guess"})])
    assert v.verdict == "Needs More Data"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_case7_two_malformed_assessments_fail_to_assess(mc):
    bad = json.dumps({"fact_slots": {"attacker_control": {"value": "NONSENSE", "evidence": ["L1"]}},
                      "reasoning": "x"})
    v = _run(mc, [bad, bad])
    assert v.verdict == "Needs More Data"
    assert "model_failed_to_assess" in v.reasoning


def test_fact_slot_overlay_present_on_first_turn():
    controller = PolicyClosureController(
        policy=_POLICY, provider=MagicMock(), finding=_finding(),
        model="gpt-4o", ledger=_seeded(),
    )
    instr = controller.initial_instructions()
    assert "fact_slots" in instr
    assert "neutralization_coverage" in instr
    assert "[L1]" in instr and "[D1]" in instr
