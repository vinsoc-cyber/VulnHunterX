# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Per-sample closure controller: assess -> support -> retrieve/repair/finalize/abstain.

Driven by scripted parsed responses + a fake typed provider — no real LLM. Pins
the obligation-driven state machine: an inadmissibly-cited fact never finalizes,
an unresolved decisive slot drives reactive retrieval, budget exhaustion and a
second schema failure both abstain to honest NMD.
"""

from __future__ import annotations

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceRequest,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
)
from vuln_hunter_x.core.types import Finding
from vuln_hunter_x.llm.decision_strategy import Abstain, Finalize, Repair, Retrieve
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP

_POLICY = load_policy_registry().resolve_family(cwe_ids=["CWE-117"], rule_id="js/log-injection")


def _finding() -> Finding:
    return Finding(
        rule_id="js/log-injection",
        message="log injection",
        file="app/routes/session.js",
        start_line=64,
        end_line=64,
        repo_name="nodegoat",
        lang="javascript",
        cwe_ids=["CWE-117"],
        dataflow_path=["req.body.userName", "console.log"],
    )


def _seeded_ledger() -> EvidenceLedger:
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("nodegoat", "javascript", "app/routes/session.js", 60, 70),
        "console.log('user ' + userName)",
    )  # L1
    led.add_scanner_dataflow("req.body.userName -> console.log")  # D1
    return led


class _FakeProvider:
    """resolve_evidence returns a scripted EvidenceResult per request."""

    def __init__(self, result_fn):
        self._result_fn = result_fn
        self.calls: list[str] = []

    def resolve_evidence(self, repo_name, lang, requests):
        out = {}
        for r in requests:
            self.calls.append(r.raw_request)
            out[r.raw_request] = self._result_fn(r)
        return out


def _result(status, *, exhaustive=True, kind=EvidenceKind.FUNCTION, scope=EvidenceScope.REPOSITORY_INDEX):
    def _fn(req: EvidenceRequest) -> EvidenceResult:
        return EvidenceResult(
            request=req, status=status, prompt_content="// encoder body",
            scope=scope, exhaustive=exhaustive,
        )
    return _fn


def _ctrl(provider, *, ledger=None, max_retrieval_rounds=2):
    from vuln_hunter_x.verification.policy.closure import PolicyClosureController

    return PolicyClosureController(
        policy=_POLICY,
        provider=provider,
        finding=_finding(),
        model="test-model",
        ledger=ledger or _seeded_ledger(),
        max_retrieval_rounds=max_retrieval_rounds,
    )


def _tp_ish(neutralization="UNRESOLVED", neut_ev=None, extra_request=True, subject="encodeForLog"):
    slots = {
        "sink_binding": {"value": "QUALIFYING_LOG_SINK", "evidence": ["L1"]},
        "attacker_control": {"value": "PROVEN", "evidence": ["D1", "L1"]},
        "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
        "record_boundary": {"value": "BREAKABLE", "evidence": ["L1"]},
        "neutralization_coverage": {"value": neutralization, "evidence": neut_ev or []},
    }
    raw = {"fact_slots": slots, "reasoning": "userName flows to console.log"}
    if extra_request:
        raw["evidence_requests"] = [
            {"kind": "function", "subject": subject, "for_slot": "neutralization_coverage"}
        ]
    return raw


# ---- finalize ----

def test_all_admissible_bypass_finalizes_tp():
    ctrl = _ctrl(_FakeProvider(_result(EvidenceStatus.NOT_FOUND_COMPLETE)))
    parsed = _tp_ish(neutralization="BYPASS_PATH_FOUND", neut_ev=["L1"], extra_request=False)
    action = ctrl.evaluate(parsed)
    assert isinstance(action, Finalize)
    assert action.verdict.verdict == TP
    assert ctrl.last_decision.verdict == TP


def test_preserved_record_finalizes_fp_even_if_neutralization_unresolved():
    ctrl = _ctrl(_FakeProvider(_result(EvidenceStatus.FOUND)))
    parsed = _tp_ish(extra_request=False)
    parsed["fact_slots"]["record_boundary"] = {"value": "PRESERVED", "evidence": ["L1"]}
    action = ctrl.evaluate(parsed)
    assert isinstance(action, Finalize)
    assert action.verdict.verdict == FP


# ---- reactive retrieval then finalize ----

def test_unresolved_neutralization_triggers_retrieval_then_finalizes():
    provider = _FakeProvider(_result(EvidenceStatus.FOUND, exhaustive=True))
    ledger = _seeded_ledger()
    ctrl = _ctrl(provider, ledger=ledger)
    # round 1: neutralization unresolved + a request -> Retrieve (ledger grows R1)
    a1 = ctrl.evaluate(_tp_ish())
    assert isinstance(a1, Retrieve)
    assert provider.calls == ["function:encodeForLog"]
    assert ledger.has("R1")
    # round 2: model now cites the retrieved encoder as full coverage -> FP
    a2 = ctrl.evaluate(_tp_ish(neutralization="ALL_REACHING_PATHS", neut_ev=["R1"], extra_request=False))
    assert isinstance(a2, Finalize)
    assert a2.verdict.verdict == FP


# ---- anti-over-confirmation: inadmissible claim cannot finalize ----

def test_inadmissible_coverage_claim_does_not_finalize():
    # Model claims every reaching path is covered but cites only the local slice
    # (not an exhaustive retrieval) -> inadmissible -> treated as unresolved.
    ctrl = _ctrl(_FakeProvider(_result(EvidenceStatus.INCOMPLETE_INDEX)))
    parsed = _tp_ish(neutralization="ALL_REACHING_PATHS", neut_ev=["L1"], extra_request=False)
    action = ctrl.evaluate(parsed)
    assert not isinstance(action, Finalize)
    assert isinstance(action, Abstain)
    assert action.verdict.verdict == NMD


# ---- budget exhaustion -> NMD ----

def test_retrieval_budget_exhaustion_abstains_nmd():
    provider = _FakeProvider(_result(EvidenceStatus.INCOMPLETE_INDEX))  # never resolves
    ctrl = _ctrl(provider, max_retrieval_rounds=2)
    a1 = ctrl.evaluate(_tp_ish(subject="enc1"))
    assert isinstance(a1, Retrieve)
    a2 = ctrl.evaluate(_tp_ish(subject="enc2"))
    assert isinstance(a2, Retrieve)
    a3 = ctrl.evaluate(_tp_ish(subject="enc3"))
    assert isinstance(a3, Abstain)
    assert a3.verdict.verdict == NMD
    assert "budget" in (ctrl.last_decision.terminal_reason or "")


# ---- schema repair once, then abstain ----

def test_schema_error_triggers_one_repair_then_abstain():
    ctrl = _ctrl(_FakeProvider(_result(EvidenceStatus.FOUND)))
    bad = _tp_ish(extra_request=False)
    bad["fact_slots"]["attacker_control"] = {"value": "NONSENSE", "evidence": ["L1"]}
    a1 = ctrl.evaluate(bad)
    assert isinstance(a1, Repair)
    a2 = ctrl.evaluate(bad)  # still malformed
    assert isinstance(a2, Abstain)
    assert a2.verdict.verdict == NMD
    assert "model_failed_to_assess" in (ctrl.last_decision.terminal_reason or "")


def test_finalized_verdict_is_policy_sourced_and_carries_reasoning():
    ctrl = _ctrl(_FakeProvider(_result(EvidenceStatus.FOUND)))
    parsed = _tp_ish(neutralization="BYPASS_PATH_FOUND", neut_ev=["L1"], extra_request=False)
    v = ctrl.evaluate(parsed).verdict
    assert v.model == "test-model"
    assert v.finding.rule_id == "js/log-injection"
    assert "log_injection" in v.reasoning
