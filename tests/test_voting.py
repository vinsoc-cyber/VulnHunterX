# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Voting: global all-NMD-by-count fix + policy-decision aggregation."""

from __future__ import annotations

from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.verification.policy.models import FP, NMD, TP, PolicyDecision
from vuln_hunter_x.verification.policy.voting import aggregate_policy_decisions


def _v(verdict, score=0.8):
    f = Finding(
        rule_id="r", message="m", file="a.py", start_line=1, end_line=1,
        repo_name="r", lang="python",
    )
    return Verdict(
        finding=f, verdict=verdict, confidence="High", reasoning="x", answers=[],
        raw_response="", model="m", confidence_score=score,
    )


# ---- global _aggregate_votes fix ----

def test_all_nmd_aggregates_to_nmd_not_fp():
    v = LLMClient._aggregate_votes([_v("Needs More Data"), _v("Needs More Data"), _v("Needs More Data")])
    assert v.verdict == "Needs More Data"


def test_all_error_aggregates_to_error():
    v = LLMClient._aggregate_votes([_v("Error"), _v("Error")])
    assert v.verdict == "Error"


def test_nmd_majority_with_one_tp_picks_tp():
    v = LLMClient._aggregate_votes([_v("Needs More Data"), _v("Needs More Data"), _v("True Positive")])
    assert v.verdict == "True Positive"


def test_tp_fp_tie_still_uses_tie_break_fp():
    v = LLMClient._aggregate_votes([_v("True Positive", 0.5), _v("False Positive", 0.5)], tie_break="fp")
    assert v.verdict == "False Positive"


# ---- policy-decision aggregation ----

def _d(verdict, reason=None):
    return PolicyDecision(verdict, "log_injection", {"attacker_control": "PROVEN"}, terminal_reason=reason)


def test_policy_all_tp_is_tp():
    assert aggregate_policy_decisions([_d(TP), _d(TP)]).verdict == TP


def test_policy_all_fp_is_fp():
    assert aggregate_policy_decisions([_d(FP), _d(FP)]).verdict == FP


def test_policy_tp_and_fp_conflict_is_nmd_sample_disagreement():
    d = aggregate_policy_decisions([_d(TP), _d(FP)])
    assert d.verdict == NMD
    assert d.terminal_reason == "sample_disagreement"


def test_policy_binary_with_some_nmd_keeps_binary():
    assert aggregate_policy_decisions([_d(TP), _d(NMD, "unresolved: x")]).verdict == TP


def test_policy_all_nmd_is_nmd():
    assert aggregate_policy_decisions([_d(NMD, "unresolved: x"), _d(NMD, "budget")]).verdict == NMD


def test_policy_empty_is_nmd():
    assert aggregate_policy_decisions([]).verdict == NMD
