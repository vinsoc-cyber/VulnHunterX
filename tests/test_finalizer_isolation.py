# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Persisted decision provenance: a policy verdict serializes its decision_source
and its policy-decision record; a legacy verdict carries neither.

The batch verdict finalizers this file once guarded (cross-rule reconciliation
and sibling re-verification) were retired in #122 — a policy verdict is now
immune to post-hoc mutation because no such pass exists.
"""

from __future__ import annotations

from vuln_hunter_x.core.types import Finding, Verdict


def _v(verdict, *, rule="py/sql-injection", file="a.py", line=10, cwe="CWE-89",
       conf="Low", source="legacy_model"):
    f = Finding(
        rule_id=rule, message="m", file=file, start_line=line, end_line=line,
        repo_name="r", lang="python", cwe_ids=[cwe],
    )
    return Verdict(
        finding=f, verdict=verdict, confidence=conf, reasoning="r", answers=[],
        raw_response="", model="m", decision_source=source,
    )


def test_to_dict_emits_decision_source_and_policy_decision():
    v = _v("True Positive", source="policy")
    v.policy_decision = {
        "family": "log_injection", "version": "1", "terminal_reason": None,
        "facts": {"attacker_control": "PROVEN"}, "evidence_ids": ["L1"],
    }
    d = v.to_dict()
    assert d["decision_source"] == "policy"
    assert d["policy_decision"]["family"] == "log_injection"
    assert d["policy_decision"]["facts"]["attacker_control"] == "PROVEN"


def test_to_dict_legacy_has_no_policy_decision():
    d = _v("True Positive").to_dict()
    assert d["decision_source"] == "legacy_model"
    assert d.get("policy_decision") is None
