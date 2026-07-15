# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Policy-sourced verdicts are immune to the legacy batch finalizers.

The per-finding finalizers (arms, confidence downgraders) never run on a policy
verdict — it returns straight from _verify_policy_finding. This locks the two
BATCH finalizers that run over the mixed verdict list: reconciliation and
sibling re-verification must not mutate (or be influenced by) a policy verdict.
Also pins that decision_source + the policy decision record persist in to_dict.
"""

from __future__ import annotations

from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import (
    _reconcile_conflicting_verdicts,
    apply_sibling_consistency,
)


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


def test_reconcile_does_not_mutate_policy_verdict():
    # Same rule + same line: without the guard this same-rule tie would rewrite
    # the FP to TP. The policy verdict must be excluded and stay FP.
    policy_fp = _v("False Positive", source="policy")
    legacy_tp = _v("True Positive")
    _reconcile_conflicting_verdicts([policy_fp, legacy_tp])
    assert policy_fp.verdict == "False Positive"


def test_reconcile_still_reconciles_legacy_only_cluster():
    # Guard must not break legacy: a same-rule legacy tie still rewrites the FP.
    legacy_tp = _v("True Positive")
    legacy_fp = _v("False Positive")
    _reconcile_conflicting_verdicts([legacy_tp, legacy_fp])
    assert legacy_fp.verdict == "True Positive"


def test_sibling_reverify_skips_policy_members():
    calls = []

    def reverify(fp, tps):
        calls.append(fp)
        return _v("True Positive")

    policy_fp = _v("False Positive", source="policy", line=10)
    legacy_tp = _v("True Positive", line=20)  # same rule, sibling line
    apply_sibling_consistency([policy_fp, legacy_tp], reverify)
    assert policy_fp not in calls
    assert policy_fp.verdict == "False Positive"


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
