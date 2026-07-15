# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P3c Task 5: non-destructive cross-family handoff combiner.

A route may SCHEDULE a policy but can never itself produce TP/FP. The combiner:
a handoff TP short-circuits (base never runs — the prose path is structurally
replaced); family_not_applicable and an applicable handoff FP fall through to
the base route (a handoff FP refutes only the candidate family); an unresolved
handoff lets a base TP win but downgrades a base FP to the handoff's honest NMD
(never erasing the unresolved real-bug possibility). Handoff assessment is
target-owned, not driven by the reported rule's questions.
"""

from __future__ import annotations

from vuln_hunter_x.core.config import load_config
from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import VerificationEngine
from vuln_hunter_x.verification.policy.loader import PolicyRegistry, load_policy_from_mapping

_TAINTED_FILENAME = "php.lang.security.injection.tainted-filename.tainted-filename"


def _path_access(name: str = "path_access"):
    return load_policy_from_mapping({
        "family": name,
        "selectors": {"languages": ["php"], "cwes": ["CWE-22"]},
        "handoff_from": {"languages": ["php"], "rule_aliases": [_TAINTED_FILENAME]},
        "applicability": {
            "slot": "sink_binding",
            "applicable_values": ["QUALIFYING_PATH_ACCESS_SINK"],
            "not_applicable_values": ["NOT_PATH_ACCESS_SINK"],
        },
        "fact_slots": {"sink_binding": ["QUALIFYING_PATH_ACCESS_SINK", "NOT_PATH_ACCESS_SINK"]},
        "decisive_slots": ["sink_binding"],
        "entailment": {"true_positive": {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}},
    })


def _finding():
    # php tainted-filename (tagged SSRF): base route = legacy, handoff = path_access.
    return Finding(
        rule_id=_TAINTED_FILENAME, message="m", file="vulnerabilities/view_help.php",
        start_line=20, end_line=20, repo_name="dvwa", lang="php", cwe_ids=["CWE-918"],
    )


def _v(verdict: str, facts: dict, family: str = "path_access") -> Verdict:
    return Verdict(
        finding=_finding(), verdict=verdict, confidence="High", reasoning="r",
        answers=[], raw_response="", model="t", decision_source="policy",
        policy_decision={"family": family, "facts": facts},
    )


def _legacy(verdict: str) -> Verdict:
    return Verdict(
        finding=_finding(), verdict=verdict, confidence="High", reasoning="r",
        answers=[], raw_response="", model="t",
    )


def _engine(handoff_verdict: Verdict, base_verdict: Verdict | None = None):
    e = VerificationEngine(load_config())
    e._policy_registry = PolicyRegistry([_path_access()])
    e._captured_questions = "UNSET"

    def _policy(finding, policy, questions=None):
        e._captured_questions = questions
        return handoff_verdict

    e._verify_policy_finding = _policy
    e._legacy_calls = []

    def _leg(finding):
        e._legacy_calls.append(1)
        if base_verdict is None:
            raise AssertionError("legacy/base must not run")
        return base_verdict

    e._verify_legacy_finding = _leg
    return e


def test_handoff_tp_short_circuits_no_base_call():
    e = _engine(_v("True Positive", {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}))
    v = e._verify_single_finding(_finding())
    assert v.verdict == "True Positive"
    assert e._legacy_calls == []  # base never consulted; prose path replaced
    assert v.policy_decision["family"] == "path_access"


def test_handoff_not_applicable_runs_base_once():
    e = _engine(
        _v("Needs More Data", {"sink_binding": "NOT_PATH_ACCESS_SINK"}),
        base_verdict=_legacy("True Positive"),
    )
    v = e._verify_single_finding(_finding())
    assert e._legacy_calls == [1]
    assert v.verdict == "True Positive"  # base result; handoff contributed no verdict


def test_applicable_handoff_fp_falls_through_to_base():
    e = _engine(
        _v("False Positive", {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}),
        base_verdict=_legacy("True Positive"),
    )
    v = e._verify_single_finding(_finding())
    assert e._legacy_calls == [1]
    assert v.verdict == "True Positive"  # a handoff FP refutes only path-access


def test_unresolved_handoff_base_fp_becomes_handoff_nmd():
    e = _engine(
        _v("Needs More Data", {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}),
        base_verdict=_legacy("False Positive"),
    )
    v = e._verify_single_finding(_finding())
    assert v.verdict == "Needs More Data"
    assert v.policy_decision["family"] == "path_access"  # keeps handoff decision


def test_unresolved_handoff_base_tp_wins():
    e = _engine(
        _v("Needs More Data", {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}),
        base_verdict=_legacy("True Positive"),
    )
    v = e._verify_single_finding(_finding())
    assert v.verdict == "True Positive"


def test_multiple_handoff_targets_fail_closed():
    e = VerificationEngine(load_config())
    e._policy_registry = PolicyRegistry([_path_access("path_access"), _path_access("pa2")])

    def _no_base(finding):
        raise AssertionError("ambiguous handoff must fail closed before any base call")

    e._verify_legacy_finding = _no_base
    v = e._verify_single_finding(_finding())
    assert v.verdict == "Needs More Data"


def test_handoff_candidate_is_policy_routed_singleton():
    # Case identity must treat a handoff candidate as one-to-one (never merged),
    # mirroring native policy findings — P3b cross-rule equivalence stays closed.
    e = VerificationEngine(load_config())
    e._policy_registry = PolicyRegistry([_path_access()])
    assert e._is_policy_routed(_finding()) is True


def test_handoff_uses_target_owned_questions_not_reported_rule():
    e = _engine(_v("True Positive", {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}))
    e._verify_single_finding(_finding())
    q = e._captured_questions
    assert q is not None  # not the reported-rule default (which is None here)
    assert "tainted-filename" not in (getattr(q, "rule_id", "") or "")
