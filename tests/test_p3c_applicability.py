# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P3c Task 4: family applicability gate + internal PolicyAttempt.

A cross-family handoff must be able to conclude "this is not my family's sink"
WITHOUT that meaning False Positive — otherwise a wrong handoff manufactures a
dismissal (recreating #120). Applicability is a distinct, declarative outcome,
evaluated before entailment. A policy that declares a handoff_from block must
declare applicability (fail closed at load).
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.verification.policy.handoff import (
    PolicyAttempt,
    PolicyAttemptStatus,
    classify_applicability,
)
from vuln_hunter_x.verification.policy.loader import (
    PolicyError,
    load_policy_from_mapping,
)


def _with_applicability():
    return load_policy_from_mapping({
        "family": "path_access",
        "selectors": {"languages": ["php"], "cwes": ["CWE-22"]},
        "handoff_from": {"languages": ["php"], "rule_aliases": ["*/tainted-filename"]},
        "applicability": {
            "slot": "sink_binding",
            "applicable_values": ["QUALIFYING_PATH_ACCESS_SINK"],
            "not_applicable_values": ["NOT_PATH_ACCESS_SINK"],
        },
        "fact_slots": {"sink_binding": ["QUALIFYING_PATH_ACCESS_SINK", "NOT_PATH_ACCESS_SINK"]},
        "admissibility": {"sink_binding": {
            "QUALIFYING_PATH_ACCESS_SINK": "LOCAL_POSITIVE",
            "NOT_PATH_ACCESS_SINK": "LOCAL_POSITIVE",
        }},
        "decisive_slots": ["sink_binding"],
        "entailment": {"true_positive": {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}},
    })


def _without_applicability():
    return load_policy_from_mapping({
        "family": "log_injection",
        "selectors": {"cwes": ["CWE-117"]},
        "fact_slots": {"sink_binding": ["QUALIFYING_LOG_SINK", "NOT_LOG_SINK"]},
        "admissibility": {"sink_binding": {
            "QUALIFYING_LOG_SINK": "LOCAL_POSITIVE",
            "NOT_LOG_SINK": "LOCAL_POSITIVE",
        }},
        "decisive_slots": ["sink_binding"],
        "entailment": {
            "true_positive": {"sink_binding": "QUALIFYING_LOG_SINK"},
            "false_positive_if_any": [{"sink_binding": "NOT_LOG_SINK"}],
        },
    })


def test_not_applicable_value_classifies_not_applicable():
    p = _with_applicability()
    assert classify_applicability(p, {"sink_binding": "NOT_PATH_ACCESS_SINK"}) == "not_applicable"


def test_applicable_value_classifies_applicable():
    p = _with_applicability()
    assert classify_applicability(p, {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}) == "applicable"


def test_absent_applicability_slot_is_unresolved():
    p = _with_applicability()
    assert classify_applicability(p, {}) == "unresolved"


def test_family_without_applicability_is_always_applicable():
    # Existing families (no applicability block) are unaffected: NOT_LOG_SINK is
    # still their FP (via entailment), never a not-applicable handoff outcome.
    p = _without_applicability()
    assert classify_applicability(p, {"sink_binding": "NOT_LOG_SINK"}) == "applicable"


def test_handoff_without_applicability_fails_to_load():
    with pytest.raises(PolicyError, match="handoff_from requires applicability"):
        load_policy_from_mapping({
            "family": "bad",
            "selectors": {"languages": ["php"]},
            "handoff_from": {"rule_aliases": ["*/tainted-filename"]},
            "fact_slots": {"sink_binding": ["QUALIFYING_PATH_ACCESS_SINK", "NOT_PATH_ACCESS_SINK"]},
            "admissibility": {"sink_binding": {
                "QUALIFYING_PATH_ACCESS_SINK": "LOCAL_POSITIVE",
                "NOT_PATH_ACCESS_SINK": "LOCAL_POSITIVE",
            }},
            "decisive_slots": ["sink_binding"],
            "entailment": {"true_positive": {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}},
        })


def test_policy_attempt_holds_status_and_optional_verdict():
    a = PolicyAttempt(status=PolicyAttemptStatus.NOT_APPLICABLE)
    assert a.status is PolicyAttemptStatus.NOT_APPLICABLE
    assert a.verdict is None and a.decision is None
