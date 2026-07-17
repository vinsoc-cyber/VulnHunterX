# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Declarative per-policy admissibility (P2c S2).

Admissibility dispatches on a policy-declared ``(slot, value) -> profile`` map,
not on hardcoded slot names. This is what makes the layer family-generic: a new
family's slots become admissible by declaring profiles from the fixed named set,
with no code branch. A value with no declared profile fails closed.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceRequest,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
)
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import (
    PolicyError,
    load_policy_from_mapping,
    load_policy_registry,
)
from vuln_hunter_x.verification.policy.support import PROFILE_NAMES, is_admissible

_CWE117 = load_policy_registry().resolve_family(cwe_ids=["CWE-117"], rule_id="js/log-injection")
_REF = SourceRef("nodegoat", "javascript", "app/routes/session.js", 60, 70)


def _retrieved(status, *, exhaustive=True, kind=EvidenceKind.FUNCTION, scope=EvidenceScope.REPOSITORY_INDEX):
    req = EvidenceRequest(kind=kind, subject="e", raw_request="function:e")
    return EvidenceLedger().add_retrieved(
        EvidenceResult(
            request=req, status=status, prompt_content="x", scope=scope, exhaustive=exhaustive
        )
    )


def _local(text="x"):
    return EvidenceLedger().add_local_slice(_REF, text)


def _bare_policy(**over):
    data = {
        "family": "bare",
        "selectors": {"cwes": ["CWE-999"]},
        "fact_slots": {"s": ["A", "B"]},
        "decisive_slots": ["s"],
        "entailment": {"true_positive": {"s": "A"}, "false_positive_if_any": []},
        "admissibility": {"s": {"A": "LOCAL_POSITIVE", "B": "LOCAL_POSITIVE"}},
    }
    data.update(over)
    return load_policy_from_mapping(data)


def test_profile_lookup_drives_admissibility():
    # neutralization_coverage=ALL_REACHING_PATHS resolves to the EXHAUSTIVE_ENCODER profile.
    assert is_admissible(
        _CWE117, "neutralization_coverage", "ALL_REACHING_PATHS",
        [_retrieved(EvidenceStatus.FOUND, exhaustive=True)],
    )
    assert not is_admissible(
        _CWE117, "neutralization_coverage", "ALL_REACHING_PATHS",
        [_retrieved(EvidenceStatus.FOUND, exhaustive=False)],
    )


def test_declared_local_profile():
    assert is_admissible(_CWE117, "attacker_control", "REFUTED", [_local()])


def test_undeclared_slot_value_fails_closed():
    # A value with no declared profile is inadmissible even with a strong citation.
    assert not is_admissible(_CWE117, "attacker_control", "NOT_A_VALUE", [_local()])


def test_loader_rejects_policy_without_admissibility():
    # Such a policy would load and then admit nothing, so every decisive slot would
    # stay unresolved and the family would answer Needs-More-Data forever. Reject it
    # at load rather than fail silently at verdict time.
    with pytest.raises(PolicyError, match="no admissibility profile"):
        _bare_policy(admissibility={})


def test_loader_rejects_unknown_profile_name():
    with pytest.raises(PolicyError):
        _bare_policy(admissibility={"s": {"A": "NO_SUCH_PROFILE"}})


def test_loader_rejects_admissibility_for_undeclared_value():
    with pytest.raises(PolicyError):
        _bare_policy(admissibility={"s": {"NOPE": "LOCAL_POSITIVE"}})


def test_known_profiles_present():
    assert {"LOCAL_POSITIVE", "EXHAUSTIVE_ENCODER", "CONCRETE_PATH", "ANY_CITATION"} <= PROFILE_NAMES
