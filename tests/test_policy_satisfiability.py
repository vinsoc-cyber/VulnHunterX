# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""A policy may only offer fact values the evidence layer can substantiate.

An admissibility profile that no producible evidence can satisfy is a trap: the
model picks the value the code plainly warrants, cites the best evidence it has,
and the claim is silently rejected — turning a real finding into Needs-More-Data.
These tests pin the emit space the profiles are checked against, and the loader
gate that rejects such a policy.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.context import evidence as evidence_mod
from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceStatus,
    inspect_capability,
)
from vuln_hunter_x.verification.policy import support
from vuln_hunter_x.verification.policy.loader import (
    PolicyError,
    load_policy_from_mapping,
    load_policy_registry,
)

_FRAMEWORK = {EvidenceKind.FRAMEWORK_SANITIZERS, EvidenceKind.FRAMEWORK_GUARDS}


# ---- the absence-authority rule has exactly one source of truth ----


def test_absence_authority_is_framework_only():
    assert evidence_mod.authoritative_for_absence(EvidenceKind.FRAMEWORK_SANITIZERS)
    assert evidence_mod.authoritative_for_absence(EvidenceKind.FRAMEWORK_GUARDS)
    assert not evidence_mod.authoritative_for_absence(EvidenceKind.FUNCTION)
    assert not evidence_mod.authoritative_for_absence(EvidenceKind.CALLER)


def test_inspect_capability_uses_the_same_rule(tmp_path):
    # One rule, consumed by both the runtime status mapping and the static emit
    # space — so a future change cannot move one without the other.
    for kind in EvidenceKind:
        cap = inspect_capability(tmp_path, "javascript", kind)
        assert cap.authoritative_for_absence == evidence_mod.authoritative_for_absence(kind)


# ---- the static emit space ----


def test_emit_space_never_pairs_not_found_complete_with_a_non_framework_kind():
    # provider._absence_status reports NOT_FOUND_COMPLETE only when the capability
    # is authoritative for absence, and that is framework-only; the framework greps
    # (provider.py:1198/:1250) carry framework kinds by construction.
    bad = [
        e
        for e in support.producible_witnesses()
        if e.status is EvidenceStatus.NOT_FOUND_COMPLETE and e.kind not in _FRAMEWORK
    ]
    assert bad == []


def test_emit_space_covers_the_seed_origins():
    origins = {e.origin for e in support.producible_witnesses()}
    assert len(origins) == 3  # local slice, scanner dataflow, retrieved


# ---- profile satisfiability ----


def test_complete_repo_absence_is_unsatisfiable():
    # Requires NOT_FOUND_COMPLETE *and* a non-framework kind. Every producible
    # NOT_FOUND_COMPLETE carries a framework kind, so the two demands are mutually
    # exclusive: no evidence the toolchain can ever emit satisfies it.
    assert not support.is_profile_satisfiable("COMPLETE_REPO_ABSENCE")


def test_every_other_profile_is_satisfiable():
    others = set(support.PROFILE_NAMES) - {"COMPLETE_REPO_ABSENCE"}
    assert {p for p in others if not support.is_profile_satisfiable(p)} == set()


def test_unknown_profile_is_not_satisfiable():
    assert not support.is_profile_satisfiable("NO_SUCH_PROFILE")


def test_selectable_excludes_unsatisfiable_and_dormant():
    assert "COMPLETE_REPO_ABSENCE" not in support.SELECTABLE_PROFILES
    assert "CONCRETE_PATH" in support.SELECTABLE_PROFILES
    assert support.SELECTABLE_PROFILES <= support.PROFILE_NAMES


def test_dormant_profiles_are_never_selectable_even_if_satisfiable():
    # Satisfiability is not semantic correctness: promotion needs review, not a
    # side effect of some unrelated producer gaining authoritative absence.
    for name in support.DORMANT_PROFILES:
        assert name not in support.SELECTABLE_PROFILES


# ---- the loader gate ----


def _mapping(neut_values, neut_admissibility):
    return {
        "family": "toy",
        "selectors": {"cwes": ["CWE-117"], "rule_aliases": ["*/toy"]},
        "fact_slots": {"neutralization_coverage": list(neut_values)},
        "decisive_slots": ["neutralization_coverage"],
        "entailment": {
            "true_positive": {"neutralization_coverage": neut_values[0]},
            "false_positive_if_any": [{"neutralization_coverage": neut_values[-1]}],
        },
        "admissibility": {"neutralization_coverage": dict(neut_admissibility)},
    }


def test_unsatisfiable_profile_is_rejected():
    with pytest.raises(PolicyError, match="NONE_FOUND_COMPLETE"):
        load_policy_from_mapping(
            _mapping(
                ["BYPASS_PATH_FOUND", "NONE_FOUND_COMPLETE"],
                {
                    "BYPASS_PATH_FOUND": "CONCRETE_PATH",
                    "NONE_FOUND_COMPLETE": "COMPLETE_REPO_ABSENCE",
                },
            )
        )


def test_value_with_no_declared_profile_is_rejected():
    # Totality: support.is_admissible fails closed on a missing mapping, so an
    # undeclared value is inadmissible forever — the same trap, silently.
    with pytest.raises(PolicyError, match="no admissibility profile"):
        load_policy_from_mapping(
            _mapping(
                ["BYPASS_PATH_FOUND", "ALL_REACHING_PATHS"],
                {"BYPASS_PATH_FOUND": "CONCRETE_PATH"},
            )
        )


def test_satisfiable_and_total_policy_loads():
    p = load_policy_from_mapping(
        _mapping(
            ["BYPASS_PATH_FOUND", "ALL_REACHING_PATHS"],
            {"BYPASS_PATH_FOUND": "CONCRETE_PATH", "ALL_REACHING_PATHS": "EXHAUSTIVE_ENCODER"},
        )
    )
    assert p.family == "toy"


def test_all_bundled_policies_offer_only_substantiable_values():
    # The release gate: every shipped family must load under the check.
    assert sorted(load_policy_registry().families) == [
        "command_injection",
        "log_injection",
        "path_access",
        "sql_injection",
        "xpath_injection",
    ]
