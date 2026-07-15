# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Pure policy core: loader (selectors + overlap) and declarative entailment.

These tests exercise the family-policy layer in isolation — no LLM, no engine,
no evidence retrieval. They pin (a) how a finding selects a family policy,
(b) that overlapping selectors fail closed, and (c) the TP/FP/NMD entailment
truth table on already-resolved facts.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.loader import (
    PolicyError,
    PolicyOverlapError,
    PolicyRegistry,
    load_policy_from_mapping,
    load_policy_registry,
)
from vuln_hunter_x.verification.policy.models import FP, NMD, TP, FamilyPolicy

# ---- a small, self-contained policy for entailment mechanics ----

_TOY_MAPPING = {
    "family": "log_injection",
    "selectors": {"cwes": ["CWE-117"], "rule_aliases": ["*/log-injection"]},
    "fact_slots": {
        "sink_binding": ["QUALIFYING_LOG_SINK", "NOT_LOG_SINK"],
        "attacker_control": ["PROVEN", "REFUTED"],
        "flow_to_sink": ["REACHES", "NO_PATH_COMPLETE"],
        "record_boundary": ["BREAKABLE", "PRESERVED"],
        "neutralization_coverage": [
            "BYPASS_PATH_FOUND",
            "ALL_REACHING_PATHS",
            "NONE_FOUND_COMPLETE",
        ],
    },
    "decisive_slots": [
        "sink_binding",
        "attacker_control",
        "flow_to_sink",
        "record_boundary",
        "neutralization_coverage",
    ],
    "entailment": {
        "true_positive": {
            "sink_binding": "QUALIFYING_LOG_SINK",
            "attacker_control": "PROVEN",
            "flow_to_sink": "REACHES",
            "record_boundary": "BREAKABLE",
            "neutralization_coverage": ["BYPASS_PATH_FOUND", "NONE_FOUND_COMPLETE"],
        },
        "false_positive_if_any": [
            {"sink_binding": "NOT_LOG_SINK"},
            {"attacker_control": "REFUTED"},
            {"flow_to_sink": "NO_PATH_COMPLETE"},
            {"record_boundary": "PRESERVED"},
            {"neutralization_coverage": "ALL_REACHING_PATHS"},
        ],
    },
}

_TP_FACTS = {
    "sink_binding": "QUALIFYING_LOG_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "record_boundary": "BREAKABLE",
    "neutralization_coverage": "BYPASS_PATH_FOUND",
}


def _toy() -> FamilyPolicy:
    return load_policy_from_mapping(_TOY_MAPPING)


# ---- loader: parsing + selectors + overlap ----

def test_load_from_mapping_parses_fields():
    p = _toy()
    assert p.family == "log_injection"
    assert "CWE-117" in p.cwes
    assert p.rule_aliases == ("*/log-injection",)
    assert p.fact_slots["attacker_control"] == ("PROVEN", "REFUTED")
    assert "neutralization_coverage" in p.decisive_slots


def test_resolve_family_matches_by_cwe():
    reg = PolicyRegistry([_toy()])
    assert reg.resolve_family(cwe_ids=["CWE-117"], rule_id="js/some-rule").family == "log_injection"


def test_resolve_family_matches_by_rule_alias_glob():
    reg = PolicyRegistry([_toy()])
    assert reg.resolve_family(cwe_ids=[], rule_id="js/log-injection").family == "log_injection"


def test_resolve_family_none_when_uncovered():
    reg = PolicyRegistry([_toy()])
    assert reg.resolve_family(cwe_ids=["CWE-89"], rule_id="js/sql-injection") is None


def test_overlapping_policies_fail_closed():
    # Two families that both select CWE-117 must raise, never silently pick one.
    other = load_policy_from_mapping({**_TOY_MAPPING, "family": "other_family"})
    reg = PolicyRegistry([_toy(), other])
    with pytest.raises(PolicyOverlapError):
        reg.resolve_family(cwe_ids=["CWE-117"], rule_id="js/log-injection")


def test_malformed_policy_undeclared_entailment_value_rejected():
    # An entailment condition referencing a value not declared in fact_slots is
    # a policy authoring bug and must fail closed at load time, not silently.
    bad = {
        **_TOY_MAPPING,
        "entailment": {
            "true_positive": {"attacker_control": "NOT_A_DECLARED_VALUE"},
            "false_positive_if_any": [],
        },
    }
    with pytest.raises(PolicyError):
        load_policy_from_mapping(bad)


def test_real_log_injection_policy_ships_and_loads():
    reg = load_policy_registry()
    p = reg.resolve_family(cwe_ids=["CWE-117"], rule_id="js/log-injection")
    assert p is not None
    assert p.family == "log_injection"
    # Decisive slots must include the off-slice-retrieval one.
    assert "neutralization_coverage" in p.decisive_slots


# ---- entailment truth table (facts already resolved) ----

def test_entail_true_positive():
    d = entail(_toy(), _TP_FACTS)
    assert d.verdict == TP


def test_entail_true_positive_with_complete_absence_neutralizer():
    facts = {**_TP_FACTS, "neutralization_coverage": "NONE_FOUND_COMPLETE"}
    assert entail(_toy(), facts).verdict == TP


def test_entail_false_positive_when_refuted_control():
    facts = {**_TP_FACTS, "attacker_control": "REFUTED"}
    d = entail(_toy(), facts)
    assert d.verdict == FP
    assert "attacker_control" in (d.terminal_reason or "")


def test_entail_false_positive_when_fully_neutralized():
    facts = {**_TP_FACTS, "neutralization_coverage": "ALL_REACHING_PATHS"}
    assert entail(_toy(), facts).verdict == FP


def test_entail_false_positive_when_not_a_log_sink():
    facts = {**_TP_FACTS, "sink_binding": "NOT_LOG_SINK"}
    assert entail(_toy(), facts).verdict == FP


def test_entail_nmd_when_decisive_slot_unresolved():
    facts = dict(_TP_FACTS)
    del facts["neutralization_coverage"]  # the off-slice fact is missing
    d = entail(_toy(), facts)
    assert d.verdict == NMD
    assert "neutralization_coverage" in (d.terminal_reason or "")


def test_entail_fp_takes_precedence_over_partial_tp():
    # A single sufficient FP condition (fully neutralized) resolves to FP even
    # when the attacker-control / flow slots look TP-ish.
    facts = {
        "sink_binding": "QUALIFYING_LOG_SINK",
        "attacker_control": "PROVEN",
        "flow_to_sink": "REACHES",
        "record_boundary": "BREAKABLE",
        "neutralization_coverage": "ALL_REACHING_PATHS",
    }
    assert entail(_toy(), facts).verdict == FP


def test_entail_records_resolved_facts_and_family():
    d = entail(_toy(), _TP_FACTS)
    assert d.family == "log_injection"
    assert d.facts["attacker_control"] == "PROVEN"
