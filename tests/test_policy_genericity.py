# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Genericity proof (P2c X1): the policy core carries a 2nd family with new
decisive slots and NO code change to loader/entailment/schema/closure/support.

XPath-injection (CWE-643) declares ``query_position`` + ``security_effect`` slots
that CWE-117 never had; they load, entail, and parse through the same generic
machinery.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.context.evidence import SourceRef
from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import (
    PolicyOverlapError,
    PolicyRegistry,
    load_policy_from_mapping,
    load_policy_registry,
)
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.schema import parse_assessment

_REG = load_policy_registry()
_XPATH = _REG.resolve_family(cwe_ids=["CWE-643"], rule_id="py/xpath-injection", lang="python")

_TP_FACTS = {
    "sink_binding": "QUALIFYING_XPATH_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "query_position": "EXPRESSION_PATH_FOUND",
    "neutralization_coverage": "BYPASS_PATH_FOUND",
    "security_effect": "SECURITY_RELEVANT_EFFECT",
}


def test_both_families_load():
    assert "log_injection" in _REG.families
    assert "xpath_injection" in _REG.families


def test_xpath_has_new_decisive_slots():
    assert "query_position" in _XPATH.fact_slots
    assert "security_effect" in _XPATH.fact_slots
    assert "query_position" in _XPATH.decisive_slots
    assert "record_boundary" not in _XPATH.fact_slots


def test_entail_tp():
    assert entail(_XPATH, _TP_FACTS).verdict == TP


def test_entail_bound_data_is_fp():
    facts = {**_TP_FACTS, "query_position": "BOUND_DATA_ONLY_ALL_PATHS"}
    assert entail(_XPATH, facts).verdict == FP


def test_entail_no_security_effect_is_fp():
    facts = {**_TP_FACTS, "security_effect": "NO_SECURITY_EFFECT"}
    assert entail(_XPATH, facts).verdict == FP


def test_entail_missing_query_position_is_nmd():
    facts = {k: v for k, v in _TP_FACTS.items() if k != "query_position"}
    d = entail(_XPATH, facts)
    assert d.verdict == NMD
    assert "query_position" in (d.terminal_reason or "")


def test_new_slot_parses_with_no_schema_change():
    led = EvidenceLedger()
    led.add_local_slice(SourceRef("app", "python", "x.py", 1, 3), "root.xpath('//u[@n=\"' + u + '\"]')")
    raw = {
        "fact_slots": {"query_position": {"value": "EXPRESSION_PATH_FOUND", "evidence": ["L1"]}},
        "reasoning": "user in expression",
    }
    a = parse_assessment(raw, _XPATH, led)
    assert a.fact_claims["query_position"].value == "EXPRESSION_PATH_FOUND"


def test_overlap_still_fails_closed():
    dup = load_policy_from_mapping({
        "family": "dup_xpath",
        "selectors": {"languages": ["python"], "cwes": ["CWE-643"]},
        "fact_slots": {"sink_binding": ["A", "B"]},
        "decisive_slots": ["sink_binding"],
        "entailment": {"true_positive": {"sink_binding": "A"}, "false_positive_if_any": []},
    })
    reg = PolicyRegistry([_XPATH, dup])
    with pytest.raises(PolicyOverlapError):
        reg.resolve_family(cwe_ids=["CWE-643"], rule_id="py/xpath-injection", lang="python")
