# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Strict covered-family assessment schema: parse + validate model output."""

from __future__ import annotations

import pytest

from vuln_hunter_x.context.evidence import EvidenceKind, SourceRef
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.schema import (
    UNRESOLVED,
    Assessment,
    SchemaError,
    parse_assessment,
)

_POLICY = load_policy_registry().resolve_family(cwe_ids=["CWE-117"], rule_id="js/log-injection")


def _ledger() -> EvidenceLedger:
    led = EvidenceLedger()
    led.add_local_slice(SourceRef("r", "javascript", "f.js", 60, 70), "console.log(userName)")
    led.add_scanner_dataflow("req.body.userName -> console.log")
    return led  # L1, D1


def _valid_raw() -> dict:
    return {
        "fact_slots": {
            "sink_binding": {"value": "QUALIFYING_LOG_SINK", "evidence": ["L1"]},
            "attacker_control": {"value": "PROVEN", "evidence": ["D1", "L1"]},
            "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
            "record_boundary": {"value": "BREAKABLE", "evidence": ["L1"]},
            "neutralization_coverage": {"value": "UNRESOLVED", "evidence": []},
        },
        "evidence_requests": [
            {"kind": "function", "subject": "encodeForLog", "for_slot": "neutralization_coverage"}
        ],
        "reasoning": "userName flows unencoded to console.log",
        "verdict": "True Positive",  # present but must be ignored
    }


def test_parse_valid_assessment():
    a = parse_assessment(_valid_raw(), _POLICY, _ledger())
    assert isinstance(a, Assessment)
    assert a.fact_claims["attacker_control"].value == "PROVEN"
    assert a.fact_claims["attacker_control"].evidence == ("D1", "L1")
    assert a.fact_claims["neutralization_coverage"].value == UNRESOLVED
    assert a.evidence_requests[0].kind is EvidenceKind.FUNCTION
    assert a.evidence_requests[0].for_slot == "neutralization_coverage"
    assert "unencoded" in a.reasoning


def test_resolved_claims_excludes_unresolved():
    a = parse_assessment(_valid_raw(), _POLICY, _ledger())
    resolved = a.resolved_facts()
    assert "neutralization_coverage" not in resolved
    assert resolved["attacker_control"] == "PROVEN"


def test_verdict_field_is_ignored():
    raw = _valid_raw()
    raw["verdict"] = "False Positive"
    a = parse_assessment(raw, _POLICY, _ledger())
    # No attribute derived from the model verdict; policy decides later.
    assert not hasattr(a, "verdict")


def test_unknown_slot_rejected():
    raw = _valid_raw()
    raw["fact_slots"]["made_up_slot"] = {"value": "X", "evidence": []}
    with pytest.raises(SchemaError):
        parse_assessment(raw, _POLICY, _ledger())


def test_unknown_enum_value_rejected():
    raw = _valid_raw()
    raw["fact_slots"]["attacker_control"] = {"value": "MAYBE", "evidence": ["L1"]}
    with pytest.raises(SchemaError):
        parse_assessment(raw, _POLICY, _ledger())


def test_resolved_value_citing_missing_evidence_id_rejected():
    raw = _valid_raw()
    raw["fact_slots"]["attacker_control"] = {"value": "PROVEN", "evidence": ["R9"]}
    with pytest.raises(SchemaError):
        parse_assessment(raw, _POLICY, _ledger())


def test_unresolved_with_empty_evidence_is_ok():
    raw = _valid_raw()
    raw["fact_slots"]["flow_to_sink"] = {"value": UNRESOLVED, "evidence": []}
    a = parse_assessment(raw, _POLICY, _ledger())
    assert a.fact_claims["flow_to_sink"].value == UNRESOLVED


def test_evidence_request_for_unknown_slot_rejected():
    raw = _valid_raw()
    raw["evidence_requests"] = [{"kind": "function", "subject": "x", "for_slot": "nope"}]
    with pytest.raises(SchemaError):
        parse_assessment(raw, _POLICY, _ledger())


def test_missing_fact_slots_rejected():
    with pytest.raises(SchemaError):
        parse_assessment({"reasoning": "x"}, _POLICY, _ledger())


def test_fact_slots_not_a_mapping_rejected():
    with pytest.raises(SchemaError):
        parse_assessment({"fact_slots": ["a", "b"]}, _POLICY, _ledger())
