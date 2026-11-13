# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""XPath-injection (CWE-643) family for Java: selection + entailment.

The decision table is the class reference's (``xpath_injection``, Python),
unchanged: query_position (expression text vs. bound data), neutralization
coverage and security_effect decide alongside sink, control and reach. Only the
selectors and the guidance are Java-specific — the Python family is scoped to
Python because its guidance names lxml sinks and lxml variable binding.
"""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import SELECTABLE_PROFILES, is_admissible

_REG = load_policy_registry()
_POLICIES = {p.family: p for p in _REG._policies}
_JAVA = _POLICIES["xpath_injection_java"]
_REFERENCE = _POLICIES["xpath_injection"]
_POLICY_DIR = Path(__file__).resolve().parents[1] / "config" / "policies"

_TP_FACTS = {
    "sink_binding": "QUALIFYING_XPATH_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "query_position": "EXPRESSION_PATH_FOUND",
    "neutralization_coverage": "BYPASS_PATH_FOUND",
    "security_effect": "SECURITY_RELEVANT_EFFECT",
}

# (rule id, CWE tags the scanner attaches) — every id form that exists.
_OWNED = [
    ("java/xml/xpath-injection", ["CWE-643"]),
    ("java/xml/xpath-injection", []),
    ("java/xpath-injection", []),  # question-bank / benchmark-anchor id
    (
        "config.opengrep-rules.java.lang.security.audit.tainted-xpath-from-http-request",
        ["CWE-643"],
    ),
    (
        "java.lang.security.audit.tainted-xpath-from-http-request.tainted-xpath-from-http-request",
        [],
    ),
    ("some.other.scanner.rule", ["CWE-643"]),
]


# ── selection ─────────────────────────────────────────────────────────


def test_family_loads_with_matching_name_and_language():
    assert _JAVA.family == "xpath_injection_java"
    assert _JAVA.languages == frozenset({"java"})
    assert _JAVA.cwes == frozenset({"CWE-643"})
    assert _JAVA.version == "1"


@pytest.mark.parametrize(("rule", "cwes"), _OWNED)
def test_real_rule_ids_select_the_family(rule, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang="java")
    assert resolved is not None and resolved.family == "xpath_injection_java", rule


def test_python_xpath_still_selects_the_reference_family():
    resolved = _REG.resolve_family(cwe_ids=["CWE-643"], rule_id="py/xpath-injection", lang="python")
    assert resolved is not None and resolved.family == "xpath_injection"


@pytest.mark.parametrize(
    ("lang", "rule", "cwes"),
    [
        ("php", "php/xpath-injection", ["CWE-643"]),
        ("go", "go/xml/xpath-injection", ["CWE-643"]),
        ("csharp", "cs/xml/xpath-injection", ["CWE-643"]),
        ("javascript", "js/xpath-injection", ["CWE-643"]),
        ("go", "java/xml/xpath-injection", []),
        ("python", "java/xml/xpath-injection", []),
        ("", "java/xml/xpath-injection", ["CWE-643"]),
    ],
)
def test_language_gate(lang, rule, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang=lang)
    assert resolved is None or resolved.family != "xpath_injection_java"


@pytest.mark.parametrize(
    ("rule", "cwes"),
    [
        ("java/xslt-injection", ["CWE-74"]),
        ("java/xxe", ["CWE-611"]),
        ("java/ldap-injection", ["CWE-90"]),
    ],
)
def test_neighbouring_java_rules_are_not_claimed(rule, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang="java")
    assert resolved is None or resolved.family != "xpath_injection_java"


# ── decision table ────────────────────────────────────────────────────


def test_decision_table_equals_the_class_reference():
    assert _JAVA.fact_slots == _REFERENCE.fact_slots
    assert _JAVA.decisive_slots == _REFERENCE.decisive_slots
    assert _JAVA.true_positive == _REFERENCE.true_positive
    assert _JAVA.false_positive_if_any == _REFERENCE.false_positive_if_any
    assert _JAVA.admissibility == _REFERENCE.admissibility
    assert _JAVA.assessment_guidance != _REFERENCE.assessment_guidance


def test_decision_table_yaml_sections_equal_the_class_reference():
    java = yaml.safe_load((_POLICY_DIR / "xpath_injection_java.yaml").read_text(encoding="utf-8"))
    ref = yaml.safe_load((_POLICY_DIR / "xpath_injection.yaml").read_text(encoding="utf-8"))
    for section in ("fact_slots", "decisive_slots", "entailment", "admissibility"):
        assert java[section] == ref[section], section


def test_slots_and_profiles():
    assert set(_JAVA.decisive_slots) == set(_TP_FACTS)
    assert "production_scope" in _JAVA.fact_slots
    for slot, values in _JAVA.fact_slots.items():
        for value in values:
            assert _JAVA.admissibility[slot][value] in SELECTABLE_PROFILES, (slot, value)
    assert set(_JAVA.admissibility["production_scope"].values()) == {"ANY_CITATION"}
    # One guidance entry per decisive slot, in table order.
    for slot, text in zip(_TP_FACTS, _JAVA.assessment_guidance, strict=True):
        assert text.startswith(f"{slot}:")


def test_entail_tp():
    decision = entail(_JAVA, _TP_FACTS)
    assert decision.verdict == TP
    assert decision.family == "xpath_injection_java"


@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("sink_binding", "NOT_XPATH_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("query_position", "BOUND_DATA_ONLY_ALL_PATHS"),
        ("neutralization_coverage", "ALL_REACHING_PATHS"),
        ("security_effect", "NO_SECURITY_EFFECT"),
    ],
)
def test_each_dominating_value_is_fp(slot, value):
    decision = entail(_JAVA, {**_TP_FACTS, slot: value})
    assert decision.verdict == FP
    assert slot in (decision.terminal_reason or "")


@pytest.mark.parametrize("slot", sorted(_TP_FACTS))
def test_each_missing_decisive_slot_is_nmd(slot):
    facts = {k: v for k, v in _TP_FACTS.items() if k != slot}
    decision = entail(_JAVA, facts)
    assert decision.verdict == NMD
    assert decision.terminal_reason == f"unresolved: {slot}"


def test_production_scope_never_decides():
    for scope in ("TEST_ONLY", "EXAMPLE_DEV", "GENERATED_VENDOR", "UNKNOWN", "PROD"):
        assert entail(_JAVA, {**_TP_FACTS, "production_scope": scope}).verdict == TP
        assert entail(_JAVA, {"production_scope": scope}).verdict == NMD


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="slice")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


def test_dataflow_alone_cannot_establish_a_safe_on_all_paths_value():
    assert is_admissible(_JAVA, "query_position", "EXPRESSION_PATH_FOUND", [_DATAFLOW])
    assert is_admissible(_JAVA, "neutralization_coverage", "BYPASS_PATH_FOUND", [_DATAFLOW])
    assert not is_admissible(_JAVA, "query_position", "BOUND_DATA_ONLY_ALL_PATHS", [_DATAFLOW])
    assert not is_admissible(_JAVA, "neutralization_coverage", "ALL_REACHING_PATHS", [_DATAFLOW])
    assert not is_admissible(_JAVA, "security_effect", "NO_SECURITY_EFFECT", [_DATAFLOW])
    assert not is_admissible(_JAVA, "attacker_control", "REFUTED", [_DATAFLOW])
    assert is_admissible(_JAVA, "query_position", "BOUND_DATA_ONLY_ALL_PATHS", [_LOCAL])


def test_uncited_values_fail_closed():
    for slot, value in _TP_FACTS.items():
        assert not is_admissible(_JAVA, slot, value, [])
