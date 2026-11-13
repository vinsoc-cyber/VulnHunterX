# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""LDAP-injection (CWE-90) families for Java and Python: selection + entailment.

Two DISTINCT defensive facts decide the class and must not collapse:
filter_channel (the value becomes filter/DN text vs. is only passed through an
encoding API on every path) and neutralization_coverage (position-appropriate
escaping on every reaching path). Coverage dismisses only a proven text path.

Python selects CWE-90 (clean). Java selects rule ids only, because the Semgrep
ldap-entry-poisoning rule also carries CWE-90 and has neither a filter nor a DN.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import SELECTABLE_PROFILES, is_admissible

_REG = load_policy_registry()
_FAMILIES = {"java": "ldap_injection_java", "python": "ldap_injection_python"}
_POLICIES = {p.family: p for p in _REG._policies}

_TP_FACTS = {
    "sink_binding": "QUALIFYING_LDAP_QUERY_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "filter_channel": "FILTER_OR_DN_TEXT_PATH_FOUND",
    "neutralization_coverage": "BYPASS_PATH_FOUND",
}

# (lang, rule id, CWE tags the scanner attaches) — every id form that exists.
_OWNED = [
    ("java", "java/ldap-injection", ["CWE-90"]),
    ("java", "java/ldap-injection", []),
    ("java", "config.opengrep-rules.java.lang.security.audit.ldap-injection", ["CWE-90"]),
    ("java", "java.lang.security.audit.ldap-injection.ldap-injection", ["CWE-90"]),
    (
        "java",
        "config.opengrep-rules.java.lang.security.audit.tainted-ldapi-from-http-request",
        ["CWE-90"],
    ),
    (
        "java",
        "java.lang.security.audit.tainted-ldapi-from-http-request.tainted-ldapi-from-http-request",
        ["CWE-90"],
    ),
    ("python", "py/ldap-injection", ["CWE-90"]),
    ("python", "py/ldap-injection", []),
    ("python", "vulnhunterx.python.ldap-injection", ["CWE-90"]),
    ("python", "config.semgrep-custom.vulnhunterx.python.ldap-injection", []),
    ("python", "some.other.scanner.rule", ["CWE-90"]),
]

_LEFT_ON_LEGACY = [
    # Object-returning search controls: CWE-90 tag, but no filter and no DN.
    ("java", "config.opengrep-rules.java.lang.security.audit.ldap-entry-poisoning", ["CWE-90"]),
    ("java", "java.lang.security.audit.ldap-entry-poisoning.ldap-entry-poisoning", ["CWE-90"]),
    ("java", "config.opengrep-rules.java.lang.security.audit.anonymous-ldap-bind", ["CWE-287"]),
    ("java", "java/insecure-ldap-auth", ["CWE-319", "CWE-522"]),
    ("java", "java/jndi-injection", ["CWE-74"]),
]


def _policy(lang):
    return _POLICIES[_FAMILIES[lang]]


# ── selection ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_family_loads_with_matching_name_and_language(lang):
    policy = _policy(lang)
    assert policy.family == _FAMILIES[lang]
    assert policy.languages == frozenset({lang})
    assert policy.version == "1"


@pytest.mark.parametrize(("lang", "rule", "cwes"), _OWNED)
def test_real_rule_ids_select_the_family(lang, rule, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang=lang)
    assert resolved is not None and resolved.family == _FAMILIES[lang], rule


@pytest.mark.parametrize(("lang", "rule", "cwes"), _LEFT_ON_LEGACY)
def test_rules_without_a_filter_or_dn_sink_are_not_claimed(lang, rule, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang=lang)
    assert resolved is None or not resolved.family.startswith("ldap_injection"), rule


def test_python_selects_cwe90_and_java_does_not():
    assert _policy("python").cwes == frozenset({"CWE-90"})
    assert _policy("java").cwes == frozenset()
    assert _REG.resolve_family(cwe_ids=["CWE-90"], rule_id="x", lang="java") is None


@pytest.mark.parametrize(
    ("lang", "rule"),
    [
        ("javascript", "js/ldap-injection"),
        ("csharp", "cs/ldap-injection"),
        ("php", "php/ldap-injection"),
        ("go", "java/ldap-injection"),
        ("java", "py/ldap-injection"),
        ("python", "java/ldap-injection"),
        ("", "py/ldap-injection"),
    ],
)
def test_language_gate(lang, rule):
    cwes = [] if lang == "python" else ["CWE-90"]
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang=lang)
    assert resolved is None or not resolved.family.startswith("ldap_injection")


# ── decision table ────────────────────────────────────────────────────


def test_decision_table_is_identical_across_languages():
    java, python = _policy("java"), _policy("python")
    assert java.fact_slots == python.fact_slots
    assert java.decisive_slots == python.decisive_slots
    assert java.true_positive == python.true_positive
    assert java.false_positive_if_any == python.false_positive_if_any
    assert java.admissibility == python.admissibility
    assert java.assessment_guidance != python.assessment_guidance


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_slots_and_profiles(lang):
    policy = _policy(lang)
    assert set(policy.decisive_slots) == set(_TP_FACTS)
    assert "production_scope" in policy.fact_slots
    assert "security_effect" not in policy.fact_slots
    for slot, values in policy.fact_slots.items():
        for value in values:
            assert policy.admissibility[slot][value] in SELECTABLE_PROFILES, (slot, value)
    assert set(policy.admissibility["production_scope"].values()) == {"ANY_CITATION"}
    # One guidance entry per decisive slot, in table order.
    for slot, text in zip(_TP_FACTS, policy.assessment_guidance, strict=True):
        assert text.startswith(f"{slot}:")


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_entail_tp(lang):
    decision = entail(_policy(lang), _TP_FACTS)
    assert decision.verdict == TP
    assert decision.family == _FAMILIES[lang]


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("sink_binding", "NOT_LDAP_QUERY_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("filter_channel", "BOUND_DATA_ONLY_ALL_PATHS"),
        ("neutralization_coverage", "ALL_REACHING_PATHS"),
    ],
)
def test_each_dominating_value_is_fp(lang, slot, value):
    decision = entail(_policy(lang), {**_TP_FACTS, slot: value})
    assert decision.verdict == FP
    assert slot in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
@pytest.mark.parametrize("slot", sorted(_TP_FACTS))
def test_each_missing_decisive_slot_is_nmd(lang, slot):
    facts = {k: v for k, v in _TP_FACTS.items() if k != slot}
    decision = entail(_policy(lang), facts)
    assert decision.verdict == NMD
    assert decision.terminal_reason == f"unresolved: {slot}"


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_coverage_without_a_proven_text_path_does_not_dismiss(lang):
    facts = {k: v for k, v in _TP_FACTS.items() if k != "filter_channel"}
    facts["neutralization_coverage"] = "ALL_REACHING_PATHS"
    decision = entail(_policy(lang), facts)
    assert decision.verdict == NMD
    assert "filter_channel" in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_production_scope_never_decides(lang):
    for scope in ("TEST_ONLY", "EXAMPLE_DEV", "GENERATED_VENDOR", "UNKNOWN", "PROD"):
        assert entail(_policy(lang), {**_TP_FACTS, "production_scope": scope}).verdict == TP
        assert entail(_policy(lang), {"production_scope": scope}).verdict == NMD


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="slice")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_dataflow_alone_cannot_establish_a_safe_on_all_paths_value(lang):
    policy = _policy(lang)
    assert is_admissible(policy, "filter_channel", "FILTER_OR_DN_TEXT_PATH_FOUND", [_DATAFLOW])
    assert is_admissible(policy, "neutralization_coverage", "BYPASS_PATH_FOUND", [_DATAFLOW])
    assert not is_admissible(policy, "filter_channel", "BOUND_DATA_ONLY_ALL_PATHS", [_DATAFLOW])
    assert not is_admissible(policy, "neutralization_coverage", "ALL_REACHING_PATHS", [_DATAFLOW])
    assert not is_admissible(policy, "attacker_control", "REFUTED", [_DATAFLOW])
    assert not is_admissible(policy, "sink_binding", "NOT_LDAP_QUERY_SINK", [_DATAFLOW])
    assert is_admissible(policy, "neutralization_coverage", "ALL_REACHING_PATHS", [_LOCAL])


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_uncited_values_fail_closed(lang):
    policy = _policy(lang)
    for slot, value in _TP_FACTS.items():
        assert not is_admissible(policy, slot, value, [])
