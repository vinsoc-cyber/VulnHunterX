# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""XML external entity (CWE-611) families for Java and Python: selection + entailment.

One class-specific fact decides the class: entity_resolution — whether the parser
instance that parses the attacker document resolves external entities on some
reaching path, or has them disabled on every path. The decision table is
identical in both languages; only selectors and guidance differ.

Java selects by rule alias only, because the Java `xml-decoder` rule is tagged
CWE-611 but flags a deserialization sink (owned by deserialization_java).
Python selects CWE-611, which is clean there; the entity-expansion rules
(CWE-776 without CWE-611) are not claimed.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import is_admissible

_REG = load_policy_registry()
_FAMILIES = {"java": "xxe_java", "python": "xxe_python"}
_POLICIES = {p.family: p for p in _REG._policies if p.family in _FAMILIES.values()}
_INVENTORY = (
    Path(__file__).resolve().parent / "fixtures" / "policy_selector_audit" / "rule_inventory.json"
)
_XML_DECODER_IDS = {
    "config.opengrep-rules.java.lang.security.audit.xml-decoder",
    "java.lang.security.audit.xml-decoder.xml-decoder",
}

# (lang, rule id, CWE tags as the scanner reports them) — every id form that exists.
_RULES = [
    ("java", "java/xxe", ["CWE-611", "CWE-776", "CWE-827"]),
    (
        "java",
        "config.opengrep-rules.java.lang.security.audit.xxe"
        ".documentbuilderfactory-disallow-doctype-decl-missing",
        ["CWE-611"],
    ),
    (
        "java",
        "java.lang.security.audit.xxe.documentbuilderfactory-disallow-doctype-decl-missing"
        ".documentbuilderfactory-disallow-doctype-decl-missing",
        ["CWE-611"],
    ),
    (
        "java",
        "java.lang.security.audit.xxe.transformerfactory-dtds-not-disabled"
        ".transformerfactory-dtds-not-disabled",
        ["CWE-611"],
    ),
    (
        "java",
        "config.opengrep-rules.java.lang.security.xmlinputfactory-possible-xxe",
        ["CWE-611"],
    ),
    (
        "java",
        "java.lang.security.xmlinputfactory-external-entities-enabled"
        ".xmlinputfactory-external-entities-enabled",
        ["CWE-611"],
    ),
    ("java", "vulnhunterx.java.xml-no-secure-features", ["CWE-611"]),
    ("python", "py/xxe", ["CWE-611", "CWE-827"]),
    ("python", "config.opengrep-rules.python.lang.security.use-defused-xml-parse", ["CWE-611"]),
    (
        "python",
        "python.lang.security.use-defused-xml-parse.use-defused-xml-parse",
        ["CWE-611"],
    ),
    ("python", "python.lang.security.use-defused-xml.use-defused-xml", ["CWE-611"]),
    ("python", "vulnhunterx.python.xxe", ["CWE-611"]),
]

_TP_FACTS = {
    "sink_binding": "QUALIFYING_XML_PARSE_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "entity_resolution": "EXTERNAL_ENTITY_RESOLVING_PATH_FOUND",
}

_LANGS = sorted(_FAMILIES)


def _policy(lang):
    return _POLICIES[_FAMILIES[lang]]


# ── loading and selection ─────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_family_loads(lang):
    assert _FAMILIES[lang] in _REG.families
    policy = _policy(lang)
    assert policy.languages == frozenset({lang})
    assert policy.version == "1"


def test_python_selects_cwe611_and_java_selects_by_alias_only():
    assert _policy("python").cwes == frozenset({"CWE-611"})
    # No CWE selector for Java: CWE-611 would also claim the XMLDecoder rule.
    assert _policy("java").cwes == frozenset()
    assert _policy("java").rule_aliases


def test_python_selected_for_cwe611_from_any_tool():
    resolved = _REG.resolve_family(cwe_ids=["CWE-611"], rule_id="other/tool-rule", lang="python")
    assert resolved is not None and resolved.family == "xxe_python"


@pytest.mark.parametrize(("lang", "rule_id", "cwes"), _RULES)
def test_selected_for_real_rule_ids(lang, rule_id, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule_id, lang=lang)
    assert resolved is not None and resolved.family == _FAMILIES[lang]


@pytest.mark.parametrize(("lang", "rule_id", "cwes"), [r for r in _RULES if r[0] == "java"])
def test_java_aliases_select_without_any_cwe_tag(lang, rule_id, cwes):
    resolved = _REG.resolve_family(cwe_ids=[], rule_id=rule_id, lang=lang)
    assert resolved is not None and resolved.family == "xxe_java"


@pytest.mark.parametrize("rule_id", sorted(_XML_DECODER_IDS))
def test_java_xml_decoder_rule_is_not_an_xxe_finding(rule_id):
    resolved = _REG.resolve_family(cwe_ids=["CWE-611"], rule_id=rule_id, lang="java")
    assert resolved is not None and resolved.family == "deserialization_java"


@pytest.mark.parametrize("lang", _LANGS)
def test_every_inventory_rule_with_cwe611_resolves_to_the_family(lang):
    rows = [
        r
        for r in json.loads(_INVENTORY.read_text(encoding="utf-8"))["rules"]
        if r["lang"] == lang and "CWE-611" in r["cwes"] and r["rule_id"] not in _XML_DECODER_IDS
    ]
    assert rows
    for row in rows:
        resolved = _REG.resolve_family(cwe_ids=row["cwes"], rule_id=row["rule_id"], lang=lang)
        assert resolved is not None and resolved.family == _FAMILIES[lang], row["rule_id"]


def test_entity_expansion_rules_are_not_claimed():
    # CWE-776 (XML bomb) is a different fact from external entity resolution.
    for lang, rule, cwes in (
        ("python", "py/xml-bomb", ["CWE-400", "CWE-776"]),
        ("python", "python.lang.security.use-defused-xmlrpc.use-defused-xmlrpc", ["CWE-776"]),
        ("java", "java/xml-bomb", ["CWE-776"]),
    ):
        resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang=lang)
        assert resolved is None or resolved.family not in _FAMILIES.values()


@pytest.mark.parametrize("lang", _LANGS)
def test_language_gate(lang):
    # The same rule ids / CWE in a language with no XXE family are never captured.
    for foreign, rule, cwes in (
        ("csharp", "cs/xml/insecure-dtd-handling", ["CWE-611", "CWE-776", "CWE-827"]),
        ("javascript", "js/xxe", ["CWE-611", "CWE-827"]),
        ("go", "go.lang.security.audit.xxe.parsing-external-entities-enabled.x", ["CWE-611"]),
        ("php", "vulnhunterx.php.xxe", ["CWE-611"]),
    ):
        resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang=foreign)
        assert resolved is None or resolved.family not in _FAMILIES.values()
    # Each language's own rule id resolves to that language's family only.
    assert _REG.resolve_family(cwe_ids=["CWE-611"], rule_id="java/xxe", lang="java").family == (
        "xxe_java"
    )
    assert _REG.resolve_family(cwe_ids=["CWE-611"], rule_id="py/xxe", lang="python").family == (
        "xxe_python"
    )
    # A Java alias does not leak into Python, where selection is by CWE.
    resolved = _REG.resolve_family(cwe_ids=[], rule_id="java/xxe", lang="python")
    assert resolved is None or resolved.family not in _FAMILIES.values()


# ── decision table shape ──────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_single_class_specific_decisive_slot(lang):
    policy = _policy(lang)
    assert policy.decisive_slots == frozenset(_TP_FACTS)
    assert "production_scope" in policy.fact_slots
    assert "production_scope" not in policy.decisive_slots
    assert "neutralization_coverage" not in policy.fact_slots


def test_decision_table_is_identical_across_languages():
    java, python = _policy("java"), _policy("python")
    assert java.fact_slots == python.fact_slots
    assert java.decisive_slots == python.decisive_slots
    assert java.true_positive == python.true_positive
    assert java.false_positive_if_any == python.false_positive_if_any
    assert java.admissibility == python.admissibility


@pytest.mark.parametrize("lang", _LANGS)
def test_one_guidance_entry_per_decisive_slot(lang):
    policy = _policy(lang)
    heads = [g.split(":", 1)[0] for g in policy.assessment_guidance]
    assert sorted(heads) == sorted(policy.decisive_slots)


# ── entailment truth table ────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_entail_tp(lang):
    assert entail(_policy(lang), _TP_FACTS).verdict == TP


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("sink_binding", "NOT_XML_PARSE_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("entity_resolution", "EXTERNAL_ENTITIES_DISABLED_ALL_PATHS"),
    ],
)
def test_each_dominating_value_is_fp(lang, slot, value):
    decision = entail(_policy(lang), {**_TP_FACTS, slot: value})
    assert decision.verdict == FP
    assert slot in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize("slot", sorted(_TP_FACTS))
def test_each_missing_decisive_slot_is_nmd(lang, slot):
    facts = {k: v for k, v in _TP_FACTS.items() if k != slot}
    decision = entail(_policy(lang), facts)
    assert decision.verdict == NMD
    assert slot in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
def test_hardened_parser_dismisses_even_with_other_slots_unresolved(lang):
    facts = {"entity_resolution": "EXTERNAL_ENTITIES_DISABLED_ALL_PATHS"}
    assert entail(_policy(lang), facts).verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
def test_production_scope_never_decides(lang):
    for scope in ("PROD", "TEST_ONLY", "EXAMPLE_DEV", "GENERATED_VENDOR", "UNKNOWN"):
        assert entail(_policy(lang), {**_TP_FACTS, "production_scope": scope}).verdict == TP
        assert entail(_policy(lang), {"production_scope": scope}).verdict == NMD


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="slice")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


@pytest.mark.parametrize("lang", _LANGS)
def test_dataflow_alone_does_not_admit_the_hardened_all_paths_value(lang):
    policy = _policy(lang)
    assert is_admissible(policy, "attacker_control", "PROVEN", [_DATAFLOW])
    assert is_admissible(policy, "flow_to_sink", "REACHES", [_DATAFLOW])
    assert not is_admissible(
        policy, "entity_resolution", "EXTERNAL_ENTITIES_DISABLED_ALL_PATHS", [_DATAFLOW]
    )
    assert not is_admissible(policy, "attacker_control", "REFUTED", [_DATAFLOW])
    assert not is_admissible(policy, "sink_binding", "NOT_XML_PARSE_SINK", [_DATAFLOW])


@pytest.mark.parametrize("lang", _LANGS)
def test_local_slice_admits_every_decisive_value_and_no_citation_admits_none(lang):
    policy = _policy(lang)
    for slot in policy.decisive_slots:
        for value in policy.fact_slots[slot]:
            assert is_admissible(policy, slot, value, [_LOCAL]), (slot, value)
            assert not is_admissible(policy, slot, value, []), (slot, value)
