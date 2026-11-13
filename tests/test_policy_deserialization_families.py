# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Unsafe-deserialization (CWE-502) families for Java and Python: selection + entailment.

Two DISTINCT defensive facts decide the class and must not collapse:
deserializer_capability (arbitrary-type decoder vs. data-only on every path) and
type_restriction (an allowlist on the stream on every path). The restriction
dismissal is scoped to a PROVEN arbitrary-type decoder, so it never dismisses
vacuously. The decision table is identical in both languages; only selectors and
guidance differ.
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
_FAMILIES = {"java": "deserialization_java", "python": "deserialization_python"}
_POLICIES = {p.family: p for p in _REG._policies if p.family in _FAMILIES.values()}
_INVENTORY = (
    Path(__file__).resolve().parent / "fixtures" / "policy_selector_audit" / "rule_inventory.json"
)

# (lang, rule id, CWE tags as the scanner reports them) — every id form that exists.
_RULES = [
    ("java", "java/unsafe-deserialization", ["CWE-502"]),
    ("java", "config.opengrep-rules.java.lang.security.audit.object-deserialization", ["CWE-502"]),
    (
        "java",
        "java.lang.security.audit.object-deserialization.object-deserialization",
        ["CWE-502"],
    ),
    (
        "java",
        "config.opengrep-rules.java.lang.security.jackson-unsafe-deserialization",
        ["CWE-502"],
    ),
    (
        "java",
        "java.lang.security.use-snakeyaml-constructor.use-snakeyaml-constructor",
        ["CWE-502"],
    ),
    (
        "java",
        "java.rmi.security.server-dangerous-object-deserialization"
        ".server-dangerous-object-deserialization",
        ["CWE-502"],
    ),
    ("python", "py/unsafe-deserialization", ["CWE-502"]),
    (
        "python",
        "config.opengrep-rules.python.lang.security.deserialization.avoid-pickle",
        ["CWE-502"],
    ),
    ("python", "python.lang.security.deserialization.pickle.avoid-pickle", ["CWE-502"]),
    (
        "python",
        "python.flask.security.insecure-deserialization.insecure-deserialization",
        ["CWE-502"],
    ),
    ("python", "vulnhunterx.python.unsafe-yaml", ["CWE-502"]),
    ("python", "py/unsafe-yaml", ["CWE-502"]),
]

_TP_FACTS = {
    "sink_binding": "QUALIFYING_DESERIALIZATION_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "deserializer_capability": "ARBITRARY_TYPE_PATH_FOUND",
    "type_restriction": "BYPASS_PATH_FOUND",
}

_LANGS = sorted(_FAMILIES)


def _policy(lang):
    return _POLICIES[_FAMILIES[lang]]


# ── loading and selection ─────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_family_loads(lang):
    family = _FAMILIES[lang]
    assert family in _REG.families
    policy = _policy(lang)
    assert policy.languages == frozenset({lang})
    assert policy.version == "1"
    assert "CWE-502" in policy.cwes


@pytest.mark.parametrize("lang", _LANGS)
def test_selected_for_cwe502(lang):
    resolved = _REG.resolve_family(cwe_ids=["CWE-502"], rule_id="some/other-tool-rule", lang=lang)
    assert resolved is not None and resolved.family == _FAMILIES[lang]


@pytest.mark.parametrize(("lang", "rule_id", "cwes"), _RULES)
def test_selected_for_real_rule_ids(lang, rule_id, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule_id, lang=lang)
    assert resolved is not None and resolved.family == _FAMILIES[lang]


@pytest.mark.parametrize(
    "rule_id",
    [
        "config.opengrep-rules.java.lang.security.audit.xml-decoder",
        "java.lang.security.audit.xml-decoder.xml-decoder",
    ],
)
def test_java_xml_decoder_rule_is_deserialization_despite_its_cwe611_tag(rule_id):
    # java.beans.XMLDecoder is a deserialization sink; the rule is tagged CWE-611.
    # It is claimed here by alias, and the Java XXE family must not also claim it.
    resolved = _REG.resolve_family(cwe_ids=["CWE-611"], rule_id=rule_id, lang="java")
    assert resolved is not None and resolved.family == "deserialization_java"


@pytest.mark.parametrize("lang", _LANGS)
def test_every_inventory_rule_with_cwe502_resolves_to_the_family(lang):
    rows = [
        r
        for r in json.loads(_INVENTORY.read_text(encoding="utf-8"))["rules"]
        if r["lang"] == lang and "CWE-502" in r["cwes"]
    ]
    assert rows
    for row in rows:
        resolved = _REG.resolve_family(cwe_ids=row["cwes"], rule_id=row["rule_id"], lang=lang)
        assert resolved is not None and resolved.family == _FAMILIES[lang], row["rule_id"]


@pytest.mark.parametrize("lang", _LANGS)
def test_language_gate(lang):
    other = "python" if lang == "java" else "java"
    # The same CWE in the other language belongs to the other language's family.
    resolved = _REG.resolve_family(cwe_ids=["CWE-502"], rule_id="x", lang=other)
    assert resolved is not None and resolved.family == _FAMILIES[other]
    # A language with no deserialization family is never captured by these two.
    for foreign, rule in (
        ("csharp", "cs/unsafe-deserialization-untrusted-input"),
        ("javascript", "js/unsafe-deserialization"),
        ("php", "php.lang.security.unserialize-use.unserialize-use"),
    ):
        resolved = _REG.resolve_family(cwe_ids=["CWE-502"], rule_id=rule, lang=foreign)
        assert resolved is None or resolved.family not in _FAMILIES.values()


@pytest.mark.parametrize("lang", _LANGS)
def test_unrelated_cwe_is_not_selected(lang):
    for cwe, rule in (("CWE-776", "py/xml-bomb"), ("CWE-327", "x/weak-crypto")):
        resolved = _REG.resolve_family(cwe_ids=[cwe], rule_id=rule, lang=lang)
        assert resolved is None or resolved.family not in _FAMILIES.values()


# ── decision table shape ──────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_two_independent_defensive_slots(lang):
    policy = _policy(lang)
    assert policy.decisive_slots == frozenset(_TP_FACTS)
    assert "production_scope" in policy.fact_slots
    assert "production_scope" not in policy.decisive_slots
    assert "security_effect" not in policy.fact_slots


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
        ("sink_binding", "NOT_DESERIALIZATION_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("deserializer_capability", "DATA_ONLY_ALL_PATHS"),
        ("type_restriction", "ALL_REACHING_PATHS"),
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
def test_restriction_does_not_dismiss_without_a_proven_arbitrary_type_decoder(lang):
    # "A filter exists" with the decoder's capability unresolved is not a fact
    # about this stream: it must stay Needs More Data, not be dismissed.
    facts = {k: v for k, v in _TP_FACTS.items() if k != "deserializer_capability"}
    decision = entail(_policy(lang), {**facts, "type_restriction": "ALL_REACHING_PATHS"})
    assert decision.verdict == NMD
    assert "deserializer_capability" in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
def test_single_safe_fact_dismisses_even_with_other_slots_unresolved(lang):
    assert entail(_policy(lang), {"deserializer_capability": "DATA_ONLY_ALL_PATHS"}).verdict == FP
    assert entail(_policy(lang), {"attacker_control": "REFUTED"}).verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
def test_production_scope_never_decides(lang):
    for scope in ("PROD", "TEST_ONLY", "EXAMPLE_DEV", "GENERATED_VENDOR", "UNKNOWN"):
        assert entail(_policy(lang), {**_TP_FACTS, "production_scope": scope}).verdict == TP
        assert entail(_policy(lang), {"production_scope": scope}).verdict == NMD


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="slice")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


@pytest.mark.parametrize("lang", _LANGS)
def test_dataflow_alone_admits_the_path_but_not_the_safe_all_paths_values(lang):
    policy = _policy(lang)
    assert is_admissible(policy, "attacker_control", "PROVEN", [_DATAFLOW])
    assert is_admissible(policy, "flow_to_sink", "REACHES", [_DATAFLOW])
    assert is_admissible(
        policy, "deserializer_capability", "ARBITRARY_TYPE_PATH_FOUND", [_DATAFLOW]
    )
    assert not is_admissible(policy, "deserializer_capability", "DATA_ONLY_ALL_PATHS", [_DATAFLOW])
    assert not is_admissible(policy, "type_restriction", "ALL_REACHING_PATHS", [_DATAFLOW])
    assert not is_admissible(policy, "attacker_control", "REFUTED", [_DATAFLOW])
    assert not is_admissible(policy, "sink_binding", "NOT_DESERIALIZATION_SINK", [_DATAFLOW])


@pytest.mark.parametrize("lang", _LANGS)
def test_local_slice_admits_every_decisive_value_and_no_citation_admits_none(lang):
    policy = _policy(lang)
    for slot in policy.decisive_slots:
        for value in policy.fact_slots[slot]:
            assert is_admissible(policy, slot, value, [_LOCAL]), (slot, value)
            assert not is_admissible(policy, slot, value, []), (slot, value)
