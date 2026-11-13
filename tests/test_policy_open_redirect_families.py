# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Open redirect (CWE-601) families: selection + entailment.

One family per language (``open_redirect_java``, ``open_redirect_python``)
sharing one decision table. Two DISTINCT facts decide the class and must not
collapse: target_control (can the value select an off-site target, including the
``//host`` and backslash forms browsers accept, or is it confined on every path
to the application's own origin) and target_restriction (is the target that is
sent held to trusted hosts or to a local path on every path). The restriction
dismisses only together with a proven external-target channel, so it can never
dismiss vacuously.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import (
    PolicyOverlapError,
    load_policy_registry,
)
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import is_admissible

_REG = load_policy_registry()
_POLICIES_DIR = Path(__file__).resolve().parents[1] / "config" / "policies"
_LANGS = ("java", "python")
_OTHER_LANGS = ("c", "cpp", "csharp", "go", "javascript", "php")

# Real rule ids per language, in every id form the scanners emit: CodeQL
# (built-in and custom), the vendored OpenGrep tree, and the semgrep.dev registry.
_RULES = {
    "java": (
        "java/unvalidated-url-redirection",
        "config.opengrep-rules.java.lang.security.audit.unvalidated-redirect",
        "config.opengrep-rules.java.spring.security.audit.spring-unvalidated-redirect",
        "java.lang.security.audit.unvalidated-redirect.unvalidated-redirect",
        "java.spring.security.audit.spring-unvalidated-redirect.spring-unvalidated-redirect",
        "vulnhunterx.java.open-redirect",
    ),
    "python": (
        "py/url-redirection",
        "config.opengrep-rules.python.django.security.injection.open-redirect",
        "config.opengrep-rules.python.flask.security.open-redirect",
        "python.django.security.injection.open-redirect.open-redirect",
        "python.flask.security.open-redirect.open-redirect",
    ),
}
_RULE_CASES = [(lang, rule) for lang in _LANGS for rule in _RULES[lang]]

_TP_FACTS = {
    "sink_binding": "QUALIFYING_REDIRECT_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "target_control": "EXTERNAL_TARGET_PATH_FOUND",
    "target_restriction": "BYPASS_PATH_FOUND",
}
_DECISIVE = tuple(_TP_FACTS)

_VERDICT_WORDING = re.compile(
    r"verdict|true positive|false positive|the rule is likely correct"
    r"|\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)"
    r"|owasp|juliet|benchmark",
    re.IGNORECASE,
)

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="slice")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


def _family(lang: str):
    return _REG.resolve_family(cwe_ids=["CWE-601"], rule_id="", lang=lang)


def _raw(lang: str) -> dict:
    return yaml.safe_load(
        (_POLICIES_DIR / f"open_redirect_{lang}.yaml").read_text(encoding="utf-8")
    )


# ── loading and selection ─────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_family_loads_with_file_stem_name_and_language_gate(lang):
    assert f"open_redirect_{lang}" in _REG.families
    raw = _raw(lang)
    assert raw["family"] == f"open_redirect_{lang}"
    assert raw["version"] == "1"
    assert raw["selectors"]["languages"] == [lang]
    assert raw["selectors"]["cwes"] == ["CWE-601"]
    assert "rule_aliases" not in raw["selectors"]


@pytest.mark.parametrize("lang", _LANGS)
def test_selected_by_cwe601(lang):
    policy = _family(lang)
    assert policy is not None and policy.family == f"open_redirect_{lang}"


@pytest.mark.parametrize(("lang", "rule"), _RULE_CASES)
def test_selected_for_real_rule_ids_in_every_id_form(lang, rule):
    policy = _REG.resolve_family(cwe_ids=["CWE-601"], rule_id=rule, lang=lang)
    assert policy is not None and policy.family == f"open_redirect_{lang}", rule


@pytest.mark.parametrize(("lang", "rule"), _RULE_CASES)
def test_rule_id_without_its_cwe_tag_is_not_claimed(lang, rule):
    # Selection is by CWE only (no alias): a finding that lost its CWE tag stays
    # on the legacy route instead of being claimed by name.
    assert _REG.resolve_family(cwe_ids=[], rule_id=rule, lang=lang) is None


@pytest.mark.parametrize("lang", _LANGS)
def test_language_gate_keeps_each_language_in_its_own_family(lang):
    other = "python" if lang == "java" else "java"
    resolved = _REG.resolve_family(cwe_ids=["CWE-601"], rule_id=_RULES[other][0], lang=lang)
    # The stage language decides, not the rule-id prefix.
    assert resolved is not None and resolved.family == f"open_redirect_{lang}"


@pytest.mark.parametrize("other", _OTHER_LANGS)
def test_cwe601_in_another_language_is_not_these_families(other):
    resolved = _REG.resolve_family(cwe_ids=["CWE-601"], rule_id="x/url-redirection", lang=other)
    assert resolved is None or resolved.family not in {"open_redirect_java", "open_redirect_python"}


@pytest.mark.parametrize("lang", _LANGS)
def test_unrelated_cwe_is_not_claimed(lang):
    resolved = _REG.resolve_family(cwe_ids=["CWE-327"], rule_id="x/weak-crypto", lang=lang)
    assert resolved is None or not resolved.family.startswith("open_redirect")


# ── decision table shape ──────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_two_independent_target_facts_are_decisive(lang):
    policy = _family(lang)
    assert policy.decisive_slots == frozenset(_DECISIVE)
    assert "production_scope" in policy.fact_slots
    assert "production_scope" not in policy.decisive_slots
    assert set(policy.admissibility["production_scope"].values()) == {"ANY_CITATION"}


def test_decision_table_is_identical_across_languages():
    java, python = _family("java"), _family("python")
    assert dict(java.fact_slots) == dict(python.fact_slots)
    assert java.decisive_slots == python.decisive_slots
    assert dict(java.true_positive) == dict(python.true_positive)
    assert [dict(c) for c in java.false_positive_if_any] == [
        dict(c) for c in python.false_positive_if_any
    ]
    assert {s: dict(v) for s, v in java.admissibility.items()} == {
        s: dict(v) for s, v in python.admissibility.items()
    }
    # The raw YAML sections match too (same order, same spelling).
    for section in ("fact_slots", "decisive_slots", "entailment", "admissibility"):
        assert _raw("java")[section] == _raw("python")[section], section


# ── entailment truth table ────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_entail_tp(lang):
    assert entail(_family(lang), _TP_FACTS).verdict == TP


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("sink_binding", "NOT_REDIRECT_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("target_control", "LOCAL_TARGET_ONLY_ALL_PATHS"),
        ("target_restriction", "ALL_REACHING_PATHS"),
    ],
)
def test_each_dominating_value_is_fp(lang, slot, value):
    decision = entail(_family(lang), {**_TP_FACTS, slot: value})
    assert decision.verdict == FP
    assert slot in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("sink_binding", "NOT_REDIRECT_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("target_control", "LOCAL_TARGET_ONLY_ALL_PATHS"),
    ],
)
def test_single_fact_dismissals_hold_with_nothing_else_resolved(lang, slot, value):
    assert entail(_family(lang), {slot: value}).verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize("missing", _DECISIVE)
def test_each_missing_decisive_slot_is_nmd_naming_the_slot(lang, missing):
    facts = {k: v for k, v in _TP_FACTS.items() if k != missing}
    decision = entail(_family(lang), facts)
    assert decision.verdict == NMD
    assert decision.terminal_reason == f"unresolved: {missing}"


@pytest.mark.parametrize("lang", _LANGS)
def test_restriction_does_not_dismiss_without_a_proven_external_channel(lang):
    # target_restriction is scoped to the positive channel: with the channel
    # unresolved (for example a prefix whose content is not in evidence) an
    # ALL_REACHING_PATHS claim dismisses nothing.
    facts = {k: v for k, v in _TP_FACTS.items() if k != "target_control"}
    decision = entail(_family(lang), {**facts, "target_restriction": "ALL_REACHING_PATHS"})
    assert decision.verdict == NMD
    assert "target_control" in (decision.terminal_reason or "")
    assert entail(_family(lang), {"target_restriction": "ALL_REACHING_PATHS"}).verdict == NMD


@pytest.mark.parametrize("lang", _LANGS)
def test_external_target_alone_is_never_a_true_positive(lang):
    # "No restriction visible" is not a witnessed bypass: without
    # target_restriction the finding stays undecided.
    facts = {k: v for k, v in _TP_FACTS.items() if k != "target_restriction"}
    assert entail(_family(lang), facts).verdict == NMD
    assert entail(_family(lang), {}).verdict == NMD


@pytest.mark.parametrize("lang", _LANGS)
def test_production_scope_never_changes_the_verdict(lang):
    policy = _family(lang)
    for scope in policy.fact_slots["production_scope"]:
        assert entail(policy, {**_TP_FACTS, "production_scope": scope}).verdict == TP
        assert entail(policy, {"production_scope": scope}).verdict == NMD


# ── admissibility ─────────────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_admissibility_profiles(lang):
    policy = _family(lang)
    # A witnessed path may rest on the scanner dataflow...
    assert is_admissible(policy, "attacker_control", "PROVEN", [_DATAFLOW])
    assert is_admissible(policy, "flow_to_sink", "REACHES", [_DATAFLOW])
    assert is_admissible(policy, "target_control", "EXTERNAL_TARGET_PATH_FOUND", [_DATAFLOW])
    assert is_admissible(policy, "target_restriction", "BYPASS_PATH_FOUND", [_LOCAL])
    # ...but every dismissing value needs more than a dataflow citation.
    for slot, value in (
        ("sink_binding", "NOT_REDIRECT_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("target_control", "LOCAL_TARGET_ONLY_ALL_PATHS"),
        ("target_restriction", "ALL_REACHING_PATHS"),
    ):
        assert not is_admissible(policy, slot, value, [_DATAFLOW]), (slot, value)
        assert is_admissible(policy, slot, value, [_LOCAL]), (slot, value)
        assert not is_admissible(policy, slot, value, []), (slot, value)


# ── guidance ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_has_one_neutral_entry_per_decisive_slot(lang):
    policy = _family(lang)
    assert len(policy.assessment_guidance) == len(_DECISIVE)
    for slot, entry in zip(_DECISIVE, policy.assessment_guidance, strict=True):
        assert entry.startswith(f"{slot}:"), entry[:40]
        assert not _VERDICT_WORDING.search(entry), _VERDICT_WORDING.search(entry)


@pytest.mark.parametrize(
    ("lang", "needles"),
    [
        ("java", ("sendRedirect", "redirect:", "RedirectView", "Location", "java.net.URI")),
        (
            "python",
            (
                "flask.redirect",
                "HttpResponseRedirect",
                "url_has_allowed_host_and_scheme",
                "urlparse(value).netloc is empty",
                "url_for",
            ),
        ),
    ],
)
def test_guidance_names_the_language_sinks_and_weak_checks(lang, needles):
    text = " ".join(_family(lang).assessment_guidance)
    for needle in needles:
        assert needle in text, needle
    # Off-site forms and weak restrictions are stated explicitly.
    assert "https://example.com@evil.test/" in text
    for form in ('"//evil.test"', '"/\\evil.test"', '"///evil.test"'):
        assert form in text, form
    assert 'startswith("/") alone' in text.replace("startsWith", "startswith")


# ── overlap ───────────────────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_finding_tagged_open_redirect_and_ssrf_fails_closed(lang):
    # No inventory rule carries both CWEs today; a finding that did would match
    # two families and must fail closed instead of picking one.
    with pytest.raises(PolicyOverlapError):
        _REG.resolve_family(cwe_ids=["CWE-918", "CWE-601"], rule_id="x", lang=lang)
