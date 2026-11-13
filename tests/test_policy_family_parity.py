# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Parity between per-language families of the same vulnerability class.

A class is implemented as one YAML per language (``sql_injection`` for PHP,
``sql_injection_java``, ...; a class with no PHP family has only suffixed
members), because the assessment guidance names
language-specific sinks and defenses. The DECISION TABLE — fact slots, decisive
slots, entailment, admissibility — must stay identical across the languages of
a class, so that a correction made to one file cannot silently leave the others
with a weaker rule. A language whose semantics force a different table declares
the differing sections in ``_DEVIATIONS`` with the reason.
"""

from __future__ import annotations

from collections.abc import Iterable

import pytest

from vuln_hunter_x.verification.policy.loader import load_policy_from_mapping, load_policy_registry
from vuln_hunter_x.verification.policy.models import FamilyPolicy

# A family belongs to a class when its name is the class name or
# ``<class>_<lang>``. Longer names first, so ``xpath_injection_java`` is not
# mistaken for a member of a shorter class.
_CLASSES = (
    "code_injection",
    "command_injection",
    "deserialization",
    "ldap_injection",
    "open_redirect",
    "path_access",
    "sql_injection",
    "ssrf",
    "xpath_injection",
    "xss",
    "xxe",
)

_SECTIONS = ("fact_slots", "decisive_slots", "entailment", "admissibility")

# family -> the family its table is compared against. Default: the class's
# bare-name family when one is loaded, else the first member by name.
_REFERENCE: dict[str, str] = {
    "command_injection_cpp": "command_injection_java",
    "command_injection_csharp": "command_injection_java",
    "command_injection_go": "command_injection_java",
    "command_injection_javascript": "command_injection_java",
    "command_injection_python": "command_injection_java",
    "path_access_csharp": "path_access_java",
    "path_access_go": "path_access_java",
    "path_access_javascript": "path_access_java",
    "path_access_python": "path_access_java",
}

# family -> {section: reason}. Only the listed sections may differ from the
# family's reference; every other section must still match.
_DEVIATIONS: dict[str, dict[str, str]] = {
    # Declared once on the Java member; the other languages are compared to it
    # through _REFERENCE, so they must carry exactly the same table.
    "command_injection_java": {
        "fact_slots": (
            "command_channel adds EXECUTABLE_CONTROL_PATH_FOUND: these runtimes launch "
            "processes without a shell, so control of the program position is a second "
            "positive state next to shell command text"
        ),
        "entailment": (
            "True Positive accepts either positive channel, and coverage dismisses on either"
        ),
        "admissibility": "profile for the added command_channel value (CONCRETE_PATH)",
    },
    "path_access_java": {
        "entailment": (
            "no handoff_from/applicability block: the family is the primary owner, so "
            "NOT_PATH_ACCESS_SINK is a False Positive condition instead of a hand-back"
        ),
        "admissibility": (
            "defense_coverage ALL_REACHING_PATHS is LOCAL_OR_EXHAUSTIVE: a "
            "canonicalise-then-prefix check is proven by local code and is not an encoder"
        ),
    },
}


def _section(policy: FamilyPolicy, name: str) -> object:
    if name == "fact_slots":
        return {slot: frozenset(values) for slot, values in policy.fact_slots.items()}
    if name == "decisive_slots":
        return policy.decisive_slots
    if name == "entailment":
        return (
            dict(policy.true_positive),
            frozenset(frozenset(c.items()) for c in policy.false_positive_if_any),
        )
    if name == "admissibility":
        return {slot: dict(values) for slot, values in policy.admissibility.items()}
    raise KeyError(name)


def class_of(family: str) -> str | None:
    for cls in sorted(_CLASSES, key=len, reverse=True):
        if family == cls or family.startswith(cls + "_"):
            return cls
    return None


def differing_sections(reference: FamilyPolicy, member: FamilyPolicy) -> set[str]:
    return {s for s in _SECTIONS if _section(reference, s) != _section(member, s)}


def reference_for(family: str, loaded: Iterable[str], overrides: dict[str, str]) -> str | None:
    """The family *family* is compared against; ``None`` when it is a reference itself."""
    cls = class_of(family)
    if cls is None:
        return None
    if family in overrides:
        return overrides[family]
    members = sorted(f for f in loaded if class_of(f) == cls)
    reference = cls if cls in members else members[0]
    return None if reference == family else reference


def parity_violations(
    policies: Iterable[FamilyPolicy],
    deviations: dict[str, dict[str, str]],
    overrides: dict[str, str] | None = None,
) -> list[str]:
    by_family = {p.family: p for p in policies}
    problems: list[str] = []
    for family, policy in sorted(by_family.items()):
        ref = reference_for(family, by_family, overrides or {})
        if ref is None:
            continue
        if ref not in by_family:
            problems.append(f"{family}: reference {ref!r} is not loaded")
            continue
        differing = differing_sections(by_family[ref], policy)
        allowed = set(deviations.get(family, {}))
        problems += [
            f"{family}: {s} differs from {ref} (declare it in _DEVIATIONS with the reason)"
            for s in sorted(differing - allowed)
        ]
        problems += [
            f"{family}: {s} is declared as a deviation but matches {ref}; remove it"
            for s in sorted(allowed - differing)
        ]
    return problems


def test_bundled_families_keep_class_parity():
    assert parity_violations(load_policy_registry()._policies, _DEVIATIONS, _REFERENCE) == []


def test_declared_deviations_name_loaded_families_and_known_sections():
    families = set(load_policy_registry().families)
    for family, sections in _DEVIATIONS.items():
        assert family in families
        assert class_of(family) is not None
        assert set(sections) <= set(_SECTIONS)
        assert all(reason.strip() for reason in sections.values())


# ── The comparator itself (synthetic families; no bundled file involved) ──


def _toy(family: str, *, escape_profile: str = "LOCAL_OR_EXHAUSTIVE", extra_fp: bool = False):
    fp = [{"attacker_control": "REFUTED"}, {"query_channel": "BOUND"}]
    if extra_fp:
        fp.append({"sink_binding": "NOT_SINK"})
    return load_policy_from_mapping(
        {
            "family": family,
            "selectors": {"languages": ["java"], "cwes": ["CWE-89"]},
            "fact_slots": {
                "sink_binding": ["SINK", "NOT_SINK"],
                "attacker_control": ["PROVEN", "REFUTED"],
                "query_channel": ["TEXT", "BOUND"],
            },
            "entailment": {
                "true_positive": {
                    "sink_binding": "SINK",
                    "attacker_control": "PROVEN",
                    "query_channel": "TEXT",
                },
                "false_positive_if_any": fp,
            },
            "admissibility": {
                "sink_binding": {"SINK": "LOCAL_POSITIVE", "NOT_SINK": "LOCAL_POSITIVE"},
                "attacker_control": {"PROVEN": "LOCAL_OR_DATAFLOW", "REFUTED": "LOCAL_POSITIVE"},
                "query_channel": {"TEXT": "CONCRETE_PATH", "BOUND": escape_profile},
            },
            "assessment_guidance": [f"guidance for {family}"],
        }
    )


def test_identical_tables_with_different_guidance_are_in_parity():
    assert parity_violations([_toy("sql_injection"), _toy("sql_injection_java")], {}) == []


@pytest.mark.parametrize(
    ("kwargs", "section"),
    [({"escape_profile": "LOCAL_POSITIVE"}, "admissibility"), ({"extra_fp": True}, "entailment")],
)
def test_undeclared_difference_is_a_violation(kwargs, section):
    problems = parity_violations([_toy("sql_injection"), _toy("sql_injection_java", **kwargs)], {})
    assert problems == [
        f"sql_injection_java: {section} differs from sql_injection "
        "(declare it in _DEVIATIONS with the reason)"
    ]


def test_declared_difference_is_accepted_and_a_stale_declaration_is_not():
    ref = _toy("sql_injection")
    changed = _toy("sql_injection_java", extra_fp=True)
    declared = {"sql_injection_java": {"entailment": "synthetic"}}
    assert parity_violations([ref, changed], declared) == []
    assert parity_violations([ref, _toy("sql_injection_java")], declared) == [
        "sql_injection_java: entailment is declared as a deviation but matches sql_injection; "
        "remove it"
    ]


def test_class_without_a_bare_name_family_uses_its_first_member():
    assert parity_violations([_toy("ssrf_java"), _toy("ssrf_python")], {}) == []
    assert parity_violations([_toy("ssrf_java"), _toy("ssrf_python", extra_fp=True)], {}) == [
        "ssrf_python: entailment differs from ssrf_java (declare it in _DEVIATIONS with the reason)"
    ]


def test_reference_override_groups_members_that_share_a_deviation():
    ref = _toy("sql_injection")
    java = _toy("sql_injection_java", extra_fp=True)
    python = _toy("sql_injection_python", extra_fp=True)
    declared = {"sql_injection_java": {"entailment": "synthetic"}}
    overrides = {"sql_injection_python": "sql_injection_java"}
    assert parity_violations([ref, java, python], declared, overrides) == []
    assert parity_violations([ref, java, _toy("sql_injection_python")], declared, overrides) == [
        "sql_injection_python: entailment differs from sql_injection_java "
        "(declare it in _DEVIATIONS with the reason)"
    ]


def test_overridden_reference_must_be_loaded():
    overrides = {"sql_injection_java": "sql_injection_go"}
    assert parity_violations(
        [_toy("sql_injection"), _toy("sql_injection_java")], {}, overrides
    ) == ["sql_injection_java: reference 'sql_injection_go' is not loaded"]


def test_unrelated_families_are_not_grouped():
    assert class_of("log_injection") is None
    assert class_of("sql_injection_python") == "sql_injection"
    assert class_of("path_access") == "path_access"
    assert class_of("xpath_injection_java") == "xpath_injection"
    assert class_of("xss_java") == "xss"
    assert class_of("xxe_java") == "xxe"
