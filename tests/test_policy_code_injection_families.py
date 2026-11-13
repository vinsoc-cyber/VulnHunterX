# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Code-injection (CWE-94/95) families for Java and Python: selection + entailment.

Two DISTINCT facts decide the class and must not collapse: interpreter_channel
(the value becomes evaluated program text vs. is only data on every path) and
neutralization_coverage (a finite allowlist on every reaching path). Coverage
dismisses only a proven code-text path, so an unresolved channel never dismisses
vacuously.

CWE-94 is a catch-all tag, so neither language selects it: Java selects CWE-95
plus rule ids, Python selects rule ids only. The rules that carry the CWEs but
are not evaluators stay on the legacy route, and these tests pin that.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import SELECTABLE_PROFILES, is_admissible

_REG = load_policy_registry()
_FAMILIES = {"java": "code_injection_java", "python": "code_injection_python"}
_POLICIES = {p.family: p for p in _REG._policies}

_TP_FACTS = {
    "sink_binding": "QUALIFYING_CODE_EVALUATION_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "interpreter_channel": "CODE_TEXT_PATH_FOUND",
    "neutralization_coverage": "BYPASS_PATH_FOUND",
}

# (lang, rule id, CWE tags the scanner attaches) — every id form that exists.
_OWNED = [
    # CodeQL
    ("java", "java/groovy-injection", ["CWE-94"]),
    ("java", "java/insecure-bean-validation", ["CWE-94"]),
    ("java", "java/jexl-expression-injection", ["CWE-94"]),
    ("java", "java/mvel-expression-injection", ["CWE-94"]),
    ("java", "java/spel-expression-injection", ["CWE-94"]),
    ("java", "java/server-side-template-injection", ["CWE-94", "CWE-1336"]),
    ("java", "java/ognl-injection", ["CWE-917"]),
    # vendored OpenGrep form
    ("java", "config.opengrep-rules.java.lang.security.audit.dangerous-groovy-shell", ["CWE-94"]),
    ("java", "config.opengrep-rules.java.lang.security.audit.el-injection", ["CWE-94"]),
    ("java", "config.opengrep-rules.java.lang.security.audit.ognl-injection", ["CWE-94"]),
    ("java", "config.opengrep-rules.java.lang.security.audit.script-engine-injection", ["CWE-94"]),
    ("java", "config.opengrep-rules.java.spring.security.audit.spel-injection", ["CWE-94"]),
    ("java", "config.opengrep-rules.java.spring.security.audit.spring-jsp-eval", ["CWE-95"]),
    ("java", "config.opengrep-rules.java.jboss.security.seam-log-injection", ["CWE-95"]),
    # registry form
    ("java", "java.lang.security.audit.el-injection.el-injection", ["CWE-94"]),
    (
        "java",
        "java.lang.security.audit.script-engine-injection.script-engine-injection",
        ["CWE-94"],
    ),
    ("java", "java.spring.security.audit.spel-injection.spel-injection", ["CWE-94"]),
    ("java", "java.jboss.security.seam-log-injection.seam-log-injection", ["CWE-95"]),
    # custom Semgrep, with and without the config path prefix
    ("java", "vulnhunterx.java.template-injection", ["CWE-917", "CWE-1336"]),
    ("java", "config.semgrep-custom.vulnhunterx.java.template-injection", ["CWE-1336"]),
    # CodeQL
    ("python", "py/code-injection", ["CWE-94", "CWE-95", "CWE-116"]),
    ("python", "py/use-of-input", ["CWE-94", "CWE-95"]),
    ("python", "py/template-injection", ["CWE-74"]),
    # vendored OpenGrep form
    ("python", "config.opengrep-rules.python.lang.security.audit.eval-detected", ["CWE-95"]),
    ("python", "config.opengrep-rules.python.lang.security.audit.exec-detected", ["CWE-95"]),
    ("python", "config.opengrep-rules.python.flask.security.injection.eval-injection", ["CWE-95"]),
    ("python", "config.opengrep-rules.python.flask.security.injection.exec-injection", ["CWE-95"]),
    (
        "python",
        "config.opengrep-rules.python.django.security.injection.code.user-exec-format-string",
        ["CWE-95"],
    ),
    ("python", "config.opengrep-rules.python.aws-lambda.security.tainted-code-exec", ["CWE-95"]),
    (
        "python",
        "config.opengrep-rules.python.lang.security.dangerous-subinterpreters-run-string",
        ["CWE-95"],
    ),
    (
        "python",
        "config.opengrep-rules.python.flask.security.audit.render-template-string",
        ["CWE-96"],
    ),
    # registry form
    ("python", "python.lang.security.audit.eval-detected.eval-detected", ["CWE-95"]),
    ("python", "python.flask.security.injection.user-eval.eval-injection", ["CWE-95"]),
    ("python", "python.flask.security.injection.user-exec.exec-injection", ["CWE-95"]),
    ("python", "python.django.security.injection.code.user-eval.user-eval", ["CWE-95"]),
    (
        "python",
        "python.lang.security.dangerous-code-run.dangerous-interactive-code-run",
        ["CWE-95"],
    ),
    (
        "python",
        "python.lang.security.audit.dangerous-code-run-audit.dangerous-interactive-code-run-audit",
        ["CWE-95"],
    ),
    (
        "python",
        "python.flask.security.dangerous-template-string.dangerous-template-string",
        ["CWE-96"],
    ),
    # custom Semgrep
    ("python", "vulnhunterx.python.template-injection", ["CWE-917", "CWE-1336"]),
    ("python", "config.semgrep-custom.vulnhunterx.python.template-injection", ["CWE-1336"]),
]

# Rules that carry CWE-94/95/96 but are not evaluators this table can decide.
_LEFT_ON_LEGACY = [
    ("java", "java/android/arbitrary-apk-installation", ["CWE-94"]),
    ("python", "py/unsafe-string-formatting", ["CWE-94", "CWE-134"]),
    ("python", "config.opengrep-rules.python.lang.security.audit.logging.listen-eval", ["CWE-95"]),
    ("python", "python.lang.security.audit.logging.listeneval.listen-eval", ["CWE-95"]),
    (
        "python",
        "config.opengrep-rules.python.lang.security.audit.dangerous-annotations-usage",
        ["CWE-95"],
    ),
    (
        "python",
        "python.lang.security.audit.dangerous-annotations-usage.dangerous-annotations-usage",
        ["CWE-95"],
    ),
    (
        "python",
        "config.opengrep-rules.python.django.security.injection.code.globals-misuse-code-execution",
        ["CWE-96"],
    ),
    ("python", "config.opengrep-rules.python.lang.security.dangerous-globals-use", ["CWE-96"]),
    ("python", "py/unsafe-reflection", ["CWE-470"]),
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
def test_non_evaluator_rules_are_not_claimed(lang, rule, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang=lang)
    assert resolved is None or not resolved.family.startswith("code_injection"), rule


def test_java_selects_cwe95_but_not_cwe94():
    assert _REG.resolve_family(cwe_ids=["CWE-95"], rule_id="x", lang="java").family == (
        "code_injection_java"
    )
    # CWE-94 also tags an APK-installation rule, so it is not a selector.
    assert _REG.resolve_family(cwe_ids=["CWE-94"], rule_id="x", lang="java") is None
    assert _policy("java").cwes == frozenset({"CWE-95"})


def test_python_has_no_cwe_selector():
    assert _policy("python").cwes == frozenset()
    for cwe in ("CWE-94", "CWE-95", "CWE-96", "CWE-917", "CWE-1336"):
        assert _REG.resolve_family(cwe_ids=[cwe], rule_id="x", lang="python") is None


@pytest.mark.parametrize(
    ("lang", "rule", "cwes"),
    [
        ("javascript", "js/code-injection", ["CWE-94", "CWE-95"]),
        ("php", "php.lang.security.eval-use.eval-use", ["CWE-95"]),
        ("go", "java/spel-expression-injection", ["CWE-94"]),
        ("java", "py/code-injection", ["CWE-94"]),
        ("python", "java/spel-expression-injection", ["CWE-94"]),
        ("", "py/code-injection", ["CWE-95"]),
    ],
)
def test_language_gate(lang, rule, cwes):
    resolved = _REG.resolve_family(cwe_ids=cwes, rule_id=rule, lang=lang)
    assert resolved is None or not resolved.family.startswith("code_injection")


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
    assert "production_scope" not in policy.decisive_slots
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
        ("sink_binding", "NOT_CODE_EVALUATION_SINK"),
        ("attacker_control", "REFUTED"),
        ("flow_to_sink", "NO_PATH_COMPLETE"),
        ("interpreter_channel", "DATA_ONLY_ALL_PATHS"),
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
def test_coverage_without_a_proven_code_text_path_does_not_dismiss(lang):
    # ALL_REACHING_PATHS is a claim about a code-text path; with the channel
    # unresolved there is nothing established to neutralize.
    facts = {k: v for k, v in _TP_FACTS.items() if k != "interpreter_channel"}
    facts["neutralization_coverage"] = "ALL_REACHING_PATHS"
    decision = entail(_policy(lang), facts)
    assert decision.verdict == NMD
    assert "interpreter_channel" in (decision.terminal_reason or "")


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_a_sandbox_left_unresolved_is_nmd_not_a_verdict(lang):
    # A restricted evaluator (SimpleEvaluationContext, SandboxedEnvironment)
    # establishes neither coverage value, so the slot is simply absent.
    facts = {k: v for k, v in _TP_FACTS.items() if k != "neutralization_coverage"}
    assert entail(_policy(lang), facts).verdict == NMD


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
    assert is_admissible(policy, "interpreter_channel", "CODE_TEXT_PATH_FOUND", [_DATAFLOW])
    assert is_admissible(policy, "neutralization_coverage", "BYPASS_PATH_FOUND", [_DATAFLOW])
    assert not is_admissible(policy, "interpreter_channel", "DATA_ONLY_ALL_PATHS", [_DATAFLOW])
    assert not is_admissible(policy, "neutralization_coverage", "ALL_REACHING_PATHS", [_DATAFLOW])
    assert not is_admissible(policy, "attacker_control", "REFUTED", [_DATAFLOW])
    assert not is_admissible(policy, "sink_binding", "NOT_CODE_EVALUATION_SINK", [_DATAFLOW])
    assert is_admissible(policy, "interpreter_channel", "DATA_ONLY_ALL_PATHS", [_LOCAL])


@pytest.mark.parametrize("lang", sorted(_FAMILIES))
def test_uncited_values_fail_closed(lang):
    policy = _policy(lang)
    for slot, value in _TP_FACTS.items():
        assert not is_admissible(policy, slot, value, [])
