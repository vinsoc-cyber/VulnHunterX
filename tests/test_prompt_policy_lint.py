# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Prompt-policy lint: covered-family rules gather facts, they don't command a
verdict.

Covered so far: CWE-117 (js/log-injection) and CWE-643 (py/xpath-injection).
The remaining Python verdict-forcing / benchmark-coaching directives are NOT
rewritten here — this lint keeps an EXACT inventory of them so the residual is
explicit and any drift (a rule silently gaining or losing a verdict command) is
caught. De-coaching another rule must update the expected set deliberately.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_PROMPTS = Path(__file__).resolve().parents[1] / "config" / "prompts"
_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct", re.IGNORECASE
)
_COACHING = re.compile(r"OWASP FP|FP trap|FP case", re.IGNORECASE)
# PHP rules coach with parenthetical verdict labels — "(vulnerable)", "(safe)",
# "(insufficient for safety)" — rather than the explicit-verdict phrasing above.
# These bias the fact-slot assessment because the rule's guided questions are
# still rendered into the policy (assessment-mode) prompt (only the trailing
# verdict command is stripped).
_PHP_PAREN_VERDICT = re.compile(
    r"\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)", re.IGNORECASE
)

# Python rules that STILL command a verdict (the closed-world contradiction is
# closed only for the covered families). py/xpath-injection and py/log-injection
# are deliberately absent — they are covered by an evidence-closure policy.
_EXPECTED_PY_VERDICT_CMD = frozenset({
    "py/broken-authentication", "py/code-injection", "py/command-injection",
    "py/command-line-injection", "py/header-injection", "py/improper-privilege-management",
    "py/incorrect-authorization", "py/ldap-injection", "py/missing-authentication",
    "py/open-redirect", "py/path-injection", "py/sql-injection", "py/ssrf",
    "py/tainted-format-string", "py/template-injection", "py/trust-boundary-violation",
    "py/unsafe-deserialization", "py/url-redirection", "py/weak-cryptographic-algorithm",
    "py/weak-sensitive-data-hashing", "py/xml-bomb", "py/xss", "py/xxe",
})
# Python rules that STILL carry benchmark-derived "OWASP FP trap" coaching (#145).
_EXPECTED_PY_COACHING = frozenset({
    "py/open-redirect", "py/path-injection", "py/url-redirection",
})
# PHP rules that STILL carry parenthetical verdict labels. php/sql-injection is
# deliberately absent — it is covered by the CWE-89 evidence-closure policy.
_EXPECTED_PHP_PAREN_VERDICT = frozenset({"php/regex-injection"})


def _rule_text(entry: dict) -> str:
    parts = list(entry.get("questions", []))
    parts.append(entry.get("context_hint", ""))
    parts.append(entry.get("short_description", ""))
    return " ".join(parts)


def _rules_matching(lang: str, pattern: re.Pattern) -> set[str]:
    data = yaml.safe_load((_PROMPTS / f"{lang}_questions.yaml").read_text())
    return {
        key for key, entry in data.items()
        if isinstance(entry, dict) and pattern.search(_rule_text(entry))
    }


def test_js_log_injection_rule_is_locators_only():
    data = yaml.safe_load((_PROMPTS / "javascript_questions.yaml").read_text())
    assert not _VERDICT_CMD.search(_rule_text(data["js/log-injection"])), (
        "the covered CWE-117 rule must gather facts, not command a verdict"
    )


def test_py_xpath_injection_rule_is_locators_only():
    data = yaml.safe_load((_PROMPTS / "python_questions.yaml").read_text())
    text = _rule_text(data["py/xpath-injection"])
    assert not _VERDICT_CMD.search(text), (
        "the covered CWE-643 rule must gather facts, not command a verdict"
    )
    assert not _COACHING.search(text), (
        "the covered CWE-643 rule must not carry benchmark 'OWASP FP trap' coaching"
    )


def test_python_verdict_command_inventory_is_exact():
    # Exact residual: the covered rules are gone; everything else is unchanged.
    assert _rules_matching("python", _VERDICT_CMD) == _EXPECTED_PY_VERDICT_CMD


def test_python_coaching_inventory_is_exact():
    assert _rules_matching("python", _COACHING) == _EXPECTED_PY_COACHING


def test_php_sql_injection_rule_is_locators_only():
    data = yaml.safe_load((_PROMPTS / "php_questions.yaml").read_text())
    text = _rule_text(data["php/sql-injection"])
    assert not _PHP_PAREN_VERDICT.search(text), (
        "the covered CWE-89 rule must gather facts, not label answers "
        "(vulnerable)/(safe)/(insufficient) — the family entailment decides the verdict"
    )


def test_php_paren_verdict_inventory_is_exact():
    # Exact residual: php/sql-injection is de-coached (covered by the CWE-89
    # policy); php/regex-injection is not yet covered and is left unchanged.
    assert _rules_matching("php", _PHP_PAREN_VERDICT) == _EXPECTED_PHP_PAREN_VERDICT


def test_other_languages_still_have_verdict_commands():
    # P2c does not touch java/cpp; they still command verdicts (not yet covered).
    assert _rules_matching("java", _VERDICT_CMD)
    assert _rules_matching("cpp", _VERDICT_CMD)
