# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Bidirectional CWE ↔ CodeQL / Semgrep rule ID mapping.

Sources:
    docs/codeql_cpp_security.md
    docs/codeql_python_security.md
    docs/codeql_javascript_security.md
"""

from __future__ import annotations

# CWE ID → list of CodeQL/Semgrep rule IDs
CWE_TO_RULES: dict[str, list[str]] = {
    # Memory safety (C/C++)
    "CWE-416": ["cpp/use-after-free"],
    "CWE-415": ["cpp/double-free"],
    "CWE-476": ["cpp/null-pointer-dereference", "cpp/tainted-null-dereference"],
    "CWE-119": ["cpp/overflow-destination", "cpp/overrunning-write", "cpp/overrunning-write-with-float"],
    "CWE-122": ["cpp/heap-buffer-overflow"],
    "CWE-125": ["cpp/out-of-bounds-read"],
    "CWE-787": ["cpp/overflow-destination", "cpp/overrunning-write"],
    "CWE-190": ["cpp/integer-overflow"],
    "CWE-193": ["cpp/off-by-one"],
    "CWE-134": ["cpp/tainted-format-string"],
    "CWE-401": ["cpp/resource-leak"],
    "CWE-457": ["cpp/use-of-uninitialized-variable"],
    "CWE-362": ["cpp/race-condition"],
    "CWE-197": ["cpp/integer-conversion"],
    "CWE-170": ["cpp/overflowing-snprintf"],
    "CWE-252": ["cpp/unchecked-return-value"],
    "CWE-426": ["cpp/untrusted-search-path"],

    # Injection (all languages)
    "CWE-77":  ["cpp/command-line-injection", "py/command-injection",
                 "js/command-injection", "php/command-injection", "java/command-injection"],
    "CWE-78":  ["cpp/tainted-eval-uncontrolled", "py/command-line-injection",
                 "js/shell-command-injection-from-environment", "java/command-line-injection"],
    "CWE-89":  ["py/sql-injection", "js/sql-injection", "php/sql-injection",
                 "java/sql-injection"],
    "CWE-22":  ["py/path-injection", "js/path-injection", "php/path-injection",
                 "cpp/path-injection", "java/path-injection"],
    "CWE-94":  ["py/code-injection", "js/code-injection"],
    "CWE-79":  ["js/xss", "py/reflected-xss", "php/reflected-xss",
                 "java/xss"],
    "CWE-917": ["js/template-injection"],
    "CWE-90":  ["java/ldap-injection", "py/ldap-injection"],
    "CWE-643": ["java/xpath-injection", "py/xpath-injection-from-tainted-data"],

    # Python-specific
    "CWE-502": ["py/unsafe-deserialization", "py/unsafe-yaml"],
    "CWE-601": ["py/url-redirection", "js/url-redirection"],
    "CWE-918": ["py/ssrf", "js/ssrf"],
    "CWE-117": ["py/log-injection"],
    "CWE-611": ["py/xml-bomb", "py/xpath-injection"],
    "CWE-327": ["py/weak-cryptography", "js/weak-cryptographic-algorithm",
                 "java/weak-cryptographic-algorithm"],
    "CWE-328": ["java/weak-cryptographic-hash", "py/weak-sensitive-data-hashing"],
    "CWE-330": ["java/insecure-randomness", "py/insecure-randomness",
                 "js/insecure-randomness"],
    "CWE-312": ["py/clear-text-storage-sensitive-data", "php/cleartext-storage"],
    "CWE-501": ["java/trust-boundary-violation"],
    "CWE-614": ["java/insecure-cookie", "js/insecure-cookie"],

    # JavaScript-specific
    "CWE-1333": ["js/redos"],
    "CWE-400":  ["js/polynomial-redos"],
    "CWE-471":  ["js/prototype-pollution"],
    "CWE-829":  ["js/untrusted-module-loading"],
    "CWE-319":  ["js/insecure-websocket", "php/cleartext-transmission"],

    # PHP-specific
    "CWE-98":  ["php/file-inclusion"],
    "CWE-621": ["php/variable-variables"],
    "CWE-73":  ["php/stream-wrapper-injection"],
    "CWE-295": ["php/certificate-validation-disabled"],

    # Cross-language
    "CWE-352": ["py/csrf-protection"],
    "CWE-20":  ["py/input-validation", "js/input-validation", "php/input-validation",
                 "cpp/input-validation"],
    "CWE-862": ["py/missing-access-control", "js/missing-authorization",
                 "php/missing-authorization", "cpp/missing-authorization"],

    # Parent/category CWEs (DiverseVul labels heavily with these; route them
    # to the corresponding leaf-CWE rules so guided-question lookup hits the
    # exact-match tier instead of falling to default questions).
    "CWE-189": ["cpp/integer-overflow", "cpp/integer-conversion"],          # Numeric Errors → CWE-190/197
    "CWE-120": ["cpp/overflow-destination", "cpp/overrunning-write"],       # Buffer Copy w/o Size Check → CWE-787
    "CWE-399": ["cpp/resource-leak"],                                       # Resource Management Errors → CWE-401
    "CWE-772": ["cpp/resource-leak"],                                       # Missing Release of Resource → CWE-401
    "CWE-310": ["cpp/weak-cryptography", "py/weak-cryptography",
                 "java/weak-cryptographic-algorithm"],                       # Crypto Issues → CWE-327
    "CWE-264": ["cpp/missing-authorization", "py/missing-access-control",
                 "java/missing-authorization"],                              # Access Control → CWE-862
    "CWE-269": ["cpp/missing-authorization", "py/missing-access-control"],   # Improper Privilege Mgmt → CWE-862
    "CWE-287": ["cpp/missing-authorization", "py/missing-access-control"],   # Improper Authentication → CWE-862
    "CWE-200": ["cpp/cleartext-storage", "py/clear-text-storage-sensitive-data",
                 "php/cleartext-storage"],                                    # Info Exposure → CWE-312
    "CWE-909": ["cpp/use-of-uninitialized-variable"],                       # Missing Initialization → CWE-457
    "CWE-59":  ["cpp/path-injection", "py/path-injection"],                 # Link Resolution → CWE-22
    "CWE-346": ["cpp/missing-authorization", "java/missing-authorization"], # Origin Validation Error → CWE-862
    "CWE-16":  ["cpp/missing-authorization"],                               # Configuration (catch-all)
}

# Build reverse mapping: rule ID → CWE ID
_RULE_TO_CWE: dict[str, str] = {}
for cwe, rules in CWE_TO_RULES.items():
    for rule in rules:
        _RULE_TO_CWE[rule] = cwe


def cwe_to_rules(cwe_id: str) -> list[str]:
    """Return CodeQL/Semgrep rule IDs for a given CWE ID.

    Args:
        cwe_id: CWE identifier, e.g. "CWE-416" or "416"

    Returns:
        List of rule IDs, empty if no mapping exists.
    """
    # Normalize: accept "416" or "CWE-416"
    normalized = cwe_id if cwe_id.startswith("CWE-") else f"CWE-{cwe_id}"
    return CWE_TO_RULES.get(normalized, [])


def rule_to_cwe(rule_id: str) -> str:
    """Return the CWE ID for a given rule ID, or '' if not mapped."""
    return _RULE_TO_CWE.get(rule_id, "")


def primary_rule(cwe_id: str) -> str:
    """Return the primary (first) CodeQL rule ID for a CWE, or ''."""
    rules = cwe_to_rules(cwe_id)
    return rules[0] if rules else ""


# Map adapter-level language labels to the rule-prefix used in CWE_TO_RULES.
# Adapters use "c" / "cpp" / "python" / "javascript" / "php" / "java"; the
# rule IDs are prefixed with "cpp/" / "py/" / "js/" / "php/" / "java/".
_LANG_TO_RULE_PREFIX: dict[str, str] = {
    "c": "cpp/",
    "cpp": "cpp/",
    "python": "py/",
    "javascript": "js/",
    "typescript": "js/",
    "php": "php/",
    "java": "java/",
}


def primary_rule_for_lang(cwe_id: str, lang: str) -> str:
    """Return the rule for ``cwe_id`` whose prefix matches ``lang``.

    Falls back to :func:`primary_rule` when no rule matches the language.
    Used by dataset adapters so that, e.g., a C file under ``CWE-22/`` gets
    ``cpp/path-injection`` instead of ``py/path-injection`` (the latter
    being the alphabetically-first entry in the CWE-22 list).
    """
    prefix = _LANG_TO_RULE_PREFIX.get(lang)
    if prefix:
        for rid in cwe_to_rules(cwe_id):
            if rid.startswith(prefix):
                return rid
    return primary_rule(cwe_id)


def all_mapped_cwes() -> list[str]:
    """Return all CWE IDs that have at least one rule mapping."""
    return sorted(CWE_TO_RULES.keys())
