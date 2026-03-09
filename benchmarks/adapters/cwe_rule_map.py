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
                 "js/shell-command-injection-from-environment"],
    "CWE-89":  ["py/sql-injection", "js/sql-injection", "php/sql-injection"],
    "CWE-22":  ["py/path-injection", "js/path-injection", "php/path-injection",
                 "cpp/path-injection"],
    "CWE-94":  ["py/code-injection", "js/code-injection"],
    "CWE-79":  ["js/xss", "py/reflected-xss", "php/reflected-xss"],
    "CWE-917": ["js/template-injection"],

    # Python-specific
    "CWE-502": ["py/unsafe-deserialization", "py/unsafe-yaml"],
    "CWE-601": ["py/url-redirection", "js/url-redirection"],
    "CWE-918": ["py/ssrf", "js/ssrf"],
    "CWE-117": ["py/log-injection"],
    "CWE-611": ["py/xml-bomb", "py/xpath-injection"],
    "CWE-327": ["py/weak-cryptography", "js/weak-cryptographic-algorithm"],
    "CWE-312": ["py/clear-text-storage-sensitive-data", "php/cleartext-storage"],

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


def all_mapped_cwes() -> list[str]:
    """Return all CWE IDs that have at least one rule mapping."""
    return sorted(CWE_TO_RULES.keys())
