# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Selector audit: which family policy owns each scanner rule.

``tests/fixtures/policy_selector_audit/rule_inventory.json`` lists every rule
the scanners can emit that carries a CWE tag, with the family the registry
selects for it (``legacy`` when none). These tests re-resolve every row, so a
selector edit that moves a rule between routes — or makes it match two families
and fail closed to Needs More Data — has to be made deliberately by regenerating
the inventory (``python scripts/audit_policy_selectors.py``) and reviewing the
diff.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

from benchmarks.adapters.cwe_rule_map import _LANG_TO_RULE_PREFIX, CWE_TO_RULES
from vuln_hunter_x.verification.policy.loader import load_policy_registry

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "audit_policy_selectors.py"
_spec = importlib.util.spec_from_file_location("audit_policy_selectors", _SCRIPT)
assert _spec and _spec.loader
audit = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = audit
_spec.loader.exec_module(audit)

_REG = load_policy_registry()
_ROWS = audit.load_inventory()
_REGEN = "re-run `python scripts/audit_policy_selectors.py` and review the diff"


def test_inventory_covers_every_stage_language_and_source():
    assert {r.lang for r in _ROWS} == set(audit.LANGS)
    assert {r.source for r in _ROWS} == audit.REPO_SOURCES | {audit.SRC_CODEQL_BUILTIN}


def test_every_rule_resolves_to_its_recorded_owner():
    moved = [
        f"{r.lang} {r.rule_id} {list(r.cwes)}: recorded {r.owner}, now {now}"
        for r in _ROWS
        if (now := audit.resolve_owner(_REG, r)) != r.owner
    ]
    assert not moved, f"rule ownership changed; {_REGEN}:\n" + "\n".join(moved[:40])


def test_no_rule_matches_two_families():
    # A rule owned by two families fails closed to Needs More Data for every
    # finding it emits. That must never be introduced by a selector edit.
    overlaps = [
        f"{r.lang} {r.rule_id} {list(r.cwes)} -> {r.owner}"
        for r in _ROWS
        if r.owner.startswith(audit.OVERLAP_PREFIX)
    ]
    assert not overlaps, "\n".join(overlaps)


def test_recorded_owners_are_loaded_families():
    owners = {r.owner for r in _ROWS} - {audit.LEGACY}
    assert owners <= set(_REG.families)


def test_in_repo_rule_sources_match_the_inventory():
    # Vendored OpenGrep rules, custom Semgrep rules and custom CodeQL queries are
    # re-read from the repository; a rule added, removed or re-tagged there must
    # show up in the inventory. (The built-in CodeQL suite needs the codeql
    # binary and is refreshed only by the script.)
    recorded = [r for r in _ROWS if r.source in audit.REPO_SOURCES]
    assert audit.collect_repo_rows(_REG) == recorded, f"inventory is stale; {_REGEN}"


def test_cwe_ids_use_the_parser_canonical_form():
    # Policy selectors compare against ids normalised by sarif/parser.py
    # (zero-stripped ``CWE-22``); the inventory must use the same form.
    assert all(c == f"CWE-{int(c[4:])}" for r in _ROWS for c in r.cwes)


def test_overlap_is_reported_not_raised():
    row = audit.RuleRow("php", "synthetic", "synthetic/two-families", ("CWE-22", "CWE-89"))
    assert audit.resolve_owner(_REG, row) == "OVERLAP:path_access,sql_injection"


def test_unowned_rule_is_legacy():
    row = audit.RuleRow("java", "synthetic", "synthetic/no-family", ("CWE-1234",))
    assert audit.resolve_owner(_REG, row) == audit.LEGACY


def test_language_gate_keeps_a_cwe_selector_inside_its_language():
    java = audit.RuleRow("java", "synthetic", "synthetic/sqli", ("CWE-89",))
    php = audit.RuleRow("php", "synthetic", "synthetic/sqli", ("CWE-89",))
    assert audit.resolve_owner(_REG, java) == "sql_injection_java"
    assert audit.resolve_owner(_REG, php) == "sql_injection"


@pytest.mark.parametrize(
    "rule_id",
    [
        "php.lang.security.injection.tainted-filename.tainted-filename",
        "config.opengrep-rules.php.lang.security.injection.tainted-filename",
        "php.lang.security.eval-use.eval-use",
        "config.opengrep-rules.php.lang.security.eval-use",
    ],
)
def test_php_path_handoff_covers_registry_and_vendored_rule_ids(rule_id):
    # The same rule has a different id per scanner; the handoff must not depend
    # on which of Semgrep or the vendored OpenGrep tree produced the finding.
    assert _REG.resolve_family(cwe_ids=[], rule_id=rule_id, lang="php") is None
    handoff = _REG.resolve_handoff(cwe_ids=[], rule_id=rule_id, lang="php")
    assert handoff is not None and handoff.family == "path_access"


def test_benchmark_rule_anchors_never_match_two_families():
    # Benchmark adapters anchor an entry on (CWE, rule id from cwe_rule_map). A
    # pair that two families claim would make every such entry Needs More Data.
    prefix_to_langs: dict[str, list[str]] = {}
    for lang, prefix in _LANG_TO_RULE_PREFIX.items():
        if lang != "typescript":  # analysed under the javascript stage language
            prefix_to_langs.setdefault(prefix, []).append(lang)
    overlaps = []
    for cwe, rules in CWE_TO_RULES.items():
        for rule in rules:
            for lang in prefix_to_langs.get(rule.split("/")[0] + "/", []):
                row = audit.RuleRow(lang, "benchmark", rule, (cwe,))
                owner = audit.resolve_owner(_REG, row)
                if owner.startswith(audit.OVERLAP_PREFIX):
                    overlaps.append(f"{lang} {cwe} {rule} -> {owner}")
    assert not overlaps, "\n".join(overlaps)
