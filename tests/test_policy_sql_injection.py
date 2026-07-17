# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Relational SQL-injection (CWE-89, PHP) family: selection + entailment.

A 4th family loads through the same generic machinery (no core-code change).
Its two DISTINCT defensive facts — query_channel (SQL text vs bound data) and
neutralization_coverage (effective, context-appropriate guard on all paths) —
must not collapse, and it deliberately has NO security_effect slot. CWE-89 owns
every PHP CWE-89 finding; a JS finding is out (language gate); a PHP finding
tagged both CWE-89 and CWE-22 matches this family and path_access → fails closed.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.loader import (
    PolicyOverlapError,
    load_policy_registry,
)
from vuln_hunter_x.verification.policy.models import FP, NMD, TP

_RULE = "php.lang.security.injection.tainted-sql-string.tainted-sql-string"
_REG = load_policy_registry()
_SQL = _REG.resolve_family(cwe_ids=["CWE-89"], rule_id=_RULE, lang="php")

_TP_FACTS = {
    "sink_binding": "QUALIFYING_RELATIONAL_SQL_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "query_channel": "SQL_TEXT_PATH_FOUND",
    "neutralization_coverage": "BYPASS_PATH_FOUND",
}


def test_family_loads_alongside_path_access():
    assert "sql_injection" in _REG.families
    assert "path_access" in _REG.families  # 2 PHP families coexist


def test_selects_on_cwe89_php():
    assert _SQL is not None and _SQL.family == "sql_injection"


def test_two_independent_defensive_slots_no_security_effect():
    assert "query_channel" in _SQL.decisive_slots
    assert "neutralization_coverage" in _SQL.decisive_slots
    assert "security_effect" not in _SQL.fact_slots


def test_javascript_sql_injection_is_out():
    # NodeGoat's js/sql-injection is MongoDB/NoSQL — a future family, not this one.
    assert _REG.resolve_family(cwe_ids=["CWE-89"], rule_id="js/sql-injection", lang="javascript") is None


def test_entail_tp():
    assert entail(_SQL, _TP_FACTS).verdict == TP


def test_bound_data_only_is_fp():
    assert entail(_SQL, {**_TP_FACTS, "query_channel": "BOUND_DATA_ONLY_ALL_PATHS"}).verdict == FP


def test_all_paths_neutralized_is_fp():
    assert entail(_SQL, {**_TP_FACTS, "neutralization_coverage": "ALL_REACHING_PATHS"}).verdict == FP


def test_refuted_attacker_control_is_fp():
    assert entail(_SQL, {**_TP_FACTS, "attacker_control": "REFUTED"}).verdict == FP


def test_missing_query_channel_is_nmd():
    facts = {k: v for k, v in _TP_FACTS.items() if k != "query_channel"}
    d = entail(_SQL, facts)
    assert d.verdict == NMD
    assert "query_channel" in (d.terminal_reason or "")


def test_cwe89_plus_cwe22_php_fails_closed():
    # A PHP finding tagged both CWE-89 (sql_injection) and CWE-22 (path_access)
    # matches two families → PolicyOverlapError → engine fails closed to NMD.
    with pytest.raises(PolicyOverlapError):
        _REG.resolve_family(cwe_ids=["CWE-89", "CWE-22"], rule_id="x", lang="php")
