# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Relational SQL-injection (CWE-89) families for Java, Python, JavaScript, Go
and C#: selection, language gate, entailment truth table and table parity.

Each language has its own file (``sql_injection_<lang>``) because the guidance
names language-specific sinks and bound-parameter APIs. The decision table is
the PHP reference family's table, unchanged.

Selectors differ by language on purpose:

* java / python / csharp select by CWE (CWE-89, plus CWE-564 for Java).
* javascript / go select by rule alias only. ``js/sql-injection`` (CWE-89, 90,
  943) is the rule that reports NoSQL query-object injection and
  ``go/unsafe-quoting`` (CWE-78, 89, 94) is interpreter-agnostic; a CWE-89
  selector would claim both and this relational table would dismiss them through
  ``sink_binding``. They stay on the legacy route.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.loader import load_policy_registry
from vuln_hunter_x.verification.policy.models import FP, NMD, TP
from vuln_hunter_x.verification.policy.support import SELECTABLE_PROFILES, is_admissible

_ROOT = Path(__file__).resolve().parents[1]
_POLICIES = _ROOT / "config" / "policies"
_REG = load_policy_registry()
_BY_FAMILY = {p.family: p for p in _REG._policies}

_LANGS = ("java", "python", "javascript", "go", "csharp")
_ALL_STAGE_LANGS = ("c", "cpp", "csharp", "go", "java", "javascript", "php", "python")

# (lang, rule id, CWE ids) the family must own: every id form that exists.
_OWNED = [
    # CodeQL
    ("java", "java/sql-injection", ["CWE-89", "CWE-564"]),
    ("java", "java/concatenated-sql-query", ["CWE-89", "CWE-564"]),
    # vendored OpenGrep / registry Semgrep
    ("java", "config.opengrep-rules.java.lang.security.audit.sqli.jdbc-sqli", ["CWE-89"]),
    ("java", "java.lang.security.audit.sqli.jdbc-sqli.jdbc-sqli", ["CWE-89"]),
    ("java", "config.opengrep-rules.java.lang.security.audit.sqli.hibernate-sqli", ["CWE-89"]),
    ("java", "java.spring.security.injection.tainted-sql-string.tainted-sql-string", ["CWE-89"]),
    ("java", "java.lang.security.audit.formatted-sql-string.formatted-sql-string", ["CWE-89"]),
    # CWE-564 alone (Hibernate) still selects the Java family
    ("java", "some/hibernate-rule", ["CWE-564"]),
    ("python", "py/sql-injection", ["CWE-89"]),
    ("python", "py/django-raw-sql", ["CWE-89"]),
    ("python", "config.opengrep-rules.python.lang.security.audit.sqli.psycopg-sqli", ["CWE-89"]),
    ("python", "python.lang.security.audit.sqli.psycopg-sqli.psycopg-sqli", ["CWE-89"]),
    (
        "python",
        "python.django.security.injection.sql.sql-injection-using-raw.sql-injection-using-raw",
        ["CWE-89"],
    ),
    (
        "python",
        "config.opengrep-rules.python.sqlalchemy.security.sqlalchemy-execute-raw-query",
        ["CWE-89"],
    ),
    ("javascript", "config.opengrep-rules.javascript.aws-lambda.security.knex-sqli", ["CWE-89"]),
    ("javascript", "javascript.aws-lambda.security.knex-sqli.knex-sqli", ["CWE-89"]),
    ("javascript", "config.opengrep-rules.javascript.aws-lambda.security.mysql-sqli", ["CWE-89"]),
    ("javascript", "javascript.aws-lambda.security.pg-sqli.pg-sqli", ["CWE-89"]),
    (
        "javascript",
        "config.opengrep-rules.javascript.aws-lambda.security.sequelize-sqli",
        ["CWE-89"],
    ),
    (
        "javascript",
        "javascript.aws-lambda.security.tainted-sql-string.tainted-sql-string",
        ["CWE-89"],
    ),
    (
        "javascript",
        "config.opengrep-rules.javascript.express.security.injection.tainted-sql-string",
        ["CWE-89"],
    ),
    (
        "javascript",
        "javascript.express.security.injection.tainted-sql-string.tainted-sql-string",
        ["CWE-89"],
    ),
    (
        "javascript",
        "config.opengrep-rules.javascript.lang.security.audit.sqli.node-knex-sqli",
        ["CWE-89"],
    ),
    (
        "javascript",
        "javascript.lang.security.audit.sqli.node-mssql-sqli.node-mssql-sqli",
        ["CWE-89"],
    ),
    (
        "javascript",
        "javascript.lang.security.audit.sqli.node-mysql-sqli.node-mysql-sqli",
        ["CWE-89"],
    ),
    (
        "javascript",
        "config.opengrep-rules.javascript.sequelize.security.audit.express-sequelize-injection",
        ["CWE-89"],
    ),
    (
        "javascript",
        "javascript.sequelize.security.audit.sequelize-injection-express."
        "express-sequelize-injection",
        ["CWE-89"],
    ),
    (
        "javascript",
        "javascript.sequelize.security.audit.sequelize-raw-query.sequelize-raw-query",
        ["CWE-89"],
    ),
    ("go", "go/sql-injection", ["CWE-89"]),
    ("go", "go/sql-injection-ext", ["CWE-89"]),
    ("go", "config.opengrep-rules.go.aws-lambda.security.database-sqli", ["CWE-89"]),
    ("go", "go.aws-lambda.security.tainted-sql-string.tainted-sql-string", ["CWE-89"]),
    (
        "go",
        "config.opengrep-rules.go.gorm.security.audit.gorm-dangerous-method-usage",
        ["CWE-89"],
    ),
    (
        "go",
        "go.gorm.security.audit.gorm-dangerous-methods-usage.gorm-dangerous-method-usage",
        ["CWE-89"],
    ),
    (
        "go",
        "config.opengrep-rules.go.lang.security.audit.database.string-formatted-query",
        ["CWE-89"],
    ),
    (
        "go",
        "go.lang.security.audit.database.string-formatted-query.string-formatted-query",
        ["CWE-89"],
    ),
    ("go", "config.opengrep-rules.go.lang.security.audit.sqli.gosql-sqli", ["CWE-89"]),
    ("go", "go.lang.security.audit.sqli.pg-orm-sqli.pg-orm-sqli", ["CWE-89"]),
    ("go", "go.lang.security.audit.sqli.pg-sqli.pg-sqli", ["CWE-89"]),
    ("go", "config.opengrep-rules.go.lang.security.audit.sqli.pgx-sqli", ["CWE-89"]),
    ("go", "go.lang.security.injection.tainted-sql-string.tainted-sql-string", ["CWE-89"]),
    ("csharp", "cs/sql-injection", ["CWE-89"]),
    ("csharp", "config.opengrep-rules.csharp.lang.security.sqli.csharp-sqli", ["CWE-89"]),
    ("csharp", "csharp.lang.security.sqli.csharp-sqli.csharp-sqli", ["CWE-89"]),
    ("csharp", "vulnhunterx.csharp.ef-raw-sql", ["CWE-89"]),
]

# (lang, rule id, CWE ids) that must NOT be claimed by a relational-SQL family.
_NOT_OWNED = [
    # NoSQL / document-store rules (CWE-943), every language
    (
        "java",
        "config.opengrep-rules.java.mongodb.security.injection.audit.mongodb-nosqli",
        ["CWE-943"],
    ),
    ("java", "java.mongodb.security.injection.audit.mongodb-nosqli.mongodb-nosqli", ["CWE-943"]),
    ("java", "vulnhunterx.java.nosql-injection", ["CWE-943"]),
    ("python", "py/nosql-injection", ["CWE-943"]),
    ("python", "vulnhunterx.python.nosql-injection", ["CWE-943"]),
    (
        "python",
        "python.aws-lambda.security.dynamodb-filter-injection.dynamodb-filter-injection",
        ["CWE-943"],
    ),
    ("javascript", "js/nosql-injection", ["CWE-943"]),
    ("javascript", "vulnhunterx.js.mongoose-where", ["CWE-943"]),
    (
        "javascript",
        "javascript.aws-lambda.security.dynamodb-request-object.dynamodb-request-object",
        ["CWE-943"],
    ),
    ("go", "vulnhunterx.go.nosql-injection", ["CWE-943"]),
    # The NoSQL-reporting CodeQL rule that is ALSO tagged CWE-89: legacy route.
    ("javascript", "js/sql-injection", ["CWE-89", "CWE-90", "CWE-943"]),
    # node-postgres-sqli is tagged CWE-915 upstream, not CWE-89: not claimed.
    (
        "javascript",
        "javascript.lang.security.audit.sqli.node-postgres-sqli.node-postgres-sqli",
        ["CWE-915"],
    ),
    # Sibling Sequelize audit rules are transport-security rules, not SQL sinks.
    (
        "javascript",
        "javascript.sequelize.security.audit.sequelize-enforce-tls.sequelize-enforce-tls",
        ["CWE-319"],
    ),
    # Interpreter-agnostic quoting rule tagged CWE-78/89/94: legacy route.
    ("go", "go/unsafe-quoting", ["CWE-78", "CWE-89", "CWE-94"]),
]

_TP_FACTS = {
    "sink_binding": "QUALIFYING_RELATIONAL_SQL_SINK",
    "attacker_control": "PROVEN",
    "flow_to_sink": "REACHES",
    "query_channel": "SQL_TEXT_PATH_FOUND",
    "neutralization_coverage": "BYPASS_PATH_FOUND",
}
_FP_VALUES = [
    ("sink_binding", "NOT_RELATIONAL_SQL_SINK"),
    ("attacker_control", "REFUTED"),
    ("flow_to_sink", "NO_PATH_COMPLETE"),
    ("query_channel", "BOUND_DATA_ONLY_ALL_PATHS"),
    ("neutralization_coverage", "ALL_REACHING_PATHS"),
]
_DECISIVE = tuple(_TP_FACTS)

_TABLE_KEYS = ("fact_slots", "decisive_slots", "entailment", "admissibility")
_VERDICT_WORDING = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct"
    r"|\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)"
    r"|OWASP|Juliet|DVWA|WebGoat|NodeGoat|benchmark",
    re.IGNORECASE,
)


def _family(lang: str) -> str:
    return f"sql_injection_{lang}"


def _policy(lang: str):
    return _BY_FAMILY[_family(lang)]


def _raw(name: str) -> dict:
    return yaml.safe_load((_POLICIES / f"{name}.yaml").read_text(encoding="utf-8"))


def _resolve(lang: str, rule_id: str, cwes: list[str]):
    return _REG.resolve_family(cwe_ids=cwes, rule_id=rule_id, lang=lang)


# ── loading and file shape ────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_family_loads_with_expected_identity(lang):
    policy = _policy(lang)
    raw = _raw(_family(lang))
    assert raw["family"] == _family(lang)
    assert raw["version"] == "1"
    assert policy.languages == frozenset({lang})
    assert "sql_injection" in _BY_FAMILY  # PHP reference stays loaded alongside


@pytest.mark.parametrize("lang", _LANGS)
def test_file_starts_with_license_header(lang):
    lines = (_POLICIES / f"{_family(lang)}.yaml").read_text(encoding="utf-8").splitlines()
    assert lines[0] == "# SPDX-License-Identifier: LGPL-2.1-only"
    assert lines[1] == "# Copyright (c) 2026 VinSOC Cyber"


def test_selector_kinds_per_language():
    assert _policy("java").cwes == frozenset({"CWE-89", "CWE-564"})
    assert _policy("python").cwes == frozenset({"CWE-89"})
    assert _policy("csharp").cwes == frozenset({"CWE-89"})
    for lang in ("java", "python", "csharp"):
        assert _policy(lang).rule_aliases == ()
    # Alias-only: a CWE-89 selector would claim js/sql-injection / go/unsafe-quoting.
    for lang in ("javascript", "go"):
        assert _policy(lang).cwes == frozenset()
        assert _policy(lang).rule_aliases


@pytest.mark.parametrize("lang", _LANGS)
def test_no_family_selects_nosql_cwe(lang):
    assert "CWE-943" not in _policy(lang).cwes


# ── selection ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(("lang", "rule_id", "cwes"), _OWNED)
def test_rule_is_selected_by_its_language_family(lang, rule_id, cwes):
    policy = _resolve(lang, rule_id, cwes)
    assert policy is not None and policy.family == _family(lang)


@pytest.mark.parametrize(("lang", "rule_id", "cwes"), _NOT_OWNED)
def test_out_of_scope_rule_is_not_claimed(lang, rule_id, cwes):
    policy = _resolve(lang, rule_id, cwes)
    assert policy is None or not policy.family.startswith("sql_injection")


@pytest.mark.parametrize("lang", ["java", "python", "csharp"])
def test_cwe_selected_family_owns_any_cwe89_rule_id(lang):
    assert _resolve(lang, "unknown/rule", ["CWE-89"]).family == _family(lang)


@pytest.mark.parametrize("lang", ["javascript", "go"])
def test_alias_selected_family_needs_a_known_rule_id(lang):
    # No CWE selector: a CWE-89 finding with an unlisted rule id stays legacy.
    assert _resolve(lang, "unknown/rule", ["CWE-89"]) is None


@pytest.mark.parametrize(("lang", "rule_id", "cwes"), _OWNED)
def test_language_gate(lang, rule_id, cwes):
    # The same rule id and CWE set under any other stage language never
    # resolves to this language's family.
    for other in _ALL_STAGE_LANGS:
        if other == lang:
            continue
        policy = _resolve(other, rule_id, cwes)
        assert policy is None or policy.family != _family(lang)


def test_php_reference_family_still_owns_php_cwe89():
    rule = "php.lang.security.injection.tainted-sql-string.tainted-sql-string"
    assert _resolve("php", rule, ["CWE-89"]).family == "sql_injection"


def test_c_and_cpp_cwe89_are_not_claimed():
    for lang in ("c", "cpp"):
        policy = _resolve(lang, "cpp/sql-injection", ["CWE-89"])
        assert policy is None or not policy.family.startswith("sql_injection")


def _load_audit():
    script = _ROOT / "scripts" / "audit_policy_selectors.py"
    spec = importlib.util.spec_from_file_location("audit_policy_selectors_sqli", script)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def test_inventory_rules_tagged_cwe89_are_owned_except_documented_legacy():
    # Every scanner rule in these languages tagged CWE-89 / CWE-564 resolves to
    # the language's family, apart from the two documented multi-interpreter
    # rules; and nothing without one of those CWEs is claimed.
    audit = _load_audit()
    legacy = {("javascript", "js/sql-injection"), ("go", "go/unsafe-quoting")}
    seen = dict.fromkeys(_LANGS, 0)
    for row in audit.load_inventory():
        if row.lang not in _LANGS:
            continue
        tagged = bool({"CWE-89", "CWE-564"} & set(row.cwes))
        own = [
            p.family
            for p in _REG._policies
            if p.family.startswith("sql_injection")
            and _REG._matches(p, set(row.cwes), row.rule_id, row.lang)
        ]
        if (row.lang, row.rule_id) in legacy:
            assert own == [], row
        elif tagged:
            assert own == [_family(row.lang)], row
            seen[row.lang] += 1
        else:
            assert own == [], row
    assert all(seen.values()), seen


# ── entailment truth table ────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_full_conjunction_is_tp(lang):
    d = entail(_policy(lang), _TP_FACTS)
    assert d.verdict == TP
    assert d.family == _family(lang)
    assert d.terminal_reason is None


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(("slot", "value"), _FP_VALUES)
def test_each_dominating_value_is_fp(lang, slot, value):
    d = entail(_policy(lang), {**_TP_FACTS, slot: value})
    assert d.verdict == FP
    assert f"{slot}={value}" in (d.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(("slot", "value"), _FP_VALUES)
def test_dominating_value_alone_is_fp_even_with_other_slots_unresolved(lang, slot, value):
    assert entail(_policy(lang), {slot: value}).verdict == FP


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize("missing", _DECISIVE)
def test_each_missing_decisive_slot_is_nmd_with_reason(lang, missing):
    facts = {k: v for k, v in _TP_FACTS.items() if k != missing}
    d = entail(_policy(lang), facts)
    assert d.verdict == NMD
    assert d.terminal_reason == f"unresolved: {missing}"


@pytest.mark.parametrize("lang", _LANGS)
def test_no_facts_is_nmd_naming_every_decisive_slot(lang):
    d = entail(_policy(lang), {})
    assert d.verdict == NMD
    for slot in _DECISIVE:
        assert slot in (d.terminal_reason or "")


@pytest.mark.parametrize("lang", _LANGS)
@pytest.mark.parametrize(
    "scope", ["PROD", "TEST_ONLY", "EXAMPLE_DEV", "GENERATED_VENDOR", "UNKNOWN"]
)
def test_production_scope_is_recorded_but_never_decisive(lang, scope):
    policy = _policy(lang)
    assert "production_scope" not in policy.decisive_slots
    assert entail(policy, {**_TP_FACTS, "production_scope": scope}).verdict == TP
    assert entail(policy, {"production_scope": scope}).verdict == NMD


@pytest.mark.parametrize("lang", _LANGS)
def test_two_independent_defensive_slots_no_security_effect(lang):
    policy = _policy(lang)
    assert policy.decisive_slots == frozenset(_DECISIVE)
    assert "security_effect" not in policy.fact_slots


# ── admissibility ─────────────────────────────────────────────────────

_LOCAL = EvidenceEntry(id="L1", origin=EvidenceOrigin.LOCAL_SLICE, summary="slice")
_DATAFLOW = EvidenceEntry(id="D1", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary="flow")


@pytest.mark.parametrize("lang", _LANGS)
def test_positive_path_values_admit_scanner_dataflow(lang):
    policy = _policy(lang)
    assert is_admissible(policy, "attacker_control", "PROVEN", [_DATAFLOW])
    assert is_admissible(policy, "flow_to_sink", "REACHES", [_DATAFLOW])
    assert is_admissible(policy, "query_channel", "SQL_TEXT_PATH_FOUND", [_DATAFLOW])
    assert is_admissible(policy, "neutralization_coverage", "BYPASS_PATH_FOUND", [_LOCAL])


@pytest.mark.parametrize("lang", _LANGS)
def test_dismissing_values_do_not_admit_scanner_dataflow_alone(lang):
    # A scanner path shows that a flow exists; it never shows that every path
    # is bound, covered, absent, or that the value is not attacker-controlled.
    policy = _policy(lang)
    for slot, value in _FP_VALUES:
        assert not is_admissible(policy, slot, value, [_DATAFLOW]), (slot, value)
        assert is_admissible(policy, slot, value, [_LOCAL]), (slot, value)


@pytest.mark.parametrize("lang", _LANGS)
def test_uncited_values_fail_closed(lang):
    policy = _policy(lang)
    for slot, values in policy.fact_slots.items():
        for value in values:
            assert not is_admissible(policy, slot, value, [])


@pytest.mark.parametrize("lang", _LANGS)
def test_every_value_has_a_selectable_profile(lang):
    policy = _policy(lang)
    for slot, values in policy.fact_slots.items():
        for value in values:
            assert policy.admissibility[slot][value] in SELECTABLE_PROFILES


# ── decision-table parity with the PHP reference ──────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_decision_table_equals_php_reference(lang):
    reference, member = _raw("sql_injection"), _raw(_family(lang))
    for key in _TABLE_KEYS:
        assert member[key] == reference[key], key


@pytest.mark.parametrize("lang", _LANGS)
def test_loaded_table_equals_php_reference(lang):
    reference, member = _BY_FAMILY["sql_injection"], _policy(lang)
    assert member.fact_slots == reference.fact_slots
    assert member.decisive_slots == reference.decisive_slots
    assert member.true_positive == reference.true_positive
    assert member.false_positive_if_any == reference.false_positive_if_any
    assert member.admissibility == reference.admissibility


def test_decision_table_is_identical_across_all_language_files():
    tables = [{k: _raw(_family(lang))[k] for k in _TABLE_KEYS} for lang in _LANGS]
    assert all(t == tables[0] for t in tables)


# ── guidance ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_has_one_entry_per_decisive_slot(lang):
    guidance = _policy(lang).assessment_guidance
    assert [g.split(":", 1)[0] for g in guidance] == list(_DECISIVE)


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_is_neutral(lang):
    text = " ".join(_policy(lang).assessment_guidance)
    assert not _VERDICT_WORDING.search(text)


@pytest.mark.parametrize("lang", _LANGS)
def test_guidance_keeps_grammar_position_rule_and_nosql_exclusion(lang):
    by_slot = {g.split(":", 1)[0]: g for g in _policy(lang).assessment_guidance}
    neutral = by_slot["neutralization_coverage"]
    for phrase in (
        "exact grammar position",
        "covers only a quoted-literal position",
        "covers a numeric position",
        "finite allowlist",
        "sibling branch does not cover the flagged branch",
        "UNRESOLVED",
    ):
        assert phrase in neutral, phrase
    assert "document-store" in by_slot["sink_binding"]
    assert "NOT_RELATIONAL_SQL_SINK" in by_slot["sink_binding"]
    assert "on EVERY reaching path" in by_slot["query_channel"]


@pytest.mark.parametrize(
    ("lang", "slot", "phrases"),
    [
        ("java", "sink_binding", ["createNativeQuery", "JdbcTemplate", "JPQL"]),
        ("java", "query_channel", ["PreparedStatement", "setParameter", "${...}", "#{...}"]),
        ("python", "sink_binding", ["cursor.execute", "RawSQL()", "text()"]),
        ("python", "query_channel", ["execute(sql % (value,))", "bindparams()", "f-string"]),
        ("javascript", "sink_binding", ["sequelize.query", "knex.raw", "MongoDB"]),
        ("javascript", "query_channel", ["replacements", "$1", "sql.query`...${v}`"]),
        ("go", "sink_binding", ["QueryRow", "sqlx", "GORM"]),
        ("go", "query_channel", ["fmt.Sprintf", "db.First(&u, value)", "sqlx.In"]),
        ("csharp", "sink_binding", ["CommandText", "Dapper", "FromSqlRaw"]),
        ("csharp", "query_channel", ["AddWithValue", "FromSqlInterpolated", "LINQ"]),
    ],
)
def test_guidance_names_language_apis(lang, slot, phrases):
    by_slot = {g.split(":", 1)[0]: g for g in _policy(lang).assessment_guidance}
    for phrase in phrases:
        assert phrase in by_slot[slot], phrase
