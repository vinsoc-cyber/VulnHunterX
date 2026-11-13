# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic acceptance panel for the relational SQL-injection (CWE-89)
families of Java, Python, JavaScript, Go and C#.

Drives the full policy path — ``LLMClient.analyze()`` with a real
``PolicyClosureController`` — against a scripted (mocked) model, so every case
is reproducible without an LLM. The verdict is entailed by the family's fact
table and evidence admissibility, NOT by a model verdict string.

Every fixture is synthetic: a short, realistic snippet per language for each
deciding fact (SQL text with no covering defense -> True Positive; bound
parameters, a position-appropriate defense, a constant value, a non-relational
sink -> False Positive; a fact the slice cannot show -> Needs More Data).

Scripted tests prove policy and control correctness, not model semantic quality.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
)
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.verification.policy.closure import PolicyClosureController
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import load_policy_registry

_REG = load_policy_registry()

_TP = "True Positive"
_FP = "False Positive"
_NMD = "Needs More Data"

# A fully resolved assessment: an attacker value reaches the SQL text with no
# defense covering its position. Individual cases change one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_RELATIONAL_SQL_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "query_channel": {"value": "SQL_TEXT_PATH_FOUND", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}
_UNRESOLVED = {"value": "UNRESOLVED", "evidence": []}

_BOUND = {"query_channel": {"value": "BOUND_DATA_ONLY_ALL_PATHS", "evidence": ["L1"]}}
_COVERED = {"neutralization_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["L1"]}}
_CONSTANT = {"attacker_control": {"value": "REFUTED", "evidence": ["L1"]}}
_NOT_SQL = {"sink_binding": {"value": "NOT_RELATIONAL_SQL_SINK", "evidence": ["L1"]}}
_NO_PATH = {"flow_to_sink": {"value": "NO_PATH_COMPLETE", "evidence": ["L1"]}}

_VERDICT_WORDING = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct"
    r"|\((?:vulnerable|unsafe|safe|insufficient[^)]*)\)"
    r"|OWASP|Juliet|DVWA|WebGoat|NodeGoat",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class _Case:
    name: str
    snippet: str
    overrides: dict = field(default_factory=dict)
    expected: str = _TP


@dataclass(frozen=True)
class _Lang:
    lang: str
    rule_id: str
    cwes: tuple[str, ...]
    file: str
    dataflow: tuple[str, str]
    guidance_markers: tuple[str, ...]
    cases: tuple[_Case, ...]

    @property
    def family(self) -> str:
        return f"sql_injection_{self.lang}"


_JAVA = _Lang(
    lang="java",
    rule_id="java/sql-injection",
    cwes=("CWE-89", "CWE-564"),
    file="src/main/java/com/example/UserDao.java",
    dataflow=('request.getParameter("name")', "stmt.executeQuery(sql)"),
    guidance_markers=("createNativeQuery", "PreparedStatement", "#{...}"),
    cases=(
        _Case(
            "statement_concat",
            'String sql = "SELECT * FROM users WHERE name = \'" + name + "\'";\n'
            "ResultSet rs = stmt.executeQuery(sql);",
        ),
        _Case(
            "prepared_statement_built_by_concat",
            # A PreparedStatement whose SQL was concatenated is still SQL text.
            "PreparedStatement ps = conn.prepareStatement(\n"
            '    "SELECT * FROM users WHERE name = \'" + name + "\' AND active = ?");\n'
            "ps.setBoolean(1, true);\nps.executeQuery();",
        ),
        _Case(
            "jpql_concat",
            'em.createQuery("SELECT u FROM User u WHERE u.name = \'" + name + "\'").getResultList();',
        ),
        _Case(
            "order_by_column_from_request",
            # Quote doubling does not cover an identifier position.
            'String sort = request.getParameter("sort").replace("\'", "\'\'");\n'
            'jdbcTemplate.query("SELECT * FROM users ORDER BY " + sort, mapper);',
        ),
        _Case(
            "prepared_statement_bound",
            'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE name = ?");\n'
            "ps.setString(1, name);\nps.executeQuery();",
            _BOUND,
            _FP,
        ),
        _Case(
            "jpa_named_parameter",
            'em.createQuery("SELECT u FROM User u WHERE u.name = :name")\n'
            '  .setParameter("name", name).getResultList();',
            _BOUND,
            _FP,
        ),
        _Case(
            "parse_int_in_numeric_position",
            'int id = Integer.parseInt(request.getParameter("id"));\n'
            'stmt.executeQuery("SELECT * FROM users WHERE id = " + id);',
            _COVERED,
            _FP,
        ),
        _Case(
            "constant_table_name",
            'private static final String TABLE = "users";\n'
            'stmt.executeQuery("SELECT COUNT(*) FROM " + TABLE);',
            _CONSTANT,
            _FP,
        ),
        _Case(
            "mongo_filter_is_not_relational",
            'collection.find(new Document("name", name)).first();',
            _NOT_SQL,
            _FP,
        ),
        _Case(
            "mybatis_mapper_text_not_in_evidence",
            # ${} vs #{} lives in the mapper XML, which the slice does not show.
            "List<User> users = userMapper.findByName(name);",
            {"query_channel": _UNRESOLVED, "neutralization_coverage": _UNRESOLVED},
            _NMD,
        ),
    ),
)

_PYTHON = _Lang(
    lang="python",
    rule_id="py/sql-injection",
    cwes=("CWE-89",),
    file="app/views.py",
    dataflow=('request.args.get("name")', "cursor.execute(query)"),
    guidance_markers=("cursor.execute", "bindparams()", "execute(sql % (value,))"),
    cases=(
        _Case(
            "fstring_into_execute",
            "query = f\"SELECT * FROM users WHERE name = '{name}'\"\ncursor.execute(query)",
        ),
        _Case(
            "percent_format_applied_to_the_string",
            "cursor.execute(\"SELECT * FROM users WHERE name = '%s'\" % name)",
        ),
        _Case(
            "sqlalchemy_text_fstring",
            "session.execute(text(f\"SELECT * FROM users WHERE name = '{name}'\"))",
        ),
        _Case(
            "django_raw_format",
            "User.objects.raw(\"SELECT * FROM auth_user WHERE username = '{}'\".format(name))",
        ),
        _Case(
            "escape_string_in_numeric_position",
            # A string escaper does not cover an unquoted numeric position.
            'uid = escape_string(request.args["id"])\n'
            'cursor.execute("SELECT * FROM users WHERE id = " + uid)',
        ),
        _Case(
            "dbapi_parameters_argument",
            'cursor.execute("SELECT * FROM users WHERE name = %s", (name,))',
            _BOUND,
            _FP,
        ),
        _Case(
            "sqlalchemy_text_bindparams",
            'session.execute(text("SELECT * FROM users WHERE name = :n").bindparams(n=name))',
            _BOUND,
            _FP,
        ),
        _Case(
            "django_orm_filter_kwarg",
            "User.objects.filter(username=name).first()",
            _BOUND,
            _FP,
        ),
        _Case(
            "int_conversion_in_numeric_position",
            'uid = int(request.args["id"])\n'
            'cursor.execute(f"SELECT * FROM users WHERE id = {uid}")',
            _COVERED,
            _FP,
        ),
        _Case(
            "column_allowlist",
            'col = request.args["sort"]\nif col not in ("name", "created"):\n    abort(400)\n'
            'cursor.execute(f"SELECT * FROM users ORDER BY {col}")',
            _COVERED,
            _FP,
        ),
        _Case(
            "pymongo_find_is_not_relational",
            'db.users.find_one({"name": name})',
            _NOT_SQL,
            _FP,
        ),
        _Case(
            "value_overwritten_before_sink",
            'name = request.args.get("name")\nname = "admin"\n'
            "cursor.execute(f\"SELECT * FROM users WHERE name = '{name}'\")",
            _NO_PATH,
            _FP,
        ),
    ),
)

_JAVASCRIPT = _Lang(
    lang="javascript",
    rule_id="javascript.express.security.injection.tainted-sql-string.tainted-sql-string",
    cwes=("CWE-89",),
    file="routes/users.js",
    dataflow=("req.query.name", "connection.query(sql)"),
    guidance_markers=("sequelize.query", "knex.raw", "sql.query`...${v}`"),
    cases=(
        _Case(
            "template_literal_into_mysql_query",
            "const sql = `SELECT * FROM users WHERE name = '${req.query.name}'`;\n"
            "connection.query(sql, (err, rows) => res.json(rows));",
        ),
        _Case(
            "pg_concat",
            'await client.query("SELECT * FROM users WHERE name = \'" + req.body.name + "\'");',
        ),
        _Case(
            "sequelize_query_interpolated",
            "await sequelize.query(`SELECT * FROM users WHERE id = ${req.params.id}`);",
        ),
        _Case(
            "knex_raw_interpolated",
            "await knex.raw(`SELECT * FROM users ORDER BY ${req.query.sort}`);",
        ),
        _Case(
            "tag_called_with_parentheses",
            # The tag only parameterizes when applied as a tag.
            "await sql.query(`SELECT * FROM users WHERE name = '${req.query.name}'`);",
        ),
        _Case(
            "mysql2_execute_placeholders",
            'await pool.execute("SELECT * FROM users WHERE name = ?", [String(req.query.name)]);',
            _BOUND,
            _FP,
        ),
        _Case(
            "pg_values_array",
            'await client.query("SELECT * FROM users WHERE name = $1", [name]);',
            _BOUND,
            _FP,
        ),
        _Case(
            "sequelize_replacements",
            'await sequelize.query("SELECT * FROM users WHERE id = :id",\n'
            "  { replacements: { id: req.params.id }, type: QueryTypes.SELECT });",
            _BOUND,
            _FP,
        ),
        _Case(
            "knex_raw_bindings",
            'await knex.raw("SELECT * FROM users WHERE name = ?", [name]);',
            _BOUND,
            _FP,
        ),
        _Case(
            "parse_int_in_numeric_position",
            "const id = parseInt(req.params.id, 10);\n"
            "connection.query(`SELECT * FROM users WHERE id = ${id}`, cb);",
            _COVERED,
            _FP,
        ),
        _Case(
            "mongoose_find_is_not_relational",
            "const user = await User.findOne({ name: req.body.name });",
            _NOT_SQL,
            _FP,
        ),
        _Case(
            "mysql_placeholder_value_of_unknown_type",
            # query() expands an object value into key = value pairs; the slice
            # does not show the value is a scalar.
            'connection.query("SELECT * FROM users WHERE name = ?", [req.body.name], cb);',
            {"query_channel": _UNRESOLVED, "neutralization_coverage": _UNRESOLVED},
            _NMD,
        ),
    ),
)

_GO = _Lang(
    lang="go",
    rule_id="go/sql-injection",
    cwes=("CWE-89",),
    file="internal/store/users.go",
    dataflow=('r.URL.Query().Get("name")', "db.Query(q)"),
    guidance_markers=("fmt.Sprintf", "db.First(&u, value)", "sqlx.In"),
    cases=(
        _Case(
            "sprintf_into_query",
            "q := fmt.Sprintf(\"SELECT * FROM users WHERE name = '%s'\", name)\n"
            "rows, err := db.Query(q)",
        ),
        _Case(
            "concat_into_exec",
            'db.Exec("DELETE FROM sessions WHERE token = \'" + token + "\'")',
        ),
        _Case(
            "gorm_where_sprintf",
            "db.Where(fmt.Sprintf(\"name = '%s'\", name)).Find(&users)",
        ),
        _Case(
            "gorm_order_from_request",
            'db.Order(r.URL.Query().Get("sort")).Find(&users)',
        ),
        _Case(
            "go_quote_verb_is_not_sql_quoting",
            'q := fmt.Sprintf("SELECT * FROM users WHERE name = %q", name)\nrows, err := db.Query(q)',
        ),
        _Case(
            "placeholder_argument",
            'rows, err := db.Query("SELECT * FROM users WHERE name = $1", name)',
            _BOUND,
            _FP,
        ),
        _Case(
            "gorm_where_placeholder",
            'db.Where("name = ?", name).Find(&users)',
            _BOUND,
            _FP,
        ),
        _Case(
            "sqlx_named_query",
            'rows, err := db.NamedQuery("SELECT * FROM users WHERE name = :name", arg)',
            _BOUND,
            _FP,
        ),
        _Case(
            "atoi_in_numeric_position",
            'id, err := strconv.Atoi(r.URL.Query().Get("id"))\n'
            'if err != nil {\n\thttp.Error(w, "bad id", 400)\n\treturn\n}\n'
            'rows, err := db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = %d", id))',
            _COVERED,
            _FP,
        ),
        _Case(
            "constant_query",
            'const q = "SELECT COUNT(*) FROM users"\nrow := db.QueryRow(q)',
            _CONSTANT,
            _FP,
        ),
        _Case(
            "mongo_filter_is_not_relational",
            'coll.FindOne(ctx, bson.M{"name": name})',
            _NOT_SQL,
            _FP,
        ),
    ),
)

_CSHARP = _Lang(
    lang="csharp",
    rule_id="cs/sql-injection",
    cwes=("CWE-89",),
    file="Controllers/UsersController.cs",
    dataflow=('Request.Query["name"]', "cmd.ExecuteReader()"),
    guidance_markers=("CommandText", "FromSqlInterpolated", "AddWithValue"),
    cases=(
        _Case(
            "command_text_concat",
            'var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = \'" + name + "\'", conn);\n'
            "var reader = cmd.ExecuteReader();",
        ),
        _Case(
            "command_text_interpolated",
            "cmd.CommandText = $\"SELECT * FROM Users WHERE Name = '{name}'\";\n"
            "cmd.ExecuteNonQuery();",
        ),
        _Case(
            "dapper_interpolated_string",
            "var users = conn.Query<User>($\"SELECT * FROM Users WHERE Name = '{name}'\");",
        ),
        _Case(
            "ef_from_sql_raw_interpolated",
            "var users = ctx.Users.FromSqlRaw($\"SELECT * FROM Users WHERE Name = '{name}'\")"
            ".ToList();",
        ),
        _Case(
            "parameter_added_but_other_value_concatenated",
            'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id ORDER BY " + sort, conn);\n'
            'cmd.Parameters.AddWithValue("@id", id);',
        ),
        _Case(
            "sql_parameter",
            'var cmd = new SqlCommand("SELECT * FROM Users WHERE Name = @name", conn);\n'
            'cmd.Parameters.AddWithValue("@name", name);\nvar reader = cmd.ExecuteReader();',
            _BOUND,
            _FP,
        ),
        _Case(
            "dapper_anonymous_object",
            'var users = conn.Query<User>("SELECT * FROM Users WHERE Name = @name", new { name });',
            _BOUND,
            _FP,
        ),
        _Case(
            "ef_from_sql_interpolated",
            'var users = ctx.Users.FromSqlInterpolated($"SELECT * FROM Users WHERE Name = {name}")'
            ".ToList();",
            _BOUND,
            _FP,
        ),
        _Case(
            "linq_query",
            "var users = ctx.Users.Where(u => u.Name == name).ToList();",
            _BOUND,
            _FP,
        ),
        _Case(
            "int_parse_in_numeric_position",
            'int id = int.Parse(Request.Query["id"]);\n'
            'cmd.CommandText = "SELECT * FROM Users WHERE Id = " + id;',
            _COVERED,
            _FP,
        ),
        _Case(
            "ef_from_sql_argument_type_not_in_evidence",
            # EF Core 2.x FromSql: the overload depends on the argument's static
            # type, declared outside the slice.
            "var users = ctx.Users.FromSql(query).ToList();",
            {"query_channel": _UNRESOLVED, "neutralization_coverage": _UNRESOLVED},
            _NMD,
        ),
    ),
)

_ALL = (_JAVA, _PYTHON, _JAVASCRIPT, _GO, _CSHARP)
_IDS = [spec.lang for spec in _ALL]
_PANEL = [(spec, case) for spec in _ALL for case in spec.cases]
_PANEL_IDS = [f"{spec.lang}-{case.name}" for spec, case in _PANEL]


def _policy(spec: _Lang):
    return _REG.resolve_family(cwe_ids=list(spec.cwes), rule_id=spec.rule_id, lang=spec.lang)


def _finding(spec: _Lang, line: int = 42) -> Finding:
    return Finding(
        rule_id=spec.rule_id,
        message="m",
        file=spec.file,
        start_line=line,
        end_line=line,
        repo_name="synthetic",
        lang=spec.lang,
        cwe_ids=list(spec.cwes),
        dataflow_path=list(spec.dataflow),
    )


def _questions(spec: _Lang) -> GuidedQuestions:
    return GuidedQuestions(rule_id=spec.rule_id, short_description="d", questions=["q?"])


def _seeded(spec: _Lang, snippet: str, line: int = 42) -> EvidenceLedger:
    ledger = EvidenceLedger()
    ledger.add_local_slice(
        SourceRef("synthetic", spec.lang, spec.file, line, line + snippet.count("\n")), snippet
    )
    ledger.add_scanner_dataflow(" -> ".join(spec.dataflow))
    return ledger


def _assess(overrides=None, requests=None) -> str:
    slots = {k: dict(v) for k, v in _BASE.items()}
    for k, v in (overrides or {}).items():
        slots[k] = dict(v)
    raw = {"fact_slots": slots, "reasoning": "assessed"}
    if requests:
        raw["evidence_requests"] = requests
    return json.dumps(raw)


def _resp(content):
    choice = MagicMock()
    choice.message.content = content
    r = MagicMock()
    r.choices = [choice]
    return r


class _FakeProvider:
    def __init__(self, status, *, exhaustive=True, kind=EvidenceKind.FUNCTION):
        self._status, self._exhaustive, self._kind = status, exhaustive, kind

    def resolve_evidence(self, repo_name, lang, requests):
        out = {}
        for r in requests:
            out[r.raw_request] = EvidenceResult(
                request=r,
                status=self._status,
                prompt_content="// helper",
                scope=EvidenceScope.REPOSITORY_INDEX,
                exhaustive=self._exhaustive,
            )
        return out


def _run(mock_completion, spec: _Lang, responses, *, snippet=None, provider=None):
    mock_completion.reset_mock()
    mock_completion.side_effect = [_resp(r) for r in responses]
    finding = _finding(spec)
    snippet = snippet if snippet is not None else spec.cases[0].snippet
    controller = PolicyClosureController(
        policy=_policy(spec),
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(spec, snippet),
        max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=finding,
        context=snippet,
        questions=_questions(spec),
        func_name="handler",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=5,
        quiet=True,
    )


# ── selection ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
def test_family_selected(spec):
    policy = _policy(spec)
    assert policy is not None and policy.family == spec.family


# ── synthetic TP / FP / NMD panel ─────────────────────────────────────


@pytest.mark.parametrize(("spec", "case"), _PANEL, ids=_PANEL_IDS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_panel_case(mc, spec, case):
    v = _run(mc, spec, [_assess(overrides=case.overrides)], snippet=case.snippet)
    assert v.verdict == case.expected
    assert f"[policy:{spec.family} " in v.reasoning


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
def test_panel_has_both_classes_per_language(spec):
    expected = [case.expected for case in spec.cases]
    assert expected.count(_TP) >= 4
    assert expected.count(_FP) >= 4


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_model_verdict_string_does_not_decide(mc, spec):
    # A free-text verdict next to an assessment that leaves a decisive slot
    # unresolved changes nothing: the table entails Needs More Data.
    raw = json.loads(_assess(overrides={"neutralization_coverage": _UNRESOLVED}))
    raw["verdict"] = _TP
    v = _run(mc, spec, [json.dumps(raw)])
    assert v.verdict == _NMD
    assert "neutralization_coverage" in v.reasoning


# ── fail-closed evidence shapes ───────────────────────────────────────


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_no_visible_defense_without_a_witnessed_path_is_nmd(mc, spec):
    # "No sanitizer visible" with nothing cited is not a bypass witness.
    v = _run(
        mc,
        spec,
        [
            _assess(
                overrides={
                    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": []}
                }
            )
        ],
    )
    assert v.verdict == _NMD
    assert "neutralization_coverage" in v.reasoning


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
@pytest.mark.parametrize(
    ("slot", "value"),
    [
        ("neutralization_coverage", "ALL_REACHING_PATHS"),
        ("query_channel", "BOUND_DATA_ONLY_ALL_PATHS"),
    ],
)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_helper_non_exhaustive_all_paths_is_nmd(mc, spec, slot, value):
    # An all-paths claim supported only by a non-exhaustive retrieved helper is
    # inadmissible, so the finding stays Needs More Data.
    responses = [
        _assess(
            overrides={slot: _UNRESOLVED},
            requests=[{"kind": "function", "subject": "buildQuery", "for_slot": slot}],
        ),
        _assess(overrides={slot: {"value": value, "evidence": ["R1"]}}),
    ]
    v = _run(mc, spec, responses, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False))
    assert v.verdict == _NMD
    assert slot in v.reasoning


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_helper_exhaustive_all_paths_is_fp(mc, spec):
    # The same claim backed by an exhaustive retrieval is admissible.
    slot = "neutralization_coverage"
    responses = [
        _assess(
            overrides={slot: _UNRESOLVED},
            requests=[{"kind": "function", "subject": "toSafeId", "for_slot": slot}],
        ),
        _assess(overrides={slot: {"value": "ALL_REACHING_PATHS", "evidence": ["R1"]}}),
    ]
    v = _run(mc, spec, responses, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True))
    assert v.verdict == _FP


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_framework_evidence_does_not_admit_all_paths(mc, spec):
    slot = "neutralization_coverage"
    responses = [
        _assess(
            overrides={slot: _UNRESOLVED},
            requests=[{"kind": "framework_sanitizers", "subject": "orm", "for_slot": slot}],
        ),
        _assess(overrides={slot: {"value": "ALL_REACHING_PATHS", "evidence": ["R1"]}}),
    ]
    v = _run(mc, spec, responses, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=True))
    assert v.verdict == _NMD


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_nmd_with_reason(mc, spec):
    responses = [
        _assess(
            overrides={"flow_to_sink": _UNRESOLVED},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides={"flow_to_sink": {"value": "NO_PATH_COMPLETE", "evidence": ["R1"]}}),
    ]
    v = _run(mc, spec, responses, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert v.verdict == _NMD
    assert "flow_to_sink" in v.reasoning


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_scanner_dataflow_alone_does_not_dismiss(mc, spec):
    # A scanner path cannot prove that every path binds its values.
    v = _run(
        mc,
        spec,
        [
            _assess(
                overrides={
                    "query_channel": {"value": "BOUND_DATA_ONLY_ALL_PATHS", "evidence": ["D1"]}
                }
            )
        ],
    )
    assert v.verdict == _NMD
    assert "query_channel" in v.reasoning


# ── rendered prompt ───────────────────────────────────────────────────


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
def test_overlay_has_sql_slots_and_family_guidance(spec):
    policy = _policy(spec)
    controller = PolicyClosureController(
        policy=policy,
        provider=MagicMock(),
        finding=_finding(spec),
        model="gpt-4o",
        ledger=_seeded(spec, spec.cases[0].snippet),
    )
    instr = controller.initial_instructions()
    for slot in _BASE:
        assert slot in instr
    assert "security_effect" not in instr
    assert "[L1]" in instr and "[D1]" in instr
    for guidance in policy.assessment_guidance:
        assert guidance in instr
    for marker in spec.guidance_markers:
        assert marker in instr, marker
    assert "NOT_RELATIONAL_SQL_SINK when" in instr
    assert not _VERDICT_WORDING.search(instr)


@pytest.mark.parametrize("spec", _ALL, ids=_IDS)
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_prompt_sent_to_model_carries_guidance_and_no_verdict_command(mc, spec):
    _run(mc, spec, [_assess()])
    messages = mc.call_args_list[0].kwargs["messages"]
    user_text = "\n".join(str(m["content"]) for m in messages if m["role"] == "user")
    for marker in spec.guidance_markers:
        assert marker in user_text, marker
    assert "Evidence-closure assessment" in user_text
    for guidance in _policy(spec).assessment_guidance:
        assert not _VERDICT_WORDING.search(guidance)
