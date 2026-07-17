# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic DVWA SQL-injection (CWE-89) acceptance panel — the ship
criterion for the relational-SQLi family.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

The 14 real DVWA `tainted-sql-string` candidates (10 TP / 4 FP, verified against
benchmark/test_case/dvwa/ground_truth.json) are driven with facts derived from
the real source. The 4 FPs (bac 22/35, 21/28) interpolate an operand fully
covered by a `^\\d+$` digit allowlist / intval on every reaching path
(neutralization ALL_REACHING_PATHS); the BAC positives (79/71) interpolate a raw
X-Forwarded-For header while the ID operands are constrained — the family must
enumerate EVERY interpoland, not just the scanner-tracked one. Two source-derived
synthetic fixtures cover the branches the scanner does not emit (escaping inert
in a numeric context -> TP; a bound parameter -> FP).

Scripted tests prove policy/control correctness, NOT model semantic quality
(that is measured on real models at P6).
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

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

_RULE = "php.lang.security.injection.tainted-sql-string.tainted-sql-string"
_REG = load_policy_registry()
_POLICY = _REG.resolve_family(cwe_ids=["CWE-89"], rule_id=_RULE, lang="php")

# A fully-resolved True-Positive assessment (attacker value reaches the SQL text
# unguarded). Individual cases flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_RELATIONAL_SQL_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "query_channel": {"value": "SQL_TEXT_PATH_FOUND", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}

# The 14 real DVWA SARIF candidates for the tainted-sql-string rule.
_TP_SITES = [
    ("vulnerabilities/sqli/source/low.php", 10),        # $_REQUEST['id'] -> '$id' quoted concat
    ("vulnerabilities/sqli/source/low.php", 31),
    ("vulnerabilities/sqli_blind/source/low.php", 11),
    ("vulnerabilities/sqli_blind/source/low.php", 32),
    ("vulnerabilities/sqli_blind/source/high.php", 11),
    ("vulnerabilities/sqli_blind/source/high.php", 33),
    ("vulnerabilities/sqli_blind/source/medium.php", 34),  # SQLite branch unguarded; MySQL-branch escape doesn't cover it
    ("vulnerabilities/brute/source/low.php", 12),
    ("vulnerabilities/bac/source/low.php", 79),         # raw $_SERVER['HTTP_X_FORWARDED_FOR'] operand; ID operands are intval'd
    ("vulnerabilities/bac/source/medium.php", 71),      # raw X-Forwarded-For header operand
]
_FP_SITES = [
    ("vulnerabilities/bac/source/low.php", 22),         # $id = intval(...) behind preg_match('/^\d+$/'), numeric context
    ("vulnerabilities/bac/source/low.php", 35),
    ("vulnerabilities/bac/source/medium.php", 21),      # $id gated by preg_match('/^\d+$/') digit allowlist
    ("vulnerabilities/bac/source/medium.php", 28),
]
# The FP deciding fact: the sole attacker operand is covered by a digit allowlist
# / integer coercion on every reaching path.
_FP_OVERRIDE = {"neutralization_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["L1"]}}


def _finding(file="vulnerabilities/sqli/source/low.php", line=10):
    return Finding(
        rule_id=_RULE, message="m", file=file, start_line=line, end_line=line,
        repo_name="dvwa", lang="php", cwe_ids=["CWE-89"],
        dataflow_path=["$_REQUEST['id']", "mysqli_query"],
    )


def _q():
    return GuidedQuestions(rule_id=_RULE, short_description="d", questions=["q?"])


def _seeded(file="vulnerabilities/sqli/source/low.php", line=10):
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("dvwa", "php", file, line, line + 2),
        '$query = "SELECT first_name, last_name FROM users WHERE user_id = \'$id\';";',
    )
    led.add_scanner_dataflow("$_REQUEST['id'] -> mysqli_query")
    return led


def _assess(overrides=None, requests=None):
    slots = {k: dict(v) for k, v in _BASE.items()}
    for k, v in (overrides or {}).items():
        slots[k] = v
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
                request=r, status=self._status, prompt_content="// helper",
                scope=EvidenceScope.REPOSITORY_INDEX, exhaustive=self._exhaustive,
            )
        return out


def _run(mock_completion, responses, *, finding=None, provider=None, max_iterations=5):
    mock_completion.side_effect = [_resp(r) for r in responses]
    finding = finding or _finding()
    controller = PolicyClosureController(
        policy=_POLICY, provider=provider or MagicMock(), finding=finding,
        model="gpt-4o", ledger=_seeded(finding.file, finding.start_line), max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=finding, context="mysqli_query(...)", questions=_q(), func_name="h",
        force_decision=False, decision_strategy=controller,
        max_iterations=max_iterations, quiet=True,
    )


def test_family_selected():
    assert _POLICY is not None and _POLICY.family == "sql_injection"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_dvwa_tainted_sql_string_panel_is_10tp_4fp(mc):
    verdicts = {}
    for file, line in _TP_SITES:
        v = _run(mc, [_assess()], finding=_finding(file, line))
        verdicts[(file, line)] = v.verdict
    for file, line in _FP_SITES:
        v = _run(mc, [_assess(overrides=_FP_OVERRIDE)], finding=_finding(file, line))
        verdicts[(file, line)] = v.verdict
    tp = sum(1 for x in verdicts.values() if x == "True Positive")
    fp = sum(1 for x in verdicts.values() if x == "False Positive")
    assert (tp, fp) == (10, 4), verdicts
    # every real TP is confirmed and every real FP is dismissed by evidence
    for site in _TP_SITES:
        assert verdicts[site] == "True Positive", site
    for site in _FP_SITES:
        assert verdicts[site] == "False Positive", site


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_synthetic_escape_in_numeric_context_is_tp(mc):
    # sqli/source/medium.php shape: mysqli_real_escape_string applied, but the
    # value sits in an UNQUOTED numeric context (WHERE user_id = $id) where
    # escaping neutralizes nothing -> still a witnessed bypass. Not a scanner
    # candidate (the rule treats escaping as a sanitizer), so validated here.
    v = _run(mc, [_assess()], finding=_finding("vulnerabilities/sqli/source/medium.php", 11))
    assert v.verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_synthetic_prepared_bound_param_is_fp(mc):
    # sqli/source/impossible.php shape: is_numeric + intval + PDO prepare(':id')
    # + bindParam -> the value never enters the SQL grammar as text.
    v = _run(
        mc,
        [_assess(overrides={
            "query_channel": {"value": "BOUND_DATA_ONLY_ALL_PATHS", "evidence": ["L1"]}
        })],
        finding=_finding("vulnerabilities/sqli/source/impossible.php", 15),
    )
    assert v.verdict == "False Positive"


def test_nodegoat_js_sql_injection_stays_out():
    # NodeGoat's js/sql-injection is MongoDB/NoSQL query-object injection — a
    # separate future family, NOT this PHP relational-SQL family.
    assert _REG.resolve_family(
        cwe_ids=["CWE-89"], rule_id="js/sql-injection", lang="javascript"
    ) is None


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_offslice_helper_non_exhaustive_all_paths_is_nmd(mc):
    # An ALL_REACHING_PATHS (fully-neutralized) claim supported only by a
    # non-exhaustive retrieved helper is inadmissible -> stays Needs More Data.
    responses = [
        _assess(
            overrides={"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "sanitize_id",
                       "for_slot": "neutralization_coverage"}],
        ),
        _assess(overrides={
            "neutralization_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["R1"]}
        }),
    ]
    v = _run(mc, responses, provider=_FakeProvider(EvidenceStatus.FOUND, exhaustive=False))
    assert v.verdict == "Needs More Data"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_incomplete_index_is_nmd_with_reason(mc):
    responses = [
        _assess(
            overrides={"flow_to_sink": {"value": "UNRESOLVED", "evidence": []}},
            requests=[{"kind": "function", "subject": "handler", "for_slot": "flow_to_sink"}],
        ),
        _assess(overrides={"flow_to_sink": {"value": "REACHES", "evidence": ["R1"]}}),
    ]
    v = _run(mc, responses, provider=_FakeProvider(EvidenceStatus.INCOMPLETE_INDEX))
    assert v.verdict == "Needs More Data"
    assert "flow_to_sink" in v.reasoning


def test_overlay_has_sql_slots_and_guidance():
    controller = PolicyClosureController(
        policy=_POLICY, provider=MagicMock(), finding=_finding(),
        model="gpt-4o", ledger=_seeded(),
    )
    instr = controller.initial_instructions()
    assert "query_channel" in instr
    assert "neutralization_coverage" in instr
    assert "security_effect" not in instr  # deliberately dropped for SQL
    assert "[L1]" in instr and "[D1]" in instr
