# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic DVWA OS command-injection (CWE-78) acceptance panel — the ship
criterion for the command-injection family.

Drives the full policy path — analyze() + a real closure controller — with a
scripted (mocked) model, so every case is reproducible without an LLM. The
verdict is entailed by the fact table + admissibility, NOT by the model string.

The 26 real DVWA exec candidates (20 TP / 6 NMD, verified against
benchmark/test_case/dvwa/ground_truth.json) span three rule aliases that DISAGREE
on CWE (injection.tainted-exec=CWE-78, exec-use and tainted-exec=CWE-94) yet all
flag the same shell sinks; the family owns all three by rule alias and the panel
drives every one (policy findings are processed one-to-one, so a per-site panel
would not exercise alias selection). The 6 NMD are DVWA's `impossible.php`: its
per-octet is_numeric() blocks any shell command-control sequence, but PHP accepts
signed numeric strings with whitespace (is_numeric('-4 ') is true), so a '-4'
token can still reach ping as an OPTION. The verifier cannot prove option-safety from the
local slice (that needs ping's option semantics, which V1 defers), so it honestly
abstains (Needs More Data) rather than falsely dismiss. A genuinely strict guard
(a canonical IPv4 regex) is covered as a synthetic FP.

Source-derived synthetic fixtures cover branches the scanner does not emit: an
argv-isolated launch behind a strict allowlist (FP), a strict allowlist on a
shell path (FP), a direct argv OPTION the attacker controls (argument injection
is deferred -> NMD, never a false dismissal), an escapeshellcmd-guarded shell
path (NMD -- escaping metacharacters does not cover argument injection), a mixed
guarded/unguarded branch (TP), a shadowed user-defined exec (NOT a sink -> FP),
and a multi-CWE finding that two families claim (fails closed).

Scripted tests prove policy/control correctness, NOT model semantic quality
(that is measured on real models later).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from vuln_hunter_x.context.evidence import SourceRef
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.questions.loader import QuestionsLoader
from vuln_hunter_x.sarif.parser import parse_sarif_file
from vuln_hunter_x.verification.policy.closure import PolicyClosureController
from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import (
    PolicyOverlapError,
    load_policy_registry,
)
from vuln_hunter_x.verification.policy.models import FP, NMD, TP

_REG = load_policy_registry()

# The three PHP exec rule ids and the CWE each SARIF result carries.
_INJ = ("php.lang.security.injection.tainted-exec.tainted-exec", "CWE-78")
_USE = ("php.lang.security.exec-use.exec-use", "CWE-94")
_TAINT = ("php.lang.security.tainted-exec.tainted-exec", "CWE-94")

_POLICY = _REG.resolve_family(cwe_ids=["CWE-78"], rule_id=_INJ[0], lang="php")

# A fully-resolved True-Positive assessment (attacker value reaches a shell
# command string with no effective neutralizer). Cases flip one slot.
_BASE = {
    "sink_binding": {"value": "QUALIFYING_OS_COMMAND_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
    "command_channel": {"value": "SHELL_COMMAND_TEXT_PATH_FOUND", "evidence": ["L1"]},
    "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
}

# The 20 real DVWA TP candidates: (rule, cwe, file, line). All shell string,
# no guard (low) or a bypassable blacklist (medium/high) or none (HealthController).
_TP = []
for _rule, _cwe in (_INJ, _USE):
    for _f, _l in [
        ("vulnerabilities/exec/source/low.php", 10),
        ("vulnerabilities/exec/source/low.php", 14),
        ("vulnerabilities/exec/source/medium.php", 19),
        ("vulnerabilities/exec/source/medium.php", 23),
        ("vulnerabilities/exec/source/high.php", 26),
        ("vulnerabilities/exec/source/high.php", 30),
        ("vulnerabilities/api/src/HealthController.php", 88),
    ]:
        _TP.append((_rule, _cwe, _f, _l))
for _f, _l in [  # bare tainted-exec did not fire on HealthController
    ("vulnerabilities/exec/source/low.php", 10),
    ("vulnerabilities/exec/source/low.php", 14),
    ("vulnerabilities/exec/source/medium.php", 19),
    ("vulnerabilities/exec/source/medium.php", 23),
    ("vulnerabilities/exec/source/high.php", 26),
    ("vulnerabilities/exec/source/high.php", 30),
]:
    _TP.append((_TAINT[0], _TAINT[1], _f, _l))

# The 6 real DVWA impossible.php candidates x each rule. Per-octet is_numeric()
# blocks any shell command-control sequence, but PHP 8 accepts signed numeric strings with
# leading/trailing whitespace (is_numeric('-4 ') is true), so an octet can carry a
# '-4' token that ping parses as an OPTION. Proving that injectable option is
# harmless needs ping's option semantics (deferred in V1), so coverage cannot be
# asserted ALL_REACHING_PATHS -> it stays unresolved -> honest Needs More Data,
# never a false dismissal.
_NMD = [
    (r, c, "vulnerabilities/exec/source/impossible.php", line)
    for (r, c) in (_INJ, _USE, _TAINT)
    for line in (22, 26)
]
_NMD_OVERRIDE = {"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}}


def _finding(rule, cwe, file, line):
    return Finding(
        rule_id=rule,
        message="m",
        file=file,
        start_line=line,
        end_line=line,
        repo_name="dvwa",
        lang="php",
        cwe_ids=[cwe],
        dataflow_path=["$_REQUEST['ip']", "shell_exec"],
    )


def _q():
    return GuidedQuestions(rule_id="cmd", short_description="d", questions=["q?"])


def _seeded(file, line):
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("dvwa", "php", file, line, line + 1),
        "$cmd = shell_exec('ping  -c 4 ' . $target);",
    )
    led.add_scanner_dataflow("$_REQUEST['ip'] -> shell_exec")
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


def _run(mc, responses, finding, *, provider=None, max_iterations=5):
    mc.side_effect = [_resp(r) for r in responses]
    policy = _REG.resolve_family(
        cwe_ids=finding.cwe_ids, rule_id=finding.rule_id, lang=finding.lang
    )
    controller = PolicyClosureController(
        policy=policy,
        provider=provider or MagicMock(),
        finding=finding,
        model="gpt-4o",
        ledger=_seeded(finding.file, finding.start_line),
        max_retrieval_rounds=2,
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=finding,
        context="shell_exec(...)",
        questions=_q(),
        func_name="h",
        force_decision=False,
        decision_strategy=controller,
        max_iterations=max_iterations,
        quiet=True,
    )


# --- selection --------------------------------------------------------------
def test_family_selected_for_all_three_aliases():
    assert _POLICY is not None and _POLICY.family == "command_injection"
    for rule, cwe in (_INJ, _USE, _TAINT):
        p = _REG.resolve_family(cwe_ids=[cwe], rule_id=rule, lang="php")
        assert p is not None and p.family == "command_injection", (rule, cwe)


def test_alias_rule_language_gated_to_php():
    # The family is php-scoped: even one of its own exec rule ids under another
    # language is not claimed (the language gate precedes alias matching).
    assert (
        _REG.resolve_family(cwe_ids=[], rule_id="php.lang.security.exec-use.exec-use", lang="go")
        is None
    )


def test_cwe78_eval_use_still_routes_to_path_access_handoff_not_here():
    # eval-use is tagged CWE-78 but is a code-injection rule that path_access hands
    # off; command_injection must NOT claim it as a primary family. This is why the
    # family carries NO CWE selector — selection is by the three exec rule aliases.
    assert (
        _REG.resolve_family(
            cwe_ids=["CWE-78"], rule_id="php.lang.security.eval-use.eval-use", lang="php"
        )
        is None
    )


_DVWA_SARIF = (
    Path(__file__).resolve().parents[1] / "benchmark/test_case/dvwa/scanner_result/dvwa.sarif"
)


def test_real_sarif_selection_is_exactly_the_exec_rules():
    # Parse the real DVWA SARIF and check what command_injection actually claims.
    # eval-use is tagged CWE-78 (and a GitHub-Actions YAML rule is too), so a
    # CWE-78 selector would over-claim; alias-only selection must own ONLY the
    # three exec rules. This regression fails if a CWE selector is reintroduced.
    findings = parse_sarif_file(_DVWA_SARIF, "php", "dvwa")
    claimed, overlaps = [], []
    for f in findings:
        try:
            p = _REG.resolve_family(cwe_ids=f.cwe_ids, rule_id=f.rule_id, lang=f.lang)
        except PolicyOverlapError:
            overlaps.append(f.rule_id)
            continue
        if p is not None and p.family == "command_injection":
            claimed.append(f.rule_id)
    assert set(claimed) == {_INJ[0], _USE[0], _TAINT[0]}, sorted(set(claimed))
    assert "php.lang.security.eval-use.eval-use" not in claimed
    assert overlaps == [], overlaps


# --- the 26-finding DVWA panel ---------------------------------------------
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_dvwa_exec_panel_is_20tp_6nmd(mc):
    verdicts = {}
    for rule, cwe, file, line in _TP:
        v = _run(mc, [_assess()], _finding(rule, cwe, file, line))
        verdicts[(rule, file, line)] = v.verdict
    for rule, cwe, file, line in _NMD:
        v = _run(mc, [_assess(overrides=_NMD_OVERRIDE)], _finding(rule, cwe, file, line))
        verdicts[(rule, file, line)] = v.verdict
    tp = sum(1 for x in verdicts.values() if x == "True Positive")
    nmd = sum(1 for x in verdicts.values() if x == "Needs More Data")
    assert (tp, nmd) == (20, 6), verdicts
    for rule, _cwe, file, line in _TP:
        assert verdicts[(rule, file, line)] == "True Positive", (rule, file, line)
    for rule, _cwe, file, line in _NMD:
        assert verdicts[(rule, file, line)] == "Needs More Data", (rule, file, line)


# --- synthetic fixtures (branches the scanner does not emit) -----------------
@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_strict_allowlist_argv_isolated_is_fp(mc):
    # pcntl_exec('/bin/ping', [$ip]) where $ip passed a strict canonical IPv4
    # regex (^\d{1,3}(\.\d{1,3}){3}$, range-checked) — NOT is_numeric, which would
    # admit signs/whitespace: fixed exe, no shell, and the operand is bounded data
    # that cannot begin with '-' or otherwise enter option parsing.
    v = _run(
        mc,
        [
            _assess(
                overrides={
                    "command_channel": {
                        "value": "FIXED_EXEC_DATA_OPERANDS_ONLY_ALL_PATHS",
                        "evidence": ["L1"],
                    }
                }
            )
        ],
        _finding(*_INJ, "vulnerabilities/exec/source/argv.php", 12),
    )
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_complete_allowlist_on_shell_path_is_fp(mc):
    # A GENUINELY strict guard on the shell path — a canonical IPv4 regex + range
    # check (NOT is_numeric), so no reaching value can carry a shell metacharacter
    # OR a leading-dash option -> every path covered -> False Positive.
    v = _run(
        mc,
        [
            _assess(
                overrides={
                    "neutralization_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["L1"]}
                }
            )
        ],
        _finding(*_INJ, "vulnerabilities/exec/source/allow.php", 9),
    )
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_direct_argv_option_control_is_nmd_not_fp(mc):
    # Attacker controls a FLAG to an otherwise-isolated argv command (argument
    # injection). The channel cannot be proven a fixed-data operand; and a model
    # that treats "no shell" as vacuous all-path coverage (ALL_REACHING_PATHS)
    # must NOT manufacture a dismissal — coverage dismisses only a proven shell
    # path -> honest Needs More Data, never a false dismissal.
    v = _run(
        mc,
        [
            _assess(
                overrides={
                    "command_channel": {"value": "UNRESOLVED", "evidence": []},
                    "neutralization_coverage": {"value": "ALL_REACHING_PATHS", "evidence": ["L1"]},
                }
            )
        ],
        _finding(*_INJ, "vulnerabilities/exec/source/flag.php", 7),
    )
    assert v.verdict == "Needs More Data"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_escapeshellcmd_guarded_shell_path_is_nmd(mc):
    # escapeshellcmd escapes metacharacters but still permits argument injection,
    # so it is neither a witnessed bypass nor proven all-path safe.
    v = _run(
        mc,
        [_assess(overrides={"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}})],
        _finding(*_INJ, "vulnerabilities/exec/source/esccmd.php", 8),
    )
    assert v.verdict == "Needs More Data"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_escaped_shell_arg_dangerous_option_is_nmd(mc):
    # system('tar ' . escapeshellarg($arg)): the shell boundary is escaped
    # (still SHELL_COMMAND_TEXT_PATH_FOUND) but $arg can act as a dangerous tar
    # option (argument injection). escapeshellarg alone does not prove all-path
    # coverage, so neutralization stays unresolved -> Needs More Data, not a
    # false FP — argument injection on a shell path is not vacuously dismissed.
    v = _run(
        mc,
        [_assess(overrides={"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}})],
        _finding(*_INJ, "vulnerabilities/exec/source/tar.php", 5),
    )
    assert v.verdict == "Needs More Data"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_escaped_interpreter_input_is_nmd(mc):
    # system('php ' . escapeshellarg($path)): the path is escaped and even
    # non-option-shaped, but the attacker controls INTERPRETER INPUT (the script
    # php runs) -> arbitrary code execution. escapeshellarg proves shell-argument
    # quoting only, not program-level safety, so coverage stays unresolved ->
    # Needs More Data (V1 defers argument/interpreter injection), not a false FP.
    v = _run(
        mc,
        [_assess(overrides={"neutralization_coverage": {"value": "UNRESOLVED", "evidence": []}})],
        _finding(*_INJ, "vulnerabilities/exec/source/php_interp.php", 9),
    )
    assert v.verdict == "Needs More Data"


def test_expect_popen_is_a_named_qualifying_sink():
    # expect_popen is a selected CWE-78 sink (it runs a command via the Bourne
    # shell); the fact-gathering guidance must name it so a real expect_popen
    # finding is not misjudged NOT_OS_COMMAND_SINK.
    assert "expect_popen" in " ".join(_POLICY.assessment_guidance)


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_expect_popen_tainted_shell_call_is_tp(mc):
    # A tainted expect_popen('...' . $target) is a qualifying shell sink reached
    # by attacker input with no neutralizer -> True Positive.
    v = _run(mc, [_assess()], _finding(*_INJ, "vulnerabilities/exec/source/expect.php", 6))
    assert v.verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_mixed_guarded_and_unguarded_branch_is_tp(mc):
    # One reaching path is allowlisted, another concatenates raw input -> the
    # uncovered branch is a witnessed bypass.
    v = _run(mc, [_assess()], _finding(*_INJ, "vulnerabilities/exec/source/mixed.php", 15))
    assert v.verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_not_os_command_sink_is_fp(mc):
    # exec-use is an audit rule; a shadowed/namespaced user-defined exec() is not
    # a real OS-command sink.
    v = _run(
        mc,
        [_assess(overrides={"sink_binding": {"value": "NOT_OS_COMMAND_SINK", "evidence": ["L1"]}})],
        _finding(*_USE, "app/helpers.php", 40),
    )
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_operator_only_constant_command_is_fp(mc):
    # exec-use fires on a fixed constant command with no request-derived value.
    v = _run(
        mc,
        [_assess(overrides={"attacker_control": {"value": "REFUTED", "evidence": ["L1"]}})],
        _finding(*_USE, "app/cron.php", 12),
    )
    assert v.verdict == "False Positive"


# --- multi-CWE overlap fails closed ----------------------------------------
@pytest.mark.parametrize("other_cwe", ["CWE-89", "CWE-22", "CWE-117"])
def test_multi_cwe_finding_two_families_fails_closed(other_cwe):
    # A PHP finding carrying CWE-78 plus another family's CWE (sql=89, path=22,
    # log=117) matches two policies; the registry fails closed rather than
    # silently picking one.
    with pytest.raises(PolicyOverlapError):
        _REG.resolve_family(
            cwe_ids=["CWE-78", other_cwe],
            rule_id="php.lang.security.injection.tainted-exec.tainted-exec",
            lang="php",
        )


# --- direct entailment truth-table checks ----------------------------------
def test_entail_tp_conjunction():
    facts = {
        "sink_binding": "QUALIFYING_OS_COMMAND_SINK",
        "attacker_control": "PROVEN",
        "flow_to_sink": "REACHES",
        "command_channel": "SHELL_COMMAND_TEXT_PATH_FOUND",
        "neutralization_coverage": "BYPASS_PATH_FOUND",
    }
    assert entail(_POLICY, facts).verdict == TP


def test_entail_fixed_exec_data_operands_is_fp():
    facts = {
        "sink_binding": "QUALIFYING_OS_COMMAND_SINK",
        "attacker_control": "PROVEN",
        "flow_to_sink": "REACHES",
        "command_channel": "FIXED_EXEC_DATA_OPERANDS_ONLY_ALL_PATHS",
        "neutralization_coverage": "BYPASS_PATH_FOUND",
    }
    assert entail(_POLICY, facts).verdict == FP


def test_entail_fp_dominates_when_shell_text_but_all_paths_covered():
    facts = {
        "sink_binding": "QUALIFYING_OS_COMMAND_SINK",
        "attacker_control": "PROVEN",
        "flow_to_sink": "REACHES",
        "command_channel": "SHELL_COMMAND_TEXT_PATH_FOUND",
        "neutralization_coverage": "ALL_REACHING_PATHS",
    }
    assert entail(_POLICY, facts).verdict == FP


def test_entail_missing_command_channel_is_nmd():
    facts = {
        "sink_binding": "QUALIFYING_OS_COMMAND_SINK",
        "attacker_control": "PROVEN",
        "flow_to_sink": "REACHES",
        "neutralization_coverage": "BYPASS_PATH_FOUND",
    }
    d = entail(_POLICY, facts)
    assert d.verdict == NMD and "command_channel" in (d.terminal_reason or "")


def test_entail_coverage_without_shell_channel_does_not_dismiss():
    # All-paths coverage is an FP only conjoined with a proven shell channel;
    # asserted with the channel unresolved (argument injection) it must NOT
    # manufacture a False Positive.
    facts = {
        "sink_binding": "QUALIFYING_OS_COMMAND_SINK",
        "attacker_control": "PROVEN",
        "flow_to_sink": "REACHES",
        "neutralization_coverage": "ALL_REACHING_PATHS",
    }
    assert entail(_POLICY, facts).verdict == NMD


# --- overlay + question alignment ------------------------------------------
def test_overlay_has_command_slots_not_security_effect():
    controller = PolicyClosureController(
        policy=_POLICY,
        provider=MagicMock(),
        finding=_finding(*_INJ, "vulnerabilities/exec/source/low.php", 10),
        model="gpt-4o",
        ledger=_seeded("vulnerabilities/exec/source/low.php", 10),
    )
    instr = controller.initial_instructions()
    assert "command_channel" in instr
    assert "neutralization_coverage" in instr
    assert "security_effect" not in instr


_PROMPTS_DIR = Path(__file__).resolve().parents[1] / "config" / "prompts"
_CATEGORIES_YAML = Path(__file__).resolve().parents[1] / "config" / "rule_categories.yaml"


def test_cwe94_exec_aliases_get_command_injection_questions():
    # The native policy path fetches the reported rule's guided questions; the two
    # CWE-94 exec aliases must resolve to command-injection questions, not the
    # CWE-94 code-injection fallback, so evidence questions match the family.
    # Built with the CWE map that WOULD route CWE-94 to code-injection, so this
    # proves the exact rule-id entries win.
    ql = QuestionsLoader(_PROMPTS_DIR)
    ql.set_cwe_question_map(
        yaml.safe_load(_CATEGORIES_YAML.read_text()).get("cwe_question_map", {})
    )
    for rule, cwe in (_USE, _TAINT, _INJ):
        q = ql.get_questions(rule, cwe_ids=[cwe], lang="php")
        blob = (q.short_description + " " + " ".join(q.questions)).lower()
        assert "shell" in blob or "command" in blob, (rule, cwe, q.short_description)
        assert "eval(" not in blob, (rule, cwe)
