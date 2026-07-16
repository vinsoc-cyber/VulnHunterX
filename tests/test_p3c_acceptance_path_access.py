# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic #120 acceptance panel: PHP path-access via cross-family handoff.

The DVWA cases #120 cites (a tainted-filename tagged SSRF / an eval whose
argument is file contents reached via a path) are LOCATED into the path_access
family by handoff and judged by EVIDENCE, not the rule's named CWE and not prose:

  view_help.php LFI (attacker path -> file_get_contents -> eval)  -> True Positive
  a confined / allowlisted path                                   -> False Positive
  a rule match with no real consequence                           -> False Positive
  operator-only (not attacker-controlled) input                   -> False Positive
  a non-path sink (a real command exec)                           -> family_not_applicable

Drives the real closure controller with a scripted (mocked) model, so every case
is reproducible without an LLM.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from vuln_hunter_x.context.evidence import SourceRef
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.verification.policy.closure import PolicyClosureController
from vuln_hunter_x.verification.policy.handoff import classify_applicability
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import load_policy_registry

_TAINTED_FILENAME = "php.lang.security.injection.tainted-filename.tainted-filename"
_EVAL_USE = "php.lang.security.eval-use.eval-use"
_REG = load_policy_registry()
_POLICY = _REG.resolve_handoff(cwe_ids=["CWE-918"], rule_id=_TAINTED_FILENAME, lang="php")

# A fully-resolved True-Positive assessment (attacker path escapes the base,
# unguarded, with a real consequence). Individual cases flip one slot.
_TP = {
    "sink_binding": {"value": "QUALIFYING_PATH_ACCESS_SINK", "evidence": ["L1"]},
    "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
    "flow_to_path": {"value": "REACHES", "evidence": ["D1"]},
    "path_escape": {"value": "ESCAPE_PATH_FOUND", "evidence": ["L1"]},
    "defense_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
    "security_effect": {"value": "SECURITY_RELEVANT_EFFECT", "evidence": ["L1"]},
}


def _finding(rule=_TAINTED_FILENAME, line=20):
    return Finding(
        rule_id=rule, message="m", file="vulnerabilities/view_help.php",
        start_line=line, end_line=line, repo_name="dvwa", lang="php",
        cwe_ids=["CWE-918"], dataflow_path=["$_GET['id']", "file_get_contents"],
    )


def _q():
    return GuidedQuestions(rule_id=_TAINTED_FILENAME, short_description="d", questions=["q?"])


def _seeded():
    led = EvidenceLedger()
    led.add_local_slice(
        SourceRef("dvwa", "php", "vulnerabilities/view_help.php", 18, 24),
        'eval("?>" . file_get_contents(DVWA_WEB_PAGE_TO_ROOT . "vulnerabilities/{$id}/help/help.php"));',
    )
    led.add_scanner_dataflow("$_GET['id'] -> file_get_contents")
    return led


def _assess(**overrides):
    slots = {k: dict(v) for k, v in _TP.items()}
    for k, v in overrides.items():
        slots[k] = v
    return json.dumps({"fact_slots": slots, "reasoning": "assessed"})


def _resp(content):
    choice = MagicMock()
    choice.message.content = content
    r = MagicMock()
    r.choices = [choice]
    return r


def _run(mc, responses):
    mc.side_effect = [_resp(r) for r in responses]
    controller = PolicyClosureController(
        policy=_POLICY, provider=MagicMock(), finding=_finding(),
        model="gpt-4o", ledger=_seeded(),
    )
    client = LLMClient(provider="openai", model="gpt-4o")
    return client.analyze(
        finding=_finding(), context="file_get_contents(... {$id} ...)", questions=_q(),
        func_name="h", force_decision=False, decision_strategy=controller,
        max_iterations=5, quiet=True,
    )


def test_path_access_family_loads_and_is_handoff_capable():
    assert "path_access" in _REG.families
    assert _POLICY is not None and _POLICY.family == "path_access"
    assert _POLICY.applicability is not None


def test_dvwa_tainted_filename_and_eval_use_route_as_handoff():
    for rule in (_TAINTED_FILENAME, _EVAL_USE):
        p = _REG.resolve_handoff(cwe_ids=["CWE-918"], rule_id=rule, lang="php")
        assert p is not None and p.family == "path_access"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_view_help_lfi_entails_true_positive(mc):
    v = _run(mc, [_assess()])
    assert v.verdict == "True Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_confined_path_is_false_positive(mc):
    v = _run(mc, [_assess(path_escape={"value": "CONFINED_ALL_PATHS", "evidence": ["L1"]})])
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_no_security_effect_is_false_positive(mc):
    v = _run(mc, [_assess(security_effect={"value": "NO_SECURITY_EFFECT", "evidence": ["L1"]})])
    assert v.verdict == "False Positive"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_operator_only_input_is_false_positive(mc):
    v = _run(mc, [_assess(attacker_control={"value": "REFUTED", "evidence": ["L1"]})])
    assert v.verdict == "False Positive"


def test_non_path_sink_is_family_not_applicable():
    # A real command-exec eval-use is NOT a path sink -> not-applicable (never a
    # dismissal): the combiner hands it back to the base route, which keeps it TP.
    assert classify_applicability(_POLICY, {"sink_binding": "NOT_PATH_ACCESS_SINK"}) == "not_applicable"
