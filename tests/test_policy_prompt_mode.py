# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Policy prompt mode (P2c S3).

On the policy path the assembled prompt must carry EXACTLY ONE response
contract — the fact-slot assessment — and no verdict command. Otherwise a real
model can obey the (higher-priority) verdict schema and omit fact_slots. Legacy
assembly (no decision strategy) stays byte-identical, so the verdict schema and
the "provide your final verdict" framing are still present there.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from vuln_hunter_x.context.evidence import SourceRef
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.llm.prompts import PromptBuilder
from vuln_hunter_x.verification.policy.closure import PolicyClosureController
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import load_policy_registry

_VERDICT_CMD = "provide your final verdict"
_RESPONSE_FMT = "Response format (strict JSON):"
_RULE_SCOPE = "RULE-SCOPE DISCIPLINE:"
_LFI_EXEMPLAR = "LFI → RCE"  # the tainted-filename/eval verdict-coaching exemplar


def test_legacy_system_prompt_unchanged():
    pb = PromptBuilder()
    assert _RESPONSE_FMT in pb.get_system_prompt(tool_name="CodeQL", lang="python")
    assert _RESPONSE_FMT in pb.get_system_prompt(
        tool_name="CodeQL", lang="python", assessment_mode=False
    )


def test_assessment_mode_system_prompt_drops_verdict_schema():
    sp = PromptBuilder().get_system_prompt(
        tool_name="CodeQL", lang="python", assessment_mode=True
    )
    assert _RESPONSE_FMT not in sp
    assert '"verdict":' not in sp


def test_legacy_system_prompt_keeps_rule_scope_block():
    # Legacy verdict mode is byte-identical: the rule-scope coaching stays.
    pb = PromptBuilder()
    sp = pb.get_system_prompt(tool_name="CodeQL", lang="python", assessment_mode=False)
    assert _RULE_SCOPE in sp
    assert _LFI_EXEMPLAR in sp


def test_assessment_mode_drops_rule_scope_verdict_coaching():
    # On the evidence-closure path the fact-slot policy entails the verdict, so
    # the rule-scope verdict-coaching block (incl. the LFI/eval exemplar) must
    # not remain to bias fact assessment (#120 structural replacement).
    sp = PromptBuilder().get_system_prompt(
        tool_name="CodeQL", lang="python", assessment_mode=True
    )
    assert _RULE_SCOPE not in sp
    assert _LFI_EXEMPLAR not in sp
    assert "IMPORTANT CONSTRAINTS:" in sp  # the rest of the guidance is retained


def test_assessment_mode_user_prompt_drops_verdict_command():
    pb = PromptBuilder()
    f = _finding()
    legacy = pb.build_user_prompt(f, "console.log(x)", _q(), "fn")
    assert _VERDICT_CMD in legacy
    assessed = pb.build_user_prompt(f, "console.log(x)", _q(), "fn", assessment_mode=True)
    assert _VERDICT_CMD not in assessed


def _finding():
    return Finding(
        rule_id="js/log-injection", message="m", file="f.js", start_line=1, end_line=1,
        repo_name="nodegoat", lang="javascript", cwe_ids=["CWE-117"], dataflow_path=["a", "b"],
    )


def _q():
    return GuidedQuestions(rule_id="js/log-injection", short_description="d", questions=["q?"])


def _first_turn_messages():
    policy = load_policy_registry().resolve_family(cwe_ids=["CWE-117"], rule_id="js/log-injection")
    led = EvidenceLedger()
    led.add_local_slice(SourceRef("nodegoat", "javascript", "f.js", 1, 3), "console.log(x)")
    led.add_scanner_dataflow("a -> b")
    ctrl = PolicyClosureController(
        policy=policy, provider=MagicMock(), finding=_finding(), model="gpt-4o", ledger=led
    )
    with patch("vuln_hunter_x.llm.client.litellm.completion") as mc:
        choice = MagicMock()
        choice.message.content = '{"fact_slots": {}, "reasoning": "x"}'
        resp = MagicMock()
        resp.choices = [choice]
        mc.return_value = resp
        LLMClient(provider="openai", model="gpt-4o").analyze(
            finding=_finding(), context="console.log(x)", questions=_q(), func_name="f",
            force_decision=False, decision_strategy=ctrl, quiet=True, max_iterations=1,
        )
        return mc.call_args_list[0].kwargs["messages"]


def test_assembled_policy_prompt_has_one_contract_no_verdict_command():
    messages = _first_turn_messages()
    system = messages[0]["content"]
    user = messages[1]["content"]
    assert _RESPONSE_FMT not in system
    assert _RULE_SCOPE not in system  # no verdict coaching on the policy path
    assert _VERDICT_CMD not in user
    assert "fact_slots" in user  # the single response contract, from the overlay
