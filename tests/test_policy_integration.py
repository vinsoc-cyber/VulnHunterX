# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Task 5 integration: analyze() decision-strategy hook + engine routing.

Covers the wiring, not the prompt (the fact-slot prompt overlay is Task 9). We
prove (a) analyze() consults a supplied strategy and acts on its actions,
(b) a real controller drives analyze() to a policy verdict, and (c) the engine
routes covered findings to the policy path, others to legacy, and fails closed
on overlapping policy selection.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from vuln_hunter_x.context.evidence import SourceRef
from vuln_hunter_x.core.config import load_config
from vuln_hunter_x.core.types import Finding, GuidedQuestions, Verdict
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.llm.decision_strategy import Finalize, Retrieve
from vuln_hunter_x.verification.engine import VerificationEngine
from vuln_hunter_x.verification.policy.closure import PolicyClosureController
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.loader import (
    PolicyRegistry,
    load_policy_from_mapping,
    load_policy_registry,
)
from vuln_hunter_x.verification.policy.models import FP, TP, PolicyDecision

_NMD_JSON = '{"verdict":"Needs More Data","confidence":"Low","reasoning":"r","answers":[]}'


def _make_litellm_response(content: str):
    choice = MagicMock()
    choice.message.content = content
    response = MagicMock()
    response.choices = [choice]
    return response


def _finding(rule_id="js/log-injection", cwe="CWE-117"):
    return Finding(
        rule_id=rule_id, message="m", file="app/routes/session.js",
        start_line=64, end_line=64, repo_name="nodegoat", lang="javascript",
        cwe_ids=[cwe], dataflow_path=["req.body.userName", "console.log"],
    )


def _q():
    return GuidedQuestions(rule_id="js/log-injection", short_description="d", questions=["q?"])


def _mk_verdict(verdict: str) -> Verdict:
    return Verdict(
        finding=_finding(), verdict=verdict, confidence="High", reasoning="r",
        answers=[], raw_response="", model="test-model",
    )


def _toy_policy(name: str):
    return load_policy_from_mapping({
        "family": name,
        "selectors": {"cwes": ["CWE-117"]},
        "fact_slots": {"sink_binding": ["QUALIFYING_LOG_SINK", "NOT_LOG_SINK"]},
        "decisive_slots": ["sink_binding"],
        "entailment": {
            "true_positive": {"sink_binding": "QUALIFYING_LOG_SINK"},
            "false_positive_if_any": [{"sink_binding": "NOT_LOG_SINK"}],
        },
    })


class _ScriptedStrategy:
    def __init__(self, actions):
        self._actions = list(actions)
        self.calls = 0

    def evaluate(self, parsed, raw_response="", iteration=1):
        self.calls += 1
        return self._actions.pop(0)


class TestAnalyzeDecisionStrategyHook:
    def setup_method(self):
        self.client = LLMClient(provider="openai", model="gpt-4o")

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_finalize_returns_strategy_verdict_with_accounting(self, mock_completion):
        mock_completion.return_value = _make_litellm_response(_NMD_JSON)
        strategy = _ScriptedStrategy([Finalize(_mk_verdict("True Positive"))])
        v = self.client.analyze(
            finding=_finding(), context="console.log(userName)", questions=_q(),
            func_name="f", force_decision=False, decision_strategy=strategy, quiet=True,
        )
        assert v.verdict == "True Positive"
        assert strategy.calls == 1
        assert mock_completion.call_count == 1
        assert v.iterations == 1

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_retrieve_then_finalize_runs_two_turns(self, mock_completion):
        mock_completion.side_effect = [
            _make_litellm_response(_NMD_JSON),
            _make_litellm_response(_NMD_JSON),
        ]
        strategy = _ScriptedStrategy(
            [Retrieve("here is more evidence"), Finalize(_mk_verdict("False Positive"))]
        )
        v = self.client.analyze(
            finding=_finding(), context="c", questions=_q(),
            func_name="f", force_decision=False, decision_strategy=strategy, quiet=True,
        )
        assert v.verdict == "False Positive"
        assert strategy.calls == 2
        assert mock_completion.call_count == 2

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_real_controller_through_analyze_finalizes_tp(self, mock_completion):
        fact_json = json.dumps({
            "fact_slots": {
                "sink_binding": {"value": "QUALIFYING_LOG_SINK", "evidence": ["L1"]},
                "attacker_control": {"value": "PROVEN", "evidence": ["D1"]},
                "flow_to_sink": {"value": "REACHES", "evidence": ["D1"]},
                "record_boundary": {"value": "BREAKABLE", "evidence": ["L1"]},
                "neutralization_coverage": {"value": "BYPASS_PATH_FOUND", "evidence": ["L1"]},
            },
            "reasoning": "unencoded userName reaches console.log",
        })
        mock_completion.return_value = _make_litellm_response(fact_json)
        policy = load_policy_registry().resolve_family(cwe_ids=["CWE-117"], rule_id="js/log-injection")
        ledger = EvidenceLedger()
        ledger.add_local_slice(
            SourceRef("nodegoat", "javascript", "app/routes/session.js", 60, 70),
            "console.log(userName)",
        )
        ledger.add_scanner_dataflow("req.body.userName -> console.log")
        controller = PolicyClosureController(
            policy=policy, provider=MagicMock(), finding=_finding(), model="gpt-4o", ledger=ledger,
        )
        v = self.client.analyze(
            finding=_finding(), context="console.log(userName)", questions=_q(),
            func_name="f", force_decision=False, decision_strategy=controller, quiet=True,
        )
        assert v.verdict == "True Positive"


class TestEngineRouting:
    def setup_method(self):
        self.engine = VerificationEngine(load_config())

    def test_covered_finding_routes_to_policy(self):
        self.engine._verify_policy_finding = lambda finding, policy: _mk_verdict("POLICY")
        self.engine._verify_legacy_finding = lambda finding: _mk_verdict("LEGACY")
        v = self.engine._verify_single_finding(_finding(cwe="CWE-117"))
        assert v.verdict == "POLICY"

    def test_uncovered_finding_routes_to_legacy(self):
        self.engine._verify_policy_finding = lambda finding, policy: _mk_verdict("POLICY")
        self.engine._verify_legacy_finding = lambda finding: _mk_verdict("LEGACY")
        v = self.engine._verify_single_finding(_finding(rule_id="js/sql-injection", cwe="CWE-89"))
        assert v.verdict == "LEGACY"

    def test_overlapping_policy_fails_closed(self):
        self.engine._policy_registry = PolicyRegistry([_toy_policy("a"), _toy_policy("b")])
        self.engine._verify_legacy_finding = lambda finding: _mk_verdict("LEGACY")
        v = self.engine._verify_single_finding(_finding(cwe="CWE-117"))
        assert v.verdict == "Needs More Data"

    def test_default_decision_source_is_legacy(self):
        assert _mk_verdict("True Positive").decision_source == "legacy_model"


class TestPolicyVotingAggregation:
    def setup_method(self):
        self.engine = VerificationEngine(load_config())
        self.policy = load_policy_registry().resolve_family(
            cwe_ids=["CWE-117"], rule_id="js/log-injection"
        )

    @staticmethod
    def _pd(verdict, reason=None):
        return PolicyDecision(verdict, "log_injection", {"attacker_control": "PROVEN"}, terminal_reason=reason)

    def test_unanimous_tp_is_high_confidence_policy_verdict(self):
        v = self.engine._aggregate_policy_samples(
            _finding(), self.policy,
            [_mk_verdict("True Positive"), _mk_verdict("True Positive")],
            [self._pd(TP), self._pd(TP)],
        )
        assert v.verdict == "True Positive"
        assert v.confidence == "High"
        assert v.decision_source == "policy"
        assert v.policy_decision["family"] == "log_injection"

    def test_sample_disagreement_becomes_nmd(self):
        v = self.engine._aggregate_policy_samples(
            _finding(), self.policy,
            [_mk_verdict("True Positive"), _mk_verdict("False Positive")],
            [self._pd(TP), self._pd(FP)],
        )
        assert v.verdict == "Needs More Data"
        assert v.confidence == "Low"
        assert "sample_disagreement" in (v.policy_decision["terminal_reason"] or "")
