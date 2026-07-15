# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P3c Task 1: the policy evidence-closure path must inherit P3a anchor fidelity.

Before P3c the policy path read ``finding.start_line`` directly and never
re-anchored, so expanding policy coverage would reintroduce #118 (reasoning over
a misaligned slice). These tests pin: a re-anchored construct is analyzed at its
resolved line; an unplaceable construct is a structural-gate NMD (never the
model); a snippet-less finding is unchanged (reported line, verdict-neutral).
"""

from __future__ import annotations

from unittest.mock import MagicMock

from vuln_hunter_x.core.config import load_config
from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import VerificationEngine
from vuln_hunter_x.verification.policy.loader import load_policy_registry


def _finding(snippet: str, start_line: int = 64) -> Finding:
    return Finding(
        rule_id="js/log-injection", message="m", file="app/routes/session.js",
        start_line=start_line, end_line=start_line, repo_name="nodegoat",
        lang="javascript", cwe_ids=["CWE-117"],
        dataflow_path=["req.body.userName", "console.log"], sink_snippet=snippet,
    )


def _policy():
    return load_policy_registry().resolve_family(
        cwe_ids=["CWE-117"], rule_id="js/log-injection"
    )


def _engine(source: str) -> VerificationEngine:
    e = VerificationEngine(load_config())
    e.config.verification.self_consistency_samples = 1
    e.context_extractor = MagicMock()
    e.context_extractor.read_source.return_value = source
    e.context_extractor.get_context.return_value = MagicMock(
        code="console.log(userName)", function_name="f", start_line=3, end_line=3
    )
    e.llm_client = MagicMock()
    e.llm_client.model = "gpt-test"
    e.llm_client.analyze.return_value = Verdict(
        finding=_finding(""), verdict="True Positive", confidence="High",
        reasoning="r", answers=[], raw_response="", model="gpt-test",
    )
    return e


def test_policy_reanchors_to_resolved_line():
    # snippet lives uniquely at line 3; reported line 64 is out of range.
    e = _engine("a\nb\nconsole.log(userName)\nc\n")
    e._verify_policy_finding(_finding("console.log(userName)"), _policy())
    called_line = e.context_extractor.get_context.call_args[0][1]
    assert called_line == 3  # analysis moves to the construct's real line


def test_policy_ambiguous_anchor_is_structural_gate_nmd():
    # snippet matches two lines -> cannot be uniquely placed -> honest NMD.
    e = _engine("console.log(userName)\nx\nconsole.log(userName)\n")
    v = e._verify_policy_finding(_finding("console.log(userName)"), _policy())
    assert v.verdict == "Needs More Data"
    assert v.decision_source == "structural_gate"
    e.llm_client.analyze.assert_not_called()


def test_policy_snippetless_uses_reported_line_unchanged():
    # no snippet -> located_unverified -> reported line, model runs (neutral).
    e = _engine("irrelevant source")
    e._verify_policy_finding(_finding(""), _policy())
    called_line = e.context_extractor.get_context.call_args[0][1]
    assert called_line == 64
    e.llm_client.analyze.assert_called_once()
