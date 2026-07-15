# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""arm_c: a framework-taint True Positive must get a TP-oriented challenge.

Previously arm_c (a 1-iter/High TP on a framework-language taint CWE) passed
challenge_prompt=None, so request_second_opinion fell back to the FP-oriented
_SECOND_OPINION_PROMPT which opens by asserting the previous verdict was 'False
Positive' — a mismatch that garbled the re-verification. The fix routes arm_c to
a dedicated framework-taint challenge that correctly states the prior TP.
"""

from __future__ import annotations

from vuln_hunter_x.core.config import load_config
from vuln_hunter_x.core.types import CodeContext, Finding, Verdict
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.verification.engine import VerificationEngine


def _tp(finding):
    return Verdict(
        finding=finding, verdict="True Positive", confidence="High", reasoning="r",
        answers=[], raw_response="", model="m", iterations=1, confidence_score=0.9,
    )


def test_framework_taint_prompt_states_prior_tp_not_fp():
    p = LLMClient._FRAMEWORK_TAINT_TP_CHALLENGE_PROMPT
    assert "True Positive" in p
    # Must not OPEN by asserting the previous verdict was a False Positive.
    assert "was 'False Positive'" not in p


def test_arm_c_routes_framework_taint_tp_to_tp_challenge():
    engine = VerificationEngine(load_config())
    finding = Finding(
        rule_id="js/reflected-xss", message="m", file="app.js", start_line=5,
        end_line=5, repo_name="r", lang="javascript", cwe_ids=["CWE-79"],
    )
    engine.context_extractor.get_context = lambda *a, **k: CodeContext(
        code="res.send(req.query.q)", function_name="h", start_line=1, end_line=10,
        file_path="app.js",
    )
    engine.llm_client.analyze = lambda **k: _tp(finding)

    captured = {}

    def fake_second(*a, **k):
        captured["challenge_prompt"] = k.get("challenge_prompt")
        return _tp(finding)

    engine.llm_client.request_second_opinion = fake_second
    engine._verify_legacy_finding(finding)

    assert captured.get("challenge_prompt") == LLMClient._FRAMEWORK_TAINT_TP_CHALLENGE_PROMPT
