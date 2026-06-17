# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for LLMClient self-consistency voting (CISC-style aggregation).

These tests cover the aggregation logic only — they do not call litellm.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.llm.client import LLMClient


def _mk_finding() -> Finding:
    return Finding(
        rule_id="cpp/use-after-free",
        message="UAF",
        file="test.c",
        start_line=42,
        end_line=42,
        repo_name="test-repo",
        lang="c",
    )


def _mk_verdict(
    verdict: str,
    confidence_score: float = 0.85,
    tokens_used: int = 1000,
    input_tokens: int = 700,
    output_tokens: int = 300,
    cost_usd: float = 0.0,
    elapsed_seconds: float = 5.0,
    iterations: int = 2,
    reasoning: str = "ok",
) -> Verdict:
    return Verdict(
        finding=_mk_finding(),
        verdict=verdict,
        confidence="High",
        reasoning=reasoning,
        answers=[],
        raw_response="raw",
        model="qwen3-max",
        elapsed_seconds=elapsed_seconds,
        iterations=iterations,
        tokens_used=tokens_used,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cost_usd=cost_usd,
        confidence_score=confidence_score,
    )


def test_voting_single_verdict_passthrough():
    v = _mk_verdict("True Positive")
    out = LLMClient._aggregate_votes([v])
    assert out is v


def test_voting_unanimous_tp_high_agreement():
    verdicts = [_mk_verdict("True Positive", confidence_score=0.9)] * 5
    out = LLMClient._aggregate_votes(verdicts)
    assert out.verdict == "True Positive"
    assert out.confidence == "High"


def test_voting_majority_wins_over_minority():
    verdicts = [
        _mk_verdict("True Positive",  confidence_score=0.8),
        _mk_verdict("True Positive",  confidence_score=0.8),
        _mk_verdict("False Positive", confidence_score=0.9),
    ]
    out = LLMClient._aggregate_votes(verdicts)
    # 2 * 0.8 = 1.6 > 0.9 → TP wins
    assert out.verdict == "True Positive"


def test_voting_confidence_weighted_can_overturn_count_majority():
    # Three FP votes with weak confidence vs. two TP votes with strong:
    # FP score 3 * 0.2 = 0.6 vs TP score 2 * 0.95 = 1.9 → TP wins.
    verdicts = [
        _mk_verdict("False Positive", confidence_score=0.2),
        _mk_verdict("False Positive", confidence_score=0.2),
        _mk_verdict("False Positive", confidence_score=0.2),
        _mk_verdict("True Positive",  confidence_score=0.95),
        _mk_verdict("True Positive",  confidence_score=0.95),
    ]
    out = LLMClient._aggregate_votes(verdicts)
    assert out.verdict == "True Positive"


def test_voting_tie_break_default_fp():
    verdicts = [
        _mk_verdict("True Positive",  confidence_score=0.5),
        _mk_verdict("False Positive", confidence_score=0.5),
    ]
    out = LLMClient._aggregate_votes(verdicts, tie_break="fp")
    assert out.verdict == "False Positive"


def test_voting_tie_break_tp():
    verdicts = [
        _mk_verdict("True Positive",  confidence_score=0.5),
        _mk_verdict("False Positive", confidence_score=0.5),
    ]
    out = LLMClient._aggregate_votes(verdicts, tie_break="tp")
    assert out.verdict == "True Positive"


def test_voting_nmd_does_not_contribute_weight():
    verdicts = [
        _mk_verdict("Needs More Data", confidence_score=0.99),
        _mk_verdict("True Positive",   confidence_score=0.5),
    ]
    out = LLMClient._aggregate_votes(verdicts)
    assert out.verdict == "True Positive"


def test_voting_aggregates_costs_and_tokens():
    verdicts = [
        _mk_verdict("True Positive", tokens_used=1000, input_tokens=700,
                    output_tokens=300, cost_usd=0.01, elapsed_seconds=2.0,
                    iterations=2),
        _mk_verdict("True Positive", tokens_used=2000, input_tokens=1500,
                    output_tokens=500, cost_usd=0.02, elapsed_seconds=4.0,
                    iterations=3),
    ]
    out = LLMClient._aggregate_votes(verdicts)
    assert out.tokens_used == 3000
    assert out.input_tokens == 2200
    assert out.output_tokens == 800
    assert out.cost_usd == pytest.approx(0.03)
    assert out.elapsed_seconds == pytest.approx(6.0)
    # Iterations is the MAX (single longest analysis), not the sum.
    assert out.iterations == 3


def test_voting_low_agreement_yields_low_confidence():
    # 1 TP + 1 FP + 1 NMD = 33% agreement → Low.
    verdicts = [
        _mk_verdict("True Positive",   confidence_score=0.5),
        _mk_verdict("False Positive",  confidence_score=0.4),
        _mk_verdict("Needs More Data", confidence_score=0.3),
    ]
    out = LLMClient._aggregate_votes(verdicts)
    assert out.confidence == "Low"


def test_voting_invalid_inputs():
    with pytest.raises(ValueError):
        LLMClient._aggregate_votes([])


def test_analyze_with_voting_invalid_samples():
    client = LLMClient(provider="openai", model="x")
    with pytest.raises(ValueError):
        client.analyze_with_voting(
            finding=_mk_finding(), context="", questions=None,  # type: ignore[arg-type]
            func_name="f", samples=0,
        )


def test_analyze_with_voting_invalid_tie_break():
    client = LLMClient(provider="openai", model="x")
    with pytest.raises(ValueError):
        client.analyze_with_voting(
            finding=_mk_finding(), context="", questions=None,  # type: ignore[arg-type]
            func_name="f", samples=3, tie_break="invalid",
        )
