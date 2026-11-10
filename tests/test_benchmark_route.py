# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""vulnhunterx route option, and the --cutoff-after/--cutoff-before filter."""

from __future__ import annotations

from datetime import date
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches.vulnhunterx import VulnHunterXApproach
from benchmarks.metrics.evaluator import evaluate
from benchmarks.scripts.run_benchmark import _apply_cutoff_filter, _parse_cutoff
from vuln_hunter_x.verification.policy.loader import PolicyRegistry


def _entry(i: int = 0, **meta) -> GroundTruthEntry:
    return GroundTruthEntry(
        id=f"e{i}",
        source_dataset="t",
        cwe_id="CWE-79",
        rule_id="python/xss",
        file_path="a.py",
        function_name="f",
        start_line=1,
        lang="python",
        label="TP",
        code_snippet="x = 1\n",
        metadata=dict(meta),
        sink_line=1,
    )


def _run(route: str, decision_source: str):
    verdict = SimpleNamespace(
        verdict="True Positive",
        confidence="High",
        reasoning="r",
        iterations=1,
        raw_response="",
        tokens_used=0,
        input_tokens=0,
        output_tokens=0,
        cached_input_tokens=0,
        cost_usd=0.0,
        decision_source=decision_source,
    )
    engine = MagicMock()
    engine.verify_findings.return_value = SimpleNamespace(verdicts=[verdict])
    with patch("benchmarks.approaches.vulnhunterx.VerificationEngine", return_value=engine):
        entry = _entry()
        result = VulnHunterXApproach(route=route).evaluate(entry)
    return engine, entry, result


def test_route_legacy_installs_empty_registry():
    engine, _, result = _run("legacy", "legacy_model")
    assert isinstance(engine._policy_registry, PolicyRegistry)
    assert engine._policy_registry.families == []
    assert result.entry.metadata["decision_source"] == "legacy_model"


def test_route_auto_leaves_engine_registry_alone():
    engine, entry, result = _run("auto", "policy")
    assert not isinstance(engine._policy_registry, PolicyRegistry)
    assert result.entry.metadata["decision_source"] == "policy"
    assert "excluded_from_scoring" not in result.entry.metadata
    assert "decision_source" not in entry.metadata  # shared entry not mutated


def test_route_policy_only_excludes_non_policy_results():
    _, _, legacy = _run("policy-only", "legacy_model")
    _, _, policy = _run("policy-only", "policy")
    assert legacy.entry.metadata["excluded_from_scoring"]
    assert "excluded_from_scoring" not in policy.entry.metadata
    m = evaluate([legacy, policy], "vulnhunterx", "t")
    assert m.n_excluded == 1 and m.total_evaluated == 1


def test_invalid_route_rejected():
    with pytest.raises(ValueError):
        VulnHunterXApproach(route="nope")


def test_route_option_in_schema():
    assert VulnHunterXApproach.option_schema["route"].default == "auto"


def test_cutoff_filter():
    es = [
        _entry(1, cve_published="2024-01-01"),
        _entry(2, cve_published="2025-06-15T10:00:00Z"),
        _entry(3, cve_published="2026-03-01"),
        _entry(4),
        _entry(5, cve_published="garbage"),
    ]
    after = _apply_cutoff_filter(es, date(2025, 1, 1), None)
    assert [e.id for e in after] == ["e2", "e3"]
    before = _apply_cutoff_filter(es, None, date(2025, 1, 1))
    assert [e.id for e in before] == ["e1"]
    both = _apply_cutoff_filter(es, date(2024, 6, 1), date(2026, 1, 1))
    assert [e.id for e in both] == ["e2"]
    assert _apply_cutoff_filter(es, None, None) is es


def test_parse_cutoff():
    assert _parse_cutoff("2025-01-02", "--x") == date(2025, 1, 2)
    assert _parse_cutoff(None, "--x") is None
    with pytest.raises(SystemExit):
        _parse_cutoff("01/02/2025", "--x")
