# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""vulnhunterx-repo approach and models.yaml loading (mock engine)."""

from __future__ import annotations

import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches import repo_context as rc
from benchmarks.approaches.registry import build_approach


def _entry(**meta):
    return GroundTruthEntry(
        id="e1",
        source_dataset="ds",
        cwe_id="CWE-79",
        rule_id="py/xss",
        file_path="a.py",
        function_name="f",
        start_line=3,
        lang="python",
        label="TP",
        code_snippet="x",
        metadata=meta,
        sink_line=3,
    )


def _verdict():
    return SimpleNamespace(
        verdict="True Positive",
        confidence="High",
        reasoning="r",
        iterations=2,
        raw_response="",
        tokens_used=3,
        input_tokens=2,
        output_tokens=1,
        cached_input_tokens=0,
        cost_usd=0.5,
        decision_source="policy",
    )


@pytest.fixture()
def repos(tmp_path):
    (tmp_path / "python" / "proj__abcd1234").mkdir(parents=True)
    return tmp_path


def test_registered_and_options():
    a = build_approach("vulnhunterx-repo", options={"route": "legacy", "max_iterations": "2"})
    assert isinstance(a, rc.RepoContextApproach) and a._route == "legacy"
    with pytest.raises(ValueError):
        rc.RepoContextApproach(route="bogus")


def test_calls_verify_findings_with_explicit_repo_name_legacy_route(repos, tmp_path):
    out = tmp_path / "out"
    a = rc.RepoContextApproach(route="legacy", repos_dir=repos, output_dir=out)
    engine = MagicMock()
    engine.verify_findings.return_value = SimpleNamespace(verdicts=[_verdict()])
    captured = {}

    def fake_engine(**kw):
        captured.update(kw)
        return engine

    with patch.object(rc, "VerificationEngine", side_effect=fake_engine):
        r = a.evaluate(_entry(repo_name="proj__abcd1234", lang="python"))

    (findings,), _ = engine.verify_findings.call_args
    assert findings[0].repo_name == "proj__abcd1234" and findings[0].lang == "python"
    assert findings[0].start_line == 3
    assert engine._policy_registry.families == []
    cfg = captured["config"]
    assert cfg.paths.repos_dir == repos and cfg.paths.output_dir == out
    assert "context_extractor" not in captured and "context_provider" not in captured
    assert r.predicted_label == "TP" and r.cost_usd == 0.5
    assert "decision_source=policy" in r.reasoning


def test_auto_route_keeps_registry(repos):
    a = rc.RepoContextApproach(route="auto", repos_dir=repos)
    engine = MagicMock()
    sentinel = object()
    engine._policy_registry = sentinel
    engine.verify_findings.return_value = SimpleNamespace(verdicts=[_verdict()])
    with patch.object(rc, "VerificationEngine", return_value=engine):
        a.evaluate(_entry(repo_name="proj__abcd1234", lang="python"))
    assert engine._policy_registry is sentinel


@pytest.mark.parametrize(
    "meta",
    [
        {},
        {"repo_name": "missing", "lang": "python"},
        {"repo_name": "../x", "lang": "python"},
    ],
)
def test_missing_repo_is_error_no_engine(repos, meta):
    a = rc.RepoContextApproach(repos_dir=repos)
    with patch.object(rc, "VerificationEngine") as eng:
        r = a.evaluate(_entry(**meta))
    assert r.predicted_label == "ERROR" and "no snippet fallback" in r.reasoning
    eng.assert_not_called()


def test_models_yaml_loads_via_matrix_loader():
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "benchmarks" / "scripts"))
    try:
        import run_model_matrix as m
    finally:
        sys.path.pop(0)
    models = m._load_models(Path(m._CONFIG_DIR) / "models.yaml.example", None)
    ids = {x["id"] for x in models}
    assert {"claude-sonnet-5-5", "claude-haiku-5-5"} <= ids
    assert not any("qwen3-coder:480b" in x["model"] for x in models)
    allowed = {"openai", "ollama", "anthropic", "deepseek", "gemini"}
    for x in models:
        assert x["provider"] in allowed and x["tier"] in {"dev", "bulk", "headline"}
        assert x["env"].startswith(".env.") and "key" not in x
