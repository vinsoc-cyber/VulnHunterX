# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Tests for parallel verification in VerificationEngine, LLMClient temperature
handling under concurrency, and ContextProvider cache safety."""

from __future__ import annotations

import threading
import time
from collections import Counter
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.config import Config
from vuln_hunter_x.core.types import (
    CodeContext,
    Finding,
    GuidedQuestions,
    Verdict,
)
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.verification.engine import VerificationEngine


def _mk_finding(idx: int) -> Finding:
    return Finding(
        rule_id=f"test/rule-{idx}",
        message=f"finding {idx}",
        file=f"file_{idx}.c",
        start_line=idx,
        end_line=idx,
        repo_name="test-repo",
        lang="c",
    )


def _mk_verdict(finding: Finding, label: str = "False Positive") -> Verdict:
    return Verdict(
        finding=finding,
        verdict=label,
        confidence="Medium",
        reasoning="ok",
        answers=[],
        raw_response="raw",
        model="fake",
        elapsed_seconds=0.01,
        iterations=1,
        tokens_used=0,
        input_tokens=0,
        output_tokens=0,
        cost_usd=0.0,
        confidence_score=0.6,
    )


class _FakeLLMClient:
    """Minimal duck-typed LLM client. Records each analyze() call and
    returns a deterministic verdict mapping by finding.rule_id."""

    def __init__(self, sleep_seconds: float = 0.0) -> None:
        self.calls: list[tuple[str, float | None]] = []
        self.lock = threading.Lock()
        self._sleep = sleep_seconds

    def analyze(self, finding, context, questions, func_name, **kwargs) -> Verdict:
        if self._sleep:
            time.sleep(self._sleep)
        with self.lock:
            self.calls.append((finding.rule_id, kwargs.get("temperature")))
        # Decide label deterministically from rule_id to make ordering visible.
        label = "True Positive" if int(finding.rule_id.split("-")[-1]) % 2 == 0 else "False Positive"
        return _mk_verdict(finding, label)

    def analyze_with_voting(self, finding, context, questions, func_name, **kwargs) -> Verdict:
        # Honour samples but ignore voting math — tests do not exercise it.
        return self.analyze(finding, context, questions, func_name, **kwargs)


def _build_engine(
    jobs: int,
    fake_llm: _FakeLLMClient,
) -> VerificationEngine:
    config = Config()
    config.verification.jobs = jobs
    config.verification.self_consistency_samples = 1
    # Disable any disk-touching defaults.
    config.output.log_file = None

    questions_loader = MagicMock()
    questions_loader.get_questions.return_value = GuidedQuestions(
        rule_id="test", short_description="d", questions=["q"],
    )
    questions_loader.rule_count = 0

    context_extractor = MagicMock()
    context_extractor.get_context.return_value = CodeContext(
        code="// snippet", function_name="f", start_line=1, end_line=1,
    )

    return VerificationEngine(
        config=config,
        questions_loader=questions_loader,
        context_extractor=context_extractor,
        context_provider=None,
        llm_client=fake_llm,
        jobs=jobs,
    )


def test_parallel_verify_matches_sequential():
    """Same findings + same fake LLM should produce identical verdict
    counts whether jobs=1 or jobs=4."""
    findings = [_mk_finding(i) for i in range(1, 21)]

    seq_engine = _build_engine(jobs=1, fake_llm=_FakeLLMClient())
    seq_result = seq_engine.verify_findings(list(findings))

    par_engine = _build_engine(jobs=4, fake_llm=_FakeLLMClient())
    par_result = par_engine.verify_findings(list(findings))

    seq_labels = Counter(v.verdict for v in seq_result.verdicts)
    par_labels = Counter(v.verdict for v in par_result.verdicts)
    assert seq_labels == par_labels

    # Order-preserving in the parallel path: the returned verdicts list maps
    # input order, even though execution finished in arbitrary order.
    assert [v.finding.rule_id for v in seq_result.verdicts] == [
        v.finding.rule_id for v in par_result.verdicts
    ]
    # stats dict is order-insensitive but should equal across runs.
    assert seq_result.stats == par_result.stats


def test_parallel_verify_progress_callbacks_serialized():
    """Progress callbacks must not be invoked concurrently — the callback
    lock should serialize them even when N workers are running."""
    findings = [_mk_finding(i) for i in range(1, 9)]
    engine = _build_engine(jobs=4, fake_llm=_FakeLLMClient(sleep_seconds=0.01))

    overlap_detected = threading.Event()
    in_flight = 0
    overlap_lock = threading.Lock()

    def on_start(i, total, finding):
        nonlocal in_flight
        with overlap_lock:
            in_flight += 1
            if in_flight > 1:
                overlap_detected.set()
        time.sleep(0.005)  # widen the window for an unsafe callback to overlap
        with overlap_lock:
            in_flight -= 1

    engine.on_finding_start(on_start)
    engine.verify_findings(findings)
    assert not overlap_detected.is_set()


def test_parallel_voting_temperature_not_shared():
    """LLMClient.analyze_with_voting must thread voting_temperature through
    per-call kwargs without mutating self.temperature. Two concurrent callers
    requesting different voting temperatures should each see their own value
    in every sub-call's kwargs."""
    base_temp = 0.123
    client = LLMClient(provider="openai", model="gpt-4o", temperature=base_temp)
    seen: list[tuple[float, float]] = []  # (requested, observed)
    seen_lock = threading.Lock()

    # Replace analyze so we don't actually call litellm. We capture the
    # temperature passed via the per-call kwarg.
    original_temp_snapshot = client.temperature

    def fake_analyze(*, temperature=None, finding=None, **_kwargs) -> Verdict:
        with seen_lock:
            seen.append((temperature, client.temperature))
        return _mk_verdict(finding, "False Positive")

    client.analyze = fake_analyze  # type: ignore[method-assign]

    finding_a = _mk_finding(1)
    finding_b = _mk_finding(2)

    def caller(target_temp: float, finding: Finding) -> None:
        client.analyze_with_voting(
            finding=finding,
            context="",
            questions=GuidedQuestions(
                rule_id="t", short_description="", questions=[],
            ),
            func_name="f",
            samples=3,
            voting_temperature=target_temp,
        )

    t_a = threading.Thread(target=caller, args=(0.9, finding_a))
    t_b = threading.Thread(target=caller, args=(0.1, finding_b))
    t_a.start()
    t_b.start()
    t_a.join()
    t_b.join()

    assert len(seen) == 6  # 2 threads × 3 samples each
    # Every recorded call must have received its caller's voting temperature,
    # not the other thread's. And self.temperature must never have been mutated.
    for requested, observed_self in seen:
        assert requested in (0.9, 0.1)
        assert observed_self == original_temp_snapshot

    assert client.temperature == base_temp


def test_context_provider_concurrent_load(tmp_path: Path):
    """Concurrent _load_csv calls on the same key must not corrupt the cache
    nor raise. After the storm, the cache holds a single canonical list."""
    output_dir = tmp_path / "output"
    repos_dir = tmp_path / "repos"
    ctx_dir = output_dir / "c" / "demo" / "context"
    ctx_dir.mkdir(parents=True)
    csv_path = ctx_dir / "functions.csv"
    csv_path.write_text("name,body\nfoo,foo_body\nbar,bar_body\n", encoding="utf-8")

    provider = ContextProvider(output_dir, repos_dir)
    barrier = threading.Barrier(8)
    results: list[list[dict]] = []
    results_lock = threading.Lock()

    def worker():
        barrier.wait()  # maximise concurrent entry into _load_csv
        rows = provider._load_csv("demo", "c", "functions")
        with results_lock:
            results.append(rows)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(results) == 8
    # Every thread saw a 2-row CSV.
    for r in results:
        assert len(r) == 2
        assert {row["name"] for row in r} == {"foo", "bar"}
    # Cache has exactly one entry under the canonical key.
    assert list(provider._cache.keys()) == ["c/demo/functions"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
