# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""#152 — shared run_completion helper: one place for the non-verification
litellm.completion calls (kwargs assembly + openai-compat + optional retry)."""

from __future__ import annotations

import litellm

from vuln_hunter_x.llm.completion import run_completion


def _capture(monkeypatch) -> dict:
    seen: dict = {}
    monkeypatch.setattr(litellm, "completion", lambda **k: seen.update(k) or "resp")
    return seen


def test_builds_core_kwargs(monkeypatch) -> None:
    seen = _capture(monkeypatch)
    out = run_completion(
        messages=[{"role": "user", "content": "x"}], model="gpt-4o",
        provider="openai", api_key="sk", max_tokens=100, timeout=30,
    )
    assert out == "resp"
    assert seen["model"] == "gpt-4o"
    assert seen["max_tokens"] == 100 and seen["timeout"] == 30
    assert seen["api_key"] == "sk"
    assert "temperature" not in seen   # omitted when None
    assert "num_retries" not in seen   # omitted when 0


def test_temperature_and_retry_passthrough(monkeypatch) -> None:
    seen = _capture(monkeypatch)
    run_completion(
        messages=[{"role": "user", "content": "x"}], model="gpt-4o",
        provider="openai", api_key="sk", max_tokens=100, timeout=30,
        temperature=0.2, num_retries=2,
    )
    assert seen["temperature"] == 0.2
    assert seen["num_retries"] == 2
    assert seen["retry_strategy"] == "exponential_backoff_retry"


def test_openai_compat_kwargs_applied(monkeypatch) -> None:
    monkeypatch.setenv("OPENAI_ENABLE_THINKING", "true")
    seen = _capture(monkeypatch)
    run_completion(
        messages=[{"role": "user", "content": "x"}], model="qwen",
        provider="openai", api_base="http://dashscope.local", api_key="sk",
        max_tokens=100, timeout=30,
    )
    assert seen.get("enable_thinking") is True   # from openai_compat_kwargs
    assert seen["api_base"] == "http://dashscope.local"
