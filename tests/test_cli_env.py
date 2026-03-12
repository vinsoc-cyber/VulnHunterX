"""Tests for CLI environment checks."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from vuln_hunter_x.cli.env import check_openai


def test_check_openai_sets_enable_thinking_false(monkeypatch):
    """OpenAI-compatible non-streaming calls should pass enable_thinking=False."""
    captured: dict = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="OK"))]
        )

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=fake_completion))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://example.invalid/v1")
    monkeypatch.delenv("OPENAI_ENABLE_THINKING", raising=False)

    ok, msg = check_openai(model="qwen3-8b")

    assert ok is True
    assert "OpenAI" in msg
    assert captured["enable_thinking"] is False


def test_check_openai_respects_enable_thinking_override(monkeypatch):
    """Env override should allow enable_thinking=True when explicitly set."""
    captured: dict = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="OK"))]
        )

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=fake_completion))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_ENABLE_THINKING", "true")

    ok, _ = check_openai(model="gpt-4o-mini")

    assert ok is True
    assert captured["enable_thinking"] is True
