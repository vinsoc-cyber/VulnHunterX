# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for CLI environment checks."""

from __future__ import annotations

import sys
from types import SimpleNamespace

from vuln_hunter_x.cli.env import check_anthropic, check_ollama, check_openai


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


def test_check_openai_omits_enable_thinking_for_official_openai(monkeypatch):
    """Real OpenAI rejects enable_thinking; we must NOT send it without an override."""
    captured: dict = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="OK"))]
        )

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=fake_completion))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)
    monkeypatch.delenv("OPENAI_ENABLE_THINKING", raising=False)

    ok, _ = check_openai(model="gpt-4o-mini")

    assert ok is True
    assert "enable_thinking" not in captured


def test_check_openai_omits_enable_thinking_when_base_url_is_openai(monkeypatch):
    """Even when OPENAI_BASE_URL points at api.openai.com, skip enable_thinking."""
    captured: dict = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="OK"))]
        )

    monkeypatch.setitem(sys.modules, "litellm", SimpleNamespace(completion=fake_completion))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("OPENAI_BASE_URL", "https://api.openai.com/v1")
    monkeypatch.delenv("OPENAI_ENABLE_THINKING", raising=False)

    ok, _ = check_openai(model="gpt-4o-mini")

    assert ok is True
    assert "enable_thinking" not in captured


def _capturing_litellm(captured: dict) -> SimpleNamespace:
    """A fake litellm module whose completion records its kwargs."""

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="OK"))]
        )

    return SimpleNamespace(completion=fake_completion)


def test_check_anthropic_bounds_completion_with_timeout(monkeypatch):
    """#131: the Anthropic connectivity ping must pass an explicit timeout so a
    stalled provider can't hang `vhx check`."""
    captured: dict = {}
    monkeypatch.setitem(sys.modules, "litellm", _capturing_litellm(captured))
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")

    ok, _ = check_anthropic()

    assert ok is True
    assert captured.get("timeout") is not None
    assert captured["timeout"] > 0


def test_check_openai_bounds_completion_with_timeout(monkeypatch):
    """#131: the OpenAI connectivity ping must pass an explicit timeout."""
    captured: dict = {}
    monkeypatch.setitem(sys.modules, "litellm", _capturing_litellm(captured))
    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)

    ok, _ = check_openai(model="gpt-4o-mini")

    assert ok is True
    assert captured.get("timeout") is not None
    assert captured["timeout"] > 0


def test_check_ollama_bounds_completion_with_timeout(monkeypatch):
    """#131: the Ollama connectivity ping must pass an explicit timeout."""
    captured: dict = {}
    monkeypatch.setitem(sys.modules, "litellm", _capturing_litellm(captured))
    # Local endpoint + plain model tag → stays on the non-cloud path.
    monkeypatch.delenv("OLLAMA_API_BASE", raising=False)
    monkeypatch.delenv("OLLAMA_BASE_URL", raising=False)

    ok, _ = check_ollama(model="llama3.2", api_base="http://localhost:11434")

    assert ok is True
    assert captured.get("timeout") is not None
    assert captured["timeout"] > 0
