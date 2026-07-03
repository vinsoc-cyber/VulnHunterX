# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for CLI environment checks."""

from __future__ import annotations

import sys
from types import SimpleNamespace

import vuln_hunter_x.cli.env as envmod
from vuln_hunter_x.cli.env import check_anthropic, check_gemini, check_ollama, check_openai


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


def test_check_gemini_probe_uses_cheap_model_and_native_route(monkeypatch):
    """The Gemini ping defaults to flash-lite, injects the key explicitly, is
    bounded by a timeout (#131), and never gets OpenAI-compat kwargs."""
    captured: dict = {}
    monkeypatch.setitem(sys.modules, "litellm", _capturing_litellm(captured))
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    ok, msg = check_gemini()

    assert ok is True
    assert "Gemini" in msg
    assert captured["model"] == "gemini/gemini-2.5-flash-lite"
    assert captured["api_key"] == "test-key"
    assert captured["timeout"] > 0
    assert "enable_thinking" not in captured


def test_check_gemini_prefixes_configured_model(monkeypatch):
    captured: dict = {}
    monkeypatch.setitem(sys.modules, "litellm", _capturing_litellm(captured))
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")

    ok, _ = check_gemini(model="gemini-2.5-flash")

    assert ok is True
    assert captured["model"] == "gemini/gemini-2.5-flash"


def test_check_gemini_key_precedence(monkeypatch):
    """GEMINI_API_KEY wins over GOOGLE_API_KEY (LiteLLM auto-read is the
    reverse, which is why the key is injected explicitly)."""
    captured: dict = {}
    monkeypatch.setitem(sys.modules, "litellm", _capturing_litellm(captured))
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-key")

    ok, _ = check_gemini()

    assert ok is True
    assert captured["api_key"] == "gemini-key"


def test_check_gemini_falls_back_to_google_api_key(monkeypatch):
    captured: dict = {}
    monkeypatch.setitem(sys.modules, "litellm", _capturing_litellm(captured))
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "google-key")

    ok, _ = check_gemini()

    assert ok is True
    assert captured["api_key"] == "google-key"


def test_check_gemini_without_keys_fails_with_actionable_message(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)

    ok, msg = check_gemini()

    assert ok is False
    assert msg == "GEMINI_API_KEY (or GOOGLE_API_KEY) not set"


def _stub_non_llm_checks(monkeypatch):
    """Stub the tool checks so run_env_check tests stay fast and offline."""
    for name in ("check_codeql", "check_semgrep", "check_opengrep", "check_treesitter"):
        monkeypatch.setattr(envmod, name, lambda *a, **k: (True, "stubbed"))


def test_run_env_check_reports_gemini_when_provider_selected(monkeypatch):
    """LLM_PROVIDER=gemini must yield a "gemini" results key — the exact gap
    deepseek shipped with (accepted by --provider, invisible to check-env)."""
    _stub_non_llm_checks(monkeypatch)
    monkeypatch.setattr(envmod, "check_gemini", lambda **k: (True, "Gemini OK"))
    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_MODEL", "gemini-2.5-flash")
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    results = envmod.run_env_check(quiet=True)

    assert results["gemini"] == (True, "Gemini OK")


def test_run_env_check_skips_gemini_on_google_key_alone(monkeypatch):
    """GOOGLE_API_KEY alone must NOT trigger a billed probe — it is commonly
    set for unrelated Google tooling."""
    _stub_non_llm_checks(monkeypatch)
    monkeypatch.setattr(
        envmod, "check_gemini", lambda **k: (_ for _ in ()).throw(AssertionError("probed"))
    )
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("GOOGLE_API_KEY", "google-key")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setattr(envmod, "check_openai", lambda **k: (True, "stubbed"))
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)

    results = envmod.run_env_check(quiet=True)

    assert results["gemini"] == (False, "Not configured")
