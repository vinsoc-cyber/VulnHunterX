# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Integration test: LLMClient rotates pooled keys (Ollama Cloud, Gemini) on 429 and parks the offender."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import litellm
import pytest

from vuln_hunter_x.llm.client import LLMClient


def _ok_response(content: str = '{"verdict": "TP"}') -> MagicMock:
    choice = MagicMock()
    choice.message.content = content
    response = MagicMock()
    response.choices = [choice]
    return response


def _rate_limit_error() -> litellm.RateLimitError:
    return litellm.RateLimitError("rate-limited", llm_provider="ollama", model="qwen3-coder-next:cloud")


@pytest.fixture()
def cloud_client(monkeypatch):
    """LLMClient pointed at Ollama Cloud with a 3-key pool."""
    monkeypatch.setenv("OLLAMA_API_BASE", "https://ollama.com")
    return LLMClient(
        provider="ollama",
        model="qwen3-coder-next:cloud",
        ollama_api_keys=["k1", "k2", "k3"],
    )


class TestPoolWiring:
    def test_pool_built_when_two_or_more_cloud_keys(self, cloud_client):
        assert cloud_client._key_pool is not None
        assert len(cloud_client._key_pool) == 3

    def test_single_key_does_not_build_pool(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_API_BASE", "https://ollama.com")
        client = LLMClient(
            provider="ollama",
            model="qwen3-coder-next:cloud",
            ollama_api_keys=["only"],
        )
        assert client._key_pool is None

    def test_local_ollama_does_not_build_pool(self, monkeypatch):
        # Local ollama (no :cloud tag, no ollama.com base) must stay on the
        # single-key path even if keys are passed (defensive).
        monkeypatch.setenv("OLLAMA_API_BASE", "http://localhost:11434")
        client = LLMClient(
            provider="ollama",
            model="llama3.2",
            ollama_api_keys=["k1", "k2"],
        )
        assert client._key_pool is None

    def test_kwargs_inject_pool_key_and_disable_litellm_retries(self, cloud_client):
        kwargs = cloud_client._build_completion_kwargs([{"role": "user", "content": "x"}])
        assert kwargs["api_key"] in {"k1", "k2", "k3"}
        # When the pool drives retry, LiteLLM's own retry loop is disabled
        # so we don't hammer a cooling key.
        assert "num_retries" not in kwargs
        assert "retry_strategy" not in kwargs


class TestRotationOnRateLimit:
    def test_429_on_first_key_falls_over_to_next(self, cloud_client):
        # Force "k1" first by aligning the cursor.
        cloud_client._key_pool._cursor = 0  # noqa: SLF001 — test introspection

        calls: list[str] = []

        def fake_completion(**kwargs):
            calls.append(kwargs["api_key"])
            if kwargs["api_key"] == "k1":
                raise _rate_limit_error()
            return _ok_response()

        with patch.object(litellm, "completion", side_effect=fake_completion):
            kwargs = cloud_client._build_completion_kwargs([{"role": "user", "content": "x"}])
            # _build_completion_kwargs already picked the first key (k1).
            assert kwargs["api_key"] == "k1"
            resp = cloud_client._completion(kwargs)

        assert resp.choices[0].message.content == '{"verdict": "TP"}'
        # First attempt on k1 raised, second attempt on a fresh key succeeded.
        assert len(calls) >= 2
        assert calls[0] == "k1"
        assert calls[1] in {"k2", "k3"}

    def test_429_parks_the_offending_key(self, cloud_client):
        pool = cloud_client._key_pool
        pool._cursor = 0  # noqa: SLF001

        def fake_completion(**kwargs):
            if kwargs["api_key"] == "k1":
                raise _rate_limit_error()
            return _ok_response()

        with patch.object(litellm, "completion", side_effect=fake_completion):
            kwargs = cloud_client._build_completion_kwargs([{"role": "user", "content": "x"}])
            cloud_client._completion(kwargs)

        # The next acquire from the pool must skip k1 (now cooling).
        next_keys = {pool.acquire() for _ in range(6)}
        assert "k1" not in next_keys

    def test_all_keys_rate_limited_raises_last_error(self, cloud_client):
        def always_429(**_kwargs):
            raise _rate_limit_error()

        with patch.object(litellm, "completion", side_effect=always_429):
            kwargs = cloud_client._build_completion_kwargs([{"role": "user", "content": "x"}])
            with pytest.raises(litellm.RateLimitError):
                cloud_client._completion(kwargs)


def _quota_error() -> litellm.APIConnectionError:
    # Mirrors the body Ollama Cloud returns when a per-account session
    # quota is hit (see benchmarks/results/.../*_vulnhunterx_results.json).
    return litellm.APIConnectionError(
        message=(
            'Ollama_chatException - {"error":"you (falregister) have reached '
            'your session usage limit, upgrade for higher limits: '
            'https://ollama.com/upgrade (ref: abc)"}'
        ),
        llm_provider="ollama",
        model="qwen3-coder-next:cloud",
    )


class TestRotationOnQuota:
    def test_quota_error_rotates_and_parks_key(self, cloud_client):
        pool = cloud_client._key_pool
        pool._cursor = 0  # noqa: SLF001

        calls: list[str] = []

        def fake_completion(**kwargs):
            calls.append(kwargs["api_key"])
            if kwargs["api_key"] == "k1":
                raise _quota_error()
            return _ok_response()

        with patch.object(litellm, "completion", side_effect=fake_completion):
            kwargs = cloud_client._build_completion_kwargs([{"role": "user", "content": "x"}])
            assert kwargs["api_key"] == "k1"
            resp = cloud_client._completion(kwargs)

        assert resp.choices[0].message.content == '{"verdict": "TP"}'
        assert calls[0] == "k1"
        assert calls[1] in {"k2", "k3"}
        # The exhausted key must stay parked for a long time, not seconds.
        next_keys = {pool.acquire() for _ in range(6)}
        assert "k1" not in next_keys

    def test_non_quota_connection_error_propagates(self, cloud_client):
        # A genuine network error must NOT burn a key — propagate immediately.
        net_err = litellm.APIConnectionError(
            message="Connection refused",
            llm_provider="ollama",
            model="qwen3-coder-next:cloud",
        )

        def always_fail(**_kwargs):
            raise net_err

        with patch.object(litellm, "completion", side_effect=always_fail):
            kwargs = cloud_client._build_completion_kwargs([{"role": "user", "content": "x"}])
            with pytest.raises(litellm.APIConnectionError):
                cloud_client._completion(kwargs)

        # No keys should have been parked.
        pool = cloud_client._key_pool
        seen = {pool.acquire() for _ in range(6)}
        assert seen == {"k1", "k2", "k3"}


@pytest.fixture()
def gemini_client(monkeypatch):
    """LLMClient on Gemini with a 3-key pool from comma-separated GEMINI_API_KEY."""
    monkeypatch.delenv("GEMINI_API_KEYS", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "g1,g2,g3")
    return LLMClient(provider="gemini", model="gemini-2.5-flash")


class TestGeminiPool:
    def test_pool_built_from_comma_separated_env(self, gemini_client):
        assert gemini_client._key_pool is not None
        assert len(gemini_client._key_pool) == 3

    def test_explicit_keys_param_overrides_env(self, monkeypatch):
        monkeypatch.setenv("GEMINI_API_KEY", "env1,env2")
        client = LLMClient(
            provider="gemini",
            model="gemini-2.5-flash",
            gemini_api_keys=["p1", "p2", "p3"],
        )
        kwargs = client._build_completion_kwargs([{"role": "user", "content": "x"}])
        assert kwargs["api_key"] in {"p1", "p2", "p3"}

    def test_single_key_does_not_build_pool(self, monkeypatch):
        monkeypatch.delenv("GEMINI_API_KEYS", raising=False)
        monkeypatch.setenv("GEMINI_API_KEY", "only")
        client = LLMClient(provider="gemini", model="gemini-2.5-flash")
        assert client._key_pool is None
        assert client._single_key == "only"

    def test_429_rotates_to_next_key(self, gemini_client):
        gemini_client._key_pool._cursor = 0  # noqa: SLF001 — test introspection

        calls: list[str] = []

        def fake_completion(**kwargs):
            calls.append(kwargs["api_key"])
            if kwargs["api_key"] == "g1":
                raise litellm.RateLimitError(
                    "rate-limited", llm_provider="gemini", model="gemini-2.5-flash"
                )
            return _ok_response()

        with patch.object(litellm, "completion", side_effect=fake_completion):
            kwargs = gemini_client._build_completion_kwargs([{"role": "user", "content": "x"}])
            assert kwargs["api_key"] == "g1"
            resp = gemini_client._completion(kwargs)

        assert resp.choices[0].message.content == '{"verdict": "TP"}'
        assert calls[0] == "g1"
        assert calls[1] in {"g2", "g3"}
        # The 429ed key is parked.
        next_keys = {gemini_client._key_pool.acquire() for _ in range(6)}
        assert "g1" not in next_keys

    def test_connection_error_propagates_even_with_quota_wording(self, gemini_client):
        # The quota-marker APIConnectionError handling is Ollama-specific;
        # for Gemini any APIConnectionError is a genuine failure — propagate
        # without burning a key.
        err = litellm.APIConnectionError(
            message="you have reached your session usage limit",
            llm_provider="gemini",
            model="gemini-2.5-flash",
        )

        def always_fail(**_kwargs):
            raise err

        with patch.object(litellm, "completion", side_effect=always_fail):
            kwargs = gemini_client._build_completion_kwargs([{"role": "user", "content": "x"}])
            with pytest.raises(litellm.APIConnectionError):
                gemini_client._completion(kwargs)

        seen = {gemini_client._key_pool.acquire() for _ in range(6)}
        assert seen == {"g1", "g2", "g3"}
