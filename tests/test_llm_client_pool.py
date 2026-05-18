# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Integration test: LLMClient rotates Ollama keys on 429 and parks the offender."""

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
        assert cloud_client._ollama_pool is not None
        assert len(cloud_client._ollama_pool) == 3

    def test_single_key_does_not_build_pool(self, monkeypatch):
        monkeypatch.setenv("OLLAMA_API_BASE", "https://ollama.com")
        client = LLMClient(
            provider="ollama",
            model="qwen3-coder-next:cloud",
            ollama_api_keys=["only"],
        )
        assert client._ollama_pool is None

    def test_local_ollama_does_not_build_pool(self, monkeypatch):
        # Local ollama (no :cloud tag, no ollama.com base) must stay on the
        # single-key path even if keys are passed (defensive).
        monkeypatch.setenv("OLLAMA_API_BASE", "http://localhost:11434")
        client = LLMClient(
            provider="ollama",
            model="llama3.2",
            ollama_api_keys=["k1", "k2"],
        )
        assert client._ollama_pool is None

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
        cloud_client._ollama_pool._cursor = 0  # noqa: SLF001 — test introspection

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
        pool = cloud_client._ollama_pool
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
