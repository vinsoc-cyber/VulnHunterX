# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Shared litellm.completion helper for the non-verification call sites.

Centralizes kwargs assembly, OpenAI-compat extras, and optional LiteLLM retry
so fuzz-repair / build-help / report-translation no longer each re-implement the
call. The verification path keeps using ``LLMClient`` (which owns the key pool +
cost tracking); this helper deliberately does NOT — the callers pass an already
provider-prefixed ``model`` and their derived ``api_key`` / ``api_base``.
"""

from __future__ import annotations

from typing import Any

import litellm

from vuln_hunter_x.core.validation import openai_compat_kwargs


def run_completion(
    *,
    messages: list[dict],
    model: str,
    provider: str,
    api_key: str | None = None,
    api_base: str | None = None,
    max_tokens: int,
    timeout: float,
    temperature: float | None = None,
    num_retries: int = 0,
) -> Any:
    """Call ``litellm.completion`` with consistent params + optional retry.

    ``temperature`` is omitted (provider default) when ``None``. When
    ``num_retries`` > 0, LiteLLM's exponential-backoff retry is enabled.
    """
    kwargs: dict[str, Any] = {
        "model": model,
        "messages": messages,
        "max_tokens": max_tokens,
        "timeout": timeout,
    }
    if temperature is not None:
        kwargs["temperature"] = temperature
    if api_base:
        kwargs["api_base"] = api_base
    if api_key:
        kwargs["api_key"] = api_key
    if num_retries:
        kwargs["num_retries"] = num_retries
        kwargs["retry_strategy"] = "exponential_backoff_retry"
    kwargs.update(
        openai_compat_kwargs(provider=provider, model=model, api_base=api_base, stream=False)
    )
    return litellm.completion(**kwargs)
