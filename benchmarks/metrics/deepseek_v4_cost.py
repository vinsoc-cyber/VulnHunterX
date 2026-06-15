# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Benchmark-only cost for DeepSeek V4 models LiteLLM cannot price yet.

LiteLLM's price table (1.86.2) tops out at ``deepseek-v3.2`` — it has no entry
for ``deepseek-v4-flash`` / ``deepseek-v4-pro``, so the pipeline's
``litellm.completion_cost()`` returns $0 for them. Rather than reintroduce
static pricing into the pipeline (``src/vuln_hunter_x``), we hard-code the two
V4 prices HERE, in the benchmark layer, and back-fill each result's cost from
its token counts after the run.

Self-disabling: ``backfill`` only fills rows whose ``cost_usd`` is still 0, so
once LiteLLM learns V4 its (non-zero) number is kept and this no-ops.

Prices: USD per 1,000,000 tokens, from https://api-docs.deepseek.com/quick_start/pricing
(snapshot 2026-06-01). v4-pro reflects the full list price.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

# (input_cache_miss, input_cache_hit, output) — USD per 1,000,000 tokens.
_V4_PRICES: dict[str, tuple[float, float, float]] = {
    "deepseek-v4-flash": (0.14, 0.0028, 0.28),
    "deepseek-v4-pro": (1.74, 0.0145, 3.48),
}

_PREFIXES = ("deepseek/", "openai/", "anthropic/")


def _normalize(model: str) -> str:
    """Strip a leading provider prefix so ``deepseek/deepseek-v4-flash`` and the
    bare ``deepseek-v4-flash`` both resolve."""
    m = (model or "").strip()
    for p in _PREFIXES:
        if m.startswith(p):
            return m[len(p) :]
    return m


def cost_usd(
    model: str,
    input_tokens: int,
    output_tokens: int,
    cached_input_tokens: int = 0,
) -> float | None:
    """USD cost for a hard-coded DeepSeek V4 model; ``None`` for any other model.

    Cache-hit input tokens are billed at the discounted tier; the remaining
    input tokens at the cache-miss rate.
    """
    prices = _V4_PRICES.get(_normalize(model))
    if prices is None:
        return None
    in_miss, in_hit, out = prices
    cached = max(0, min(cached_input_tokens, input_tokens))
    uncached = input_tokens - cached
    return (
        uncached / 1_000_000 * in_miss
        + cached / 1_000_000 * in_hit
        + output_tokens / 1_000_000 * out
    )


def backfill(model: str, results: Iterable[Any]) -> int:
    """Fill ``cost_usd`` for DeepSeek-V4 results that LiteLLM left at 0.

    Mutates each result in place. Returns the number of rows patched. Rows with
    a non-zero cost (LiteLLM priced them) or non-V4 models are left untouched.
    """
    patched = 0
    for r in results:
        if getattr(r, "cost_usd", 0.0):
            continue  # LiteLLM already priced it — keep that number.
        c = cost_usd(
            model,
            getattr(r, "input_tokens", 0) or 0,
            getattr(r, "output_tokens", 0) or 0,
            getattr(r, "cached_input_tokens", 0) or 0,
        )
        if c is not None and c > 0:
            r.cost_usd = c
            patched += 1
    return patched
