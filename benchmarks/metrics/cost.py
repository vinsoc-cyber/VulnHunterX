# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Cost reporting for benchmark evaluation.

Implements the dual-column cost model required for Q1-journal cost
transparency:

  - local_marginal_cost_usd : actual USD paid (≈ 0 for local Ollama; the
                              value litellm.completion_cost reports).
  - imputed_api_cost_usd    : tokens × an API list-pricing schedule. Lets
                              reviewers re-cost the same token count under
                              any provider's pricing without re-running.

The pricing schedule is plain JSON so reviewers do not have to read code
to verify our cost claims. Two formats are supported:

  Flat (single model):
    {"input": 0.5, "output": 1.5, "currency": "USD", "unit": "per_1m_tokens"}

  Per-model:
    {
      "qwen3-max": {"input": 0.5, "output": 1.5},
      "claude-opus-4.7": {"input": 15.0, "output": 75.0}
    }

Pricing values are in USD per 1,000,000 tokens (the de-facto API list-
pricing unit). All standard providers publish in this unit; reviewers only
need to copy figures from a vendor pricing page.

Optional cache-hit tier (DeepSeek, etc.):
  {"input": 0.27, "input_cache_hit": 0.07, "output": 1.10}

When ``input_cache_hit`` is set, ``imputed_cost(...)`` honours an
``input_cached_tokens`` argument so cache-hit input tokens are billed at
the lower rate. DeepSeek's cache-hit rate is ~26% of cache-miss, so
ignoring it can be a 2–4× error per call when prompt-cache reuse is high.
``local_marginal_cost_usd`` (LiteLLM-reported) may diverge from
``imputed_api_cost_usd`` for DeepSeek because LiteLLM's built-in pricing
table does not always split cache tiers; the imputed value is the
authoritative one for the paper.

Top-level keys beginning with ``_`` (e.g. ``_source``, ``_note``) are
treated as documentation and ignored.

Provider-prefix robustness: ``resolve_pricing`` accepts both
``"deepseek-chat"`` and the LiteLLM-style ``"deepseek/deepseek-chat"`` —
the leading ``provider/`` segment is stripped before lookup if no exact
or prefix match is found.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Pricing:
    """USD per 1,000,000 tokens for one model.

    ``input_cache_hit_per_million`` is optional. When set, callers may
    pass ``input_cached_tokens`` to ``cost(...)`` to bill those tokens
    at the discounted rate; the remaining (``input_tokens -
    input_cached_tokens``) are billed at ``input_per_million``.
    """

    input_per_million: float
    output_per_million: float
    input_cache_hit_per_million: float | None = None

    def cost(
        self,
        input_tokens: int,
        output_tokens: int,
        input_cached_tokens: int = 0,
    ) -> float:
        if input_cached_tokens < 0:
            input_cached_tokens = 0
        if input_cached_tokens > input_tokens:
            input_cached_tokens = input_tokens
        if self.input_cache_hit_per_million is not None and input_cached_tokens > 0:
            uncached = input_tokens - input_cached_tokens
            i = (
                (uncached / 1_000_000.0) * self.input_per_million
                + (input_cached_tokens / 1_000_000.0) * self.input_cache_hit_per_million
            )
        else:
            i = (input_tokens / 1_000_000.0) * self.input_per_million
        o = (output_tokens / 1_000_000.0) * self.output_per_million
        return i + o


# Reference pricing snapshots (USD / 1M tokens) for the models the
# benchmark has historically used. These are documented defaults; the
# `--pricing <file>` CLI flag overrides them. Sources cited in the paper.
DEFAULT_PRICING: dict[str, Pricing] = {
    # Qwen3 family — Alibaba Cloud official list pricing snapshot (2026-01).
    "qwen3-max":         Pricing(0.50, 1.50),
    "qwen3-max-2026-01-23": Pricing(0.50, 1.50),
    "qwen3-coder-flash": Pricing(0.30, 0.90),
    "qwen3-coder-next":  Pricing(0.40, 1.20),
    "qwen-flash":        Pricing(0.20, 0.60),
    "qwen3-8b":          Pricing(0.10, 0.30),
    "qwen3.5-plus":      Pricing(0.40, 1.20),
    "qwen3.5-122b-a10b": Pricing(0.50, 1.50),
    # OpenAI list pricing (USD / 1M tokens). Cache-hit input billed at
    # 50% of cache-miss for cache-eligible models. Sources: OpenAI public
    # pricing page (snapshot 2026-01).
    "gpt-4-turbo":       Pricing(10.00, 30.00),  # legacy: no cache discount
    "gpt-4o":            Pricing(2.50, 10.00, input_cache_hit_per_million=1.25),
    "gpt-4o-mini":       Pricing(0.15, 0.60,  input_cache_hit_per_million=0.075),
    "gpt-4.1":           Pricing(2.00, 8.00,  input_cache_hit_per_million=0.50),
    "gpt-4.1-mini":      Pricing(0.40, 1.60,  input_cache_hit_per_million=0.10),
    "gpt-4.1-nano":      Pricing(0.10, 0.40,  input_cache_hit_per_million=0.025),
    # Reasoning models — list pricing as of 2026-01 snapshot.
    "o1":                Pricing(15.00, 60.00, input_cache_hit_per_million=7.50),
    "o3":                Pricing(2.00, 8.00,  input_cache_hit_per_million=0.50),
    "o3-mini":           Pricing(1.10, 4.40,  input_cache_hit_per_million=0.55),
    "o4-mini":           Pricing(1.10, 4.40,  input_cache_hit_per_million=0.275),
    # Anthropic Claude — NOTE: Anthropic prompt caching uses a
    # write-penalty model (cache writes cost 1.25-2x normal input;
    # reads are 0.1x). The current Pricing dataclass only models
    # cache-hit discounts, so these entries reflect uncached rates only.
    # Imputed cost for Claude with heavy cache reuse will be slightly
    # over-estimated; honest modelling tracked as a future refactor.
    "claude-opus-4.7":   Pricing(15.00, 75.00),
    "claude-sonnet-4.6": Pricing(3.00, 15.00),
    "claude-haiku-4.5":  Pricing(1.00, 5.00),
    # DeepSeek (standard tier, UTC 00:30-16:30). Cache-hit input billed
    # at ~26% of cache-miss; off-peak discount not modelled.
    "deepseek-chat":     Pricing(0.27, 1.10, input_cache_hit_per_million=0.07),
    "deepseek-reasoner": Pricing(0.55, 2.19, input_cache_hit_per_million=0.14),
}


def _parse_entry(entry: dict[str, Any], model: str) -> Pricing:
    return Pricing(
        input_per_million=float(entry["input"]),
        output_per_million=float(entry["output"]),
        input_cache_hit_per_million=(
            float(entry["input_cache_hit"]) if "input_cache_hit" in entry else None
        ),
    )


def load_pricing(
    path: str | Path | None = None,
) -> dict[str, Pricing] | Pricing:
    """Load a pricing schedule from JSON, or return DEFAULT_PRICING.

    Returns either a single ``Pricing`` (flat schema) or a dict keyed by
    model name. Callers should use ``resolve_pricing`` to pick the right
    one for a model. Top-level keys beginning with ``_`` are ignored
    (used for documentation, e.g. ``_source``, ``_unit``, ``_note``).
    """
    if path is None:
        return dict(DEFAULT_PRICING)
    p = Path(path)
    if not p.is_file():
        raise FileNotFoundError(f"Pricing file not found: {p}")
    data: dict[str, Any] = json.loads(p.read_text())
    # Flat schema?
    if "input" in data and "output" in data:
        return _parse_entry(data, "<flat>")
    # Per-model schema.
    result: dict[str, Pricing] = {}
    for model, prices in data.items():
        if model.startswith("_"):
            continue  # documentation key
        if not isinstance(prices, dict):
            raise ValueError(
                f"Invalid pricing entry for {model!r}: expected dict, got {type(prices).__name__}"
            )
        result[model] = _parse_entry(prices, model)
    return result


def resolve_pricing(
    schedule: dict[str, Pricing] | Pricing,
    model: str,
) -> Pricing | None:
    """Pick the pricing record for ``model`` from a schedule.

    Lookup order:
      1. Flat schedule -> always wins.
      2. Exact match on ``model``.
      3. Longest key in schedule that is a prefix of ``model``
         (e.g., ``"qwen3-max"`` matches ``"qwen3-max-2026-01-23"``).
      4. If ``model`` looks like ``"<provider>/<name>"``, retry steps 2–3
         with the ``provider/`` prefix stripped (handles LiteLLM-style
         ids like ``"deepseek/deepseek-chat"``).

    Returns None when nothing matches and the schedule is per-model.
    """
    if isinstance(schedule, Pricing):
        return schedule

    def _lookup(name: str) -> Pricing | None:
        if name in schedule:
            return schedule[name]
        candidates = [k for k in schedule if name.startswith(k)]
        if candidates:
            return schedule[max(candidates, key=len)]
        return None

    hit = _lookup(model)
    if hit is not None:
        return hit
    # Strip LiteLLM-style "<provider>/" prefix and retry.
    if "/" in model:
        return _lookup(model.split("/", 1)[1])
    return None


def imputed_cost(
    input_tokens: int,
    output_tokens: int,
    schedule: dict[str, Pricing] | Pricing,
    model: str,
    input_cached_tokens: int = 0,
) -> float | None:
    """Imputed API cost in USD; None if no pricing record matches.

    ``input_cached_tokens`` is the count (subset of ``input_tokens``)
    that hit the provider's prompt cache. If the matched ``Pricing`` has
    no ``input_cache_hit_per_million`` set, this argument is ignored
    (cached tokens are billed at the regular input rate, preserving
    back-compat).
    """
    p = resolve_pricing(schedule, model)
    if p is None:
        return None
    return p.cost(input_tokens, output_tokens, input_cached_tokens=input_cached_tokens)
