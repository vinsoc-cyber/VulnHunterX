# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Tests for benchmarks.metrics.cost (dual-column local + imputed pricing)."""

from __future__ import annotations

import json
import math

import pytest

from benchmarks.metrics.cost import (
    DEFAULT_PRICING,
    Pricing,
    imputed_cost,
    load_pricing,
    resolve_pricing,
)


def test_pricing_cost_basic():
    p = Pricing(input_per_million=1.0, output_per_million=2.0)
    # 1M input + 1M output = $1 + $2 = $3.
    assert math.isclose(p.cost(1_000_000, 1_000_000), 3.0)
    # 500k input + 250k output = 0.5 + 0.5 = $1.
    assert math.isclose(p.cost(500_000, 250_000), 1.0)
    assert p.cost(0, 0) == 0.0


def test_load_pricing_default():
    schedule = load_pricing()
    assert isinstance(schedule, dict)
    assert "qwen3-max" in schedule
    assert isinstance(schedule["qwen3-max"], Pricing)


def test_load_pricing_flat(tmp_path):
    f = tmp_path / "pricing.json"
    f.write_text(json.dumps({"input": 0.5, "output": 1.5}))
    p = load_pricing(f)
    assert isinstance(p, Pricing)
    assert math.isclose(p.input_per_million, 0.5)


def test_load_pricing_per_model(tmp_path):
    f = tmp_path / "pricing.json"
    f.write_text(json.dumps({
        "model-a": {"input": 1.0, "output": 2.0},
        "model-b": {"input": 5.0, "output": 10.0},
    }))
    schedule = load_pricing(f)
    assert isinstance(schedule, dict)
    assert "model-a" in schedule and "model-b" in schedule
    assert math.isclose(schedule["model-a"].output_per_million, 2.0)


def test_load_pricing_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_pricing(tmp_path / "no-such-file.json")


def test_load_pricing_invalid_per_model_entry(tmp_path):
    f = tmp_path / "pricing.json"
    # Entry value is a string, not a dict — should error.
    f.write_text(json.dumps({"model-a": "1.0"}))
    with pytest.raises(ValueError):
        load_pricing(f)


def test_resolve_pricing_flat_always_wins():
    p = Pricing(0.1, 0.2)
    # Flat pricing is the same regardless of model name.
    assert resolve_pricing(p, "anything") is p


def test_resolve_pricing_exact_match():
    schedule = {"qwen3-max": Pricing(0.5, 1.5)}
    assert resolve_pricing(schedule, "qwen3-max").input_per_million == 0.5


def test_resolve_pricing_longest_prefix():
    # "qwen3-max-2026-01-23" should match "qwen3-max" (longest available).
    schedule = {
        "qwen3":     Pricing(0.10, 0.30),
        "qwen3-max": Pricing(0.50, 1.50),
    }
    p = resolve_pricing(schedule, "qwen3-max-2026-01-23")
    assert p is not None
    assert math.isclose(p.input_per_million, 0.50)


def test_resolve_pricing_no_match():
    schedule = {"foo": Pricing(0.1, 0.2)}
    assert resolve_pricing(schedule, "bar") is None


def test_imputed_cost_returns_none_when_no_match():
    schedule = {"foo": Pricing(0.1, 0.2)}
    assert imputed_cost(1000, 1000, schedule, "bar") is None


def test_imputed_cost_qwen3_max_default_pricing():
    """At default pricing, 1M input + 1M output for qwen3-max = $0.50 + $1.50 = $2.00."""
    cost = imputed_cost(
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        schedule=DEFAULT_PRICING,
        model="qwen3-max",
    )
    assert cost is not None
    assert math.isclose(cost, 2.0)


# ---- DeepSeek + cache-hit tier ----

def _project_root():
    """Locate repo root by walking up from this test file."""
    from pathlib import Path

    here = Path(__file__).resolve()
    for parent in [here.parent, *here.parents]:
        if (parent / "pricing.deepseek.json").is_file():
            return parent
    raise RuntimeError("Could not locate pricing.deepseek.json from test file")


def test_load_pricing_deepseek_json_real_file():
    """The shipped pricing.deepseek.json must load cleanly and carry cache-hit rates."""
    schedule = load_pricing(_project_root() / "pricing.deepseek.json")
    assert isinstance(schedule, dict)
    chat = schedule["deepseek-chat"]
    assert math.isclose(chat.input_per_million, 0.27)
    assert math.isclose(chat.output_per_million, 1.10)
    assert chat.input_cache_hit_per_million is not None
    assert math.isclose(chat.input_cache_hit_per_million, 0.07)
    reasoner = schedule["deepseek-reasoner"]
    assert math.isclose(reasoner.input_per_million, 0.55)
    assert math.isclose(reasoner.output_per_million, 2.19)
    # Documentation keys (_source, _unit, _note) must be filtered out.
    assert all(not k.startswith("_") for k in schedule)


def test_load_pricing_ignores_underscore_keys(tmp_path):
    f = tmp_path / "pricing.json"
    f.write_text(json.dumps({
        "_source": "https://example.com",
        "_unit": "per_1m_tokens",
        "model-a": {"input": 1.0, "output": 2.0},
    }))
    schedule = load_pricing(f)
    assert isinstance(schedule, dict)
    assert "_source" not in schedule
    assert "model-a" in schedule


def test_imputed_cost_deepseek_no_cache():
    """1M input cache-miss + 1M output for deepseek-chat = $0.27 + $1.10 = $1.37."""
    schedule = load_pricing(_project_root() / "pricing.deepseek.json")
    cost = imputed_cost(
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        schedule=schedule,
        model="deepseek-chat",
    )
    assert cost is not None
    assert math.isclose(cost, 0.27 + 1.10)


def test_imputed_cost_deepseek_with_cache_hit():
    """80% cache-hit: 0.8 * $0.07 + 0.2 * $0.27 (no output)."""
    schedule = load_pricing(_project_root() / "pricing.deepseek.json")
    cost = imputed_cost(
        input_tokens=1_000_000,
        output_tokens=0,
        schedule=schedule,
        model="deepseek-chat",
        input_cached_tokens=800_000,
    )
    assert cost is not None
    expected = 0.8 * 0.07 + 0.2 * 0.27
    assert math.isclose(cost, expected, rel_tol=1e-9)


def test_imputed_cost_deepseek_provider_prefix():
    """LiteLLM-style 'deepseek/deepseek-chat' must resolve to the same pricing."""
    schedule = load_pricing(_project_root() / "pricing.deepseek.json")
    a = imputed_cost(1_000_000, 1_000_000, schedule, "deepseek-chat")
    b = imputed_cost(1_000_000, 1_000_000, schedule, "deepseek/deepseek-chat")
    assert a is not None and b is not None
    assert math.isclose(a, b)


def test_resolve_pricing_strips_provider_prefix():
    """resolve_pricing falls back to stripping <provider>/ when no direct match."""
    schedule = {"deepseek-chat": Pricing(0.27, 1.10, input_cache_hit_per_million=0.07)}
    p = resolve_pricing(schedule, "deepseek/deepseek-chat")
    assert p is not None
    assert math.isclose(p.input_per_million, 0.27)


def test_pricing_cache_hit_back_compat_when_unset():
    """A Pricing without input_cache_hit_per_million bills cached tokens at the regular input rate."""
    p = Pricing(input_per_million=1.0, output_per_million=0.0)
    # 1M input, 800k of them "cached" — but no cache-hit rate set, so all
    # 1M billed at $1.0/M = $1.0 (back-compat preserved).
    assert math.isclose(p.cost(1_000_000, 0, input_cached_tokens=800_000), 1.0)


def test_default_pricing_includes_gpt_4o_mini():
    """Regression: gpt-4o-mini was previously absent, making imputed_cost return None."""
    assert "gpt-4o-mini" in DEFAULT_PRICING
    p = DEFAULT_PRICING["gpt-4o-mini"]
    assert math.isclose(p.input_per_million, 0.15)
    assert math.isclose(p.output_per_million, 0.60)
    assert p.input_cache_hit_per_million is not None
    assert math.isclose(p.input_cache_hit_per_million, 0.075)


def test_imputed_cost_gpt_4o_mini_with_cache_hit():
    """50% cache-hit: 0.5 * $0.075 + 0.5 * $0.15 input + $0.60 output."""
    cost = imputed_cost(
        input_tokens=1_000_000,
        output_tokens=1_000_000,
        schedule=DEFAULT_PRICING,
        model="gpt-4o-mini",
        input_cached_tokens=500_000,
    )
    assert cost is not None
    expected = 0.5 * 0.075 + 0.5 * 0.15 + 0.60
    assert math.isclose(cost, expected, rel_tol=1e-9)


def test_load_pricing_openai_json_real_file():
    """The shipped pricing.openai.json must load cleanly with cache-hit fields."""
    schedule = load_pricing(_project_root() / "pricing.openai.json")
    assert isinstance(schedule, dict)
    mini = schedule["gpt-4o-mini"]
    assert math.isclose(mini.input_per_million, 0.15)
    assert math.isclose(mini.output_per_million, 0.60)
    assert mini.input_cache_hit_per_million is not None
    assert math.isclose(mini.input_cache_hit_per_million, 0.075)
    # gpt-4-turbo is legacy and has no cache discount in the JSON.
    legacy = schedule["gpt-4-turbo"]
    assert legacy.input_cache_hit_per_million is None
    # LiteLLM-style provider prefix should resolve to the same pricing.
    a = imputed_cost(1_000_000, 1_000_000, schedule, "gpt-4o-mini")
    b = imputed_cost(1_000_000, 1_000_000, schedule, "openai/gpt-4o-mini")
    assert a is not None and b is not None
    assert math.isclose(a, b)


def test_pricing_cache_hit_clamps_cached_to_input():
    """input_cached_tokens > input_tokens is clamped (no negative uncached count)."""
    p = Pricing(1.0, 0.0, input_cache_hit_per_million=0.1)
    # Claim 2M cached but only 1M input -> clamp to 1M cached, 0 uncached.
    cost = p.cost(1_000_000, 0, input_cached_tokens=2_000_000)
    assert math.isclose(cost, 0.1)


class TestAutoPricing:
    def test_known_paid_models_resolve(self):
        from benchmarks.metrics.cost import auto_pricing

        assert auto_pricing("gpt-4.1") is not None
        assert auto_pricing("gpt-5") is not None
        assert auto_pricing("deepseek-chat") is not None
        assert auto_pricing("deepseek-reasoner") is not None

    def test_ollama_models_are_zero_cost(self):
        from benchmarks.metrics.cost import auto_pricing

        p = auto_pricing("ollama/qwen3-coder:480b-cloud")
        assert p is not None
        assert p.input_per_million == 0.0
        assert p.output_per_million == 0.0

    def test_unknown_paid_model_returns_none(self):
        from benchmarks.metrics.cost import auto_pricing

        assert auto_pricing("definitely-not-a-real-model-xyz") is None

    def test_imputed_cost_zero_for_local(self):
        from benchmarks.metrics.cost import DEFAULT_PRICING, imputed_cost

        c = imputed_cost(1000, 500, DEFAULT_PRICING, "ollama/llama3.2")
        assert c == 0.0
