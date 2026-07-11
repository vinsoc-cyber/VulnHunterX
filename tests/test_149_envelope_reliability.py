# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""#149 — verifier envelope reliability.

Part A: a truncated/unparseable verdict body is retried once (bigger budget when
truncated) before it can silently become an abstention that force-decision then
launders into a verdict. Part B: response_format guarantees the JSON envelope
where supported, with graceful-degrade when a provider rejects it.
"""
from __future__ import annotations

from types import SimpleNamespace

import litellm

from vuln_hunter_x.llm.client import LLMClient

# ── raw bodies the real _parse_response will see ──────────────────────
TRUNC = '{"verdict": "True Positive", "confidence": "High"'          # unbalanced -> truncated
GOOD_TP = '{"verdict": "True Positive", "confidence": "High", "reasoning": "sqli"}'
GOOD_FP = '{"verdict": "False Positive", "confidence": "High", "reasoning": "safe"}'
NMD = '{"verdict": "Needs More Data", "confidence": "Low", "reasoning": "need caller"}'


def _delta(t: int) -> dict:
    return {"total_tokens": t, "input_tokens": t, "output_tokens": t,
            "cached_input_tokens": 0, "cost_usd": 0.0}


def _client_min() -> LLMClient:
    """Bare client with only what _complete_parse_retry reads."""
    c = LLMClient.__new__(LLMClient)
    c.max_tokens = 4096
    return c


def _client_kwargs() -> LLMClient:
    """Client with the attrs _build_completion_kwargs / _completion read."""
    c = LLMClient.__new__(LLMClient)
    c.model = "gpt-4o"
    c.provider = "openai"
    c.temperature = 0.0
    c.max_tokens = 4096
    c.request_timeout = 30
    c._key_pool = None
    c._single_key = None
    c.num_retries = 0
    c._is_ollama_cloud = False
    c._response_format_supported = True
    return c


# ── Part A: _complete_and_meter ───────────────────────────────────────
def test_complete_and_meter_extracts_usage(monkeypatch) -> None:
    c = _client_min()
    resp = SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=GOOD_TP))],
        usage=SimpleNamespace(total_tokens=100, prompt_tokens=80, completion_tokens=20,
                              prompt_tokens_details=SimpleNamespace(cached_tokens=5)),
    )
    monkeypatch.setattr(c, "_build_completion_kwargs", lambda messages, temperature=None: {"messages": messages})
    monkeypatch.setattr(c, "_completion", lambda kwargs: resp)
    monkeypatch.setattr(litellm, "completion_cost", lambda completion_response: 0.01)
    raw, delta = c._complete_and_meter([{"role": "user", "content": "x"}], 0.0)
    assert raw == GOOD_TP
    assert delta["total_tokens"] == 100
    assert delta["input_tokens"] == 80
    assert delta["output_tokens"] == 20
    assert delta["cached_input_tokens"] == 5
    assert delta["cost_usd"] == 0.01


def test_complete_and_meter_max_tokens_override(monkeypatch) -> None:
    c = _client_min()
    seen: dict = {}
    monkeypatch.setattr(c, "_build_completion_kwargs", lambda messages, temperature=None: {"max_tokens": 4096})
    resp = SimpleNamespace(choices=[SimpleNamespace(message=SimpleNamespace(content=GOOD_TP))], usage=None)

    def fake_completion(kwargs):
        seen.update(kwargs)
        return resp

    monkeypatch.setattr(c, "_completion", fake_completion)
    monkeypatch.setattr(litellm, "completion_cost", lambda completion_response: 0.0)
    c._complete_and_meter([], 0.0, max_tokens=8192)
    assert seen["max_tokens"] == 8192


# ── Part A: _complete_parse_retry ─────────────────────────────────────
def test_retry_on_truncated_then_success(monkeypatch) -> None:
    c = _client_min()
    seq = [(TRUNC, _delta(10)), (GOOD_TP, _delta(20))]
    calls: dict = {"n": 0, "max_tokens": []}

    def fake(messages, temperature, max_tokens=None):
        calls["n"] += 1
        calls["max_tokens"].append(max_tokens)
        return seq.pop(0)

    monkeypatch.setattr(c, "_complete_and_meter", fake)
    raw, parsed, delta = c._complete_parse_retry([], 0.0)
    assert calls["n"] == 2                       # retried once
    assert calls["max_tokens"][1] == 8192        # truncated -> bigger budget (capped)
    assert parsed["verdict"] == "True Positive"  # kept the good retry
    assert delta["total_tokens"] == 30           # usage summed


def test_no_retry_on_healthy(monkeypatch) -> None:
    c = _client_min()
    calls = {"n": 0}

    def fake(messages, temperature, max_tokens=None):
        calls["n"] += 1
        return (GOOD_FP, _delta(15))

    monkeypatch.setattr(c, "_complete_and_meter", fake)
    raw, parsed, delta = c._complete_parse_retry([], 0.0)
    assert calls["n"] == 1                        # no retry on a healthy body
    assert parsed["verdict"] == "False Positive"
    assert delta["total_tokens"] == 15


def test_no_retry_on_genuine_nmd(monkeypatch) -> None:
    c = _client_min()
    calls = {"n": 0}

    def fake(messages, temperature, max_tokens=None):
        calls["n"] += 1
        return (NMD, _delta(12))

    monkeypatch.setattr(c, "_complete_and_meter", fake)
    raw, parsed, delta = c._complete_parse_retry([], 0.0)
    assert calls["n"] == 1                        # NMD is a real answer, not parse_failed
    assert parsed["verdict"] == "Needs More Data"


def test_retry_still_truncated_keeps_abstention(monkeypatch) -> None:
    c = _client_min()
    seq = [(TRUNC, _delta(10)), (TRUNC, _delta(11))]

    def fake(messages, temperature, max_tokens=None):
        return seq.pop(0)

    monkeypatch.setattr(c, "_complete_and_meter", fake)
    raw, parsed, delta = c._complete_parse_retry([], 0.0)
    assert parsed.get("parse_failed") is True     # honest abstention after two tries
    assert parsed["verdict"] == "Needs More Data"
    assert delta["total_tokens"] == 21            # both calls counted


# ── Part B: response_format + graceful-degrade ────────────────────────
def test_response_format_present_for_openai(monkeypatch) -> None:
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)
    c = _client_kwargs()
    kw = c._build_completion_kwargs([{"role": "user", "content": "x"}])
    assert kw.get("response_format") == {"type": "json_object"}


def test_response_format_omitted_when_unsupported(monkeypatch) -> None:
    c = _client_kwargs()
    c._response_format_supported = False
    kw = c._build_completion_kwargs([{"role": "user", "content": "x"}])
    assert "response_format" not in kw


def test_graceful_degrade_on_response_format_rejection(monkeypatch) -> None:
    c = _client_kwargs()
    calls = {"n": 0}

    def fake_raw(kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            assert "response_format" in kwargs
            raise litellm.BadRequestError(
                "Unsupported parameter: 'response_format'", model="m", llm_provider="openai")
        assert "response_format" not in kwargs    # dropped on the retry
        return "OK"

    monkeypatch.setattr(c, "_completion_raw", fake_raw)
    out = c._completion({"model": "m", "response_format": {"type": "json_object"}})
    assert out == "OK"
    assert calls["n"] == 2
    assert c._response_format_supported is False   # disabled for the session
