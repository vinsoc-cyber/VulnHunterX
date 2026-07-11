# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""#148 — request_second_opinion must route through _completion (key rotation),
not call litellm.completion directly (which under a pool gets neither rotation
nor retry, silently returning the prior verdict)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import litellm

from vuln_hunter_x.core.types import Finding, GuidedQuestions, Verdict
from vuln_hunter_x.llm.client import LLMClient

_JSON = (
    '{"verdict":"True Positive","confidence":"High","confidence_score":0.9,'
    '"answers":[],"reasoning":"r","data_flow":"","context_needed":[]}'
)


def _client() -> LLMClient:
    """A bare LLMClient with only the attributes request_second_opinion reads."""
    c = LLMClient.__new__(LLMClient)
    c.prompt_builder = MagicMock()
    c.model = "gpt-4o"
    c.temperature = 0.0
    c.max_tokens = 256
    c.request_timeout = 30
    c.provider = "openai"
    c._key_pool = None
    c._single_key = None
    c.num_retries = 0
    c._is_ollama_cloud = False
    return c


def _fake_resp() -> SimpleNamespace:
    return SimpleNamespace(
        choices=[SimpleNamespace(message=SimpleNamespace(content=_JSON))],
        usage=SimpleNamespace(
            total_tokens=10, prompt_tokens=8, completion_tokens=2,
            prompt_tokens_details=SimpleNamespace(cached_tokens=0),
        ),
    )


def test_second_opinion_dispatches_through_completion(monkeypatch) -> None:
    c = _client()
    resp = _fake_resp()
    calls = {"wrapper": 0, "raw": 0}

    def fake_wrapper(kwargs):
        calls["wrapper"] += 1
        return resp

    def fake_raw(**kwargs):
        calls["raw"] += 1
        return resp

    monkeypatch.setattr(c, "_completion", fake_wrapper)
    monkeypatch.setattr(litellm, "completion", fake_raw)

    finding = Finding(rule_id="r", message="", file="f.php", start_line=1,
                      end_line=1, repo_name="app", lang="php", cwe_ids=["CWE-22"])
    prev = Verdict(finding=finding, verdict="False Positive", confidence="Low",
                   reasoning="", answers=[], raw_response="", model="m",
                   confidence_score=0.2)

    result = c.request_second_opinion(
        finding=finding, context="code",
        questions=GuidedQuestions(rule_id="r", short_description="d", questions=["q"]),
        func_name="fn",
        previous_verdict=prev,
    )

    assert calls["wrapper"] == 1   # dispatched through the retry/rotation wrapper
    assert calls["raw"] == 0       # never called litellm.completion directly
    assert result.verdict == "True Positive"  # the wrapper's response was used
