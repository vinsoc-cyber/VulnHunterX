"""Tests for LLMClient (multi-turn verification with LiteLLM)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient


@pytest.fixture()
def finding():
    return Finding(
        rule_id="cpp/use-after-free",
        message="Use of pointer after free",
        file="src/buf.c",
        start_line=42,
        end_line=42,
        repo_name="myrepo",
        lang="c",
    )


@pytest.fixture()
def questions():
    return GuidedQuestions(
        rule_id="cpp/use-after-free",
        short_description="Use-after-free",
        questions=["Is the pointer freed before use?", "What is the lifetime?"],
        context_hint="Check allocation and free",
    )


def _make_litellm_response(content: str):
    choice = MagicMock()
    choice.message.content = content
    response = MagicMock()
    response.choices = [choice]
    return response


def _make_empty_choices_response():
    response = MagicMock()
    response.choices = []
    return response


class TestLLMClientParseResponse:
    """Unit tests for _parse_response — the 4 fallback JSON parsing strategies."""

    def setup_method(self):
        self.client = LLMClient()

    def test_parse_markdown_json_block(self):
        raw = '```json\n{"verdict": "True Positive", "confidence": "High", "reasoning": "r", "answers": []}\n```'
        result = self.client._parse_response(raw)
        assert result["verdict"] == "True Positive"
        assert result["confidence"] == "High"

    def test_parse_direct_json(self):
        raw = '{"verdict": "False Positive", "confidence": "Medium", "reasoning": "r", "answers": []}'
        result = self.client._parse_response(raw)
        assert result["verdict"] == "False Positive"

    def test_parse_embedded_json_object(self):
        raw = 'Some preamble text {"verdict": "Needs More Data", "confidence": "Low", "reasoning": "r", "answers": [], "context_needed": ["caller:foo"]} trailing text'
        result = self.client._parse_response(raw)
        assert result["verdict"] == "Needs More Data"
        assert "caller:foo" in result.get("context_needed", [])

    def test_parse_manual_fallback_true_positive(self):
        raw = "The code has a use-after-free. I believe this is a True Positive with High confidence."
        result = self.client._parse_response(raw)
        assert result["verdict"] == "True Positive"

    def test_parse_manual_fallback_false_positive(self):
        raw = "After careful analysis, this is a False Positive."
        result = self.client._parse_response(raw)
        assert result["verdict"] == "False Positive"

    def test_parse_returns_needs_more_data_for_garbage(self):
        raw = "this is completely unparseable garbage @#$%"
        result = self.client._parse_response(raw)
        assert result["verdict"] == "Needs More Data"
        assert "confidence" in result
        assert "reasoning" in result

    def test_parse_markdown_block_without_json_label(self):
        raw = '```\n{"verdict": "True Positive", "confidence": "Low", "reasoning": "ok", "answers": []}\n```'
        result = self.client._parse_response(raw)
        assert result["verdict"] == "True Positive"


class TestLLMClientAnalyze:
    """Tests for analyze() — the main multi-turn flow."""

    def setup_method(self):
        self.client = LLMClient(provider="openai", model="gpt-4o")

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_single_turn_true_positive(self, mock_completion, finding, questions):
        mock_completion.return_value = _make_litellm_response(
            '{"verdict": "True Positive", "confidence": "High", "reasoning": "confirmed", "answers": ["yes"]}'
        )

        verdict = self.client.analyze(
            finding=finding,
            context="void free_it(char *p) { free(p); use(p); }",
            questions=questions,
            func_name="free_it",
            max_iterations=3,
            quiet=True,
        )

        assert verdict.verdict == "True Positive"
        assert verdict.confidence == "High"
        assert verdict.iterations == 1
        mock_completion.assert_called_once()

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_empty_choices_raises_and_returns_error_verdict(self, mock_completion, finding, questions):
        mock_completion.return_value = _make_empty_choices_response()

        verdict = self.client.analyze(
            finding=finding,
            context="code",
            questions=questions,
            func_name="func",
            max_iterations=1,
            quiet=True,
        )

        assert verdict.verdict == "Error"
        assert "empty choices" in verdict.reasoning.lower()

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_max_iterations_returns_needs_more_data(self, mock_completion, finding, questions):
        mock_completion.return_value = _make_litellm_response(
            '{"verdict": "Needs More Data", "confidence": "Low", "reasoning": "need caller", "answers": [], "context_needed": ["caller:foo"]}'
        )

        verdict = self.client.analyze(
            finding=finding,
            context="code",
            questions=questions,
            func_name="func",
            context_provider=None,
            max_iterations=2,
            quiet=True,
        )

        assert verdict.verdict == "Needs More Data"
        # Without context_provider, exits on first iteration even with context_needed
        assert verdict.iterations == 1

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_multi_turn_expands_context(self, mock_completion, finding, questions):
        first_response = _make_litellm_response(
            '{"verdict": "Needs More Data", "confidence": "Low", "reasoning": "need caller", "answers": [], "context_needed": ["caller:foo"]}'
        )
        second_response = _make_litellm_response(
            '{"verdict": "True Positive", "confidence": "High", "reasoning": "confirmed", "answers": ["yes"], "context_needed": []}'
        )
        mock_completion.side_effect = [first_response, second_response]

        mock_provider = MagicMock()
        mock_provider.get_additional_context.return_value = {
            "caller:foo": "void caller() { char *p = malloc(10); free_it(p); }"
        }

        verdict = self.client.analyze(
            finding=finding,
            context="code",
            questions=questions,
            func_name="func",
            context_provider=mock_provider,
            max_iterations=3,
            quiet=True,
        )

        assert verdict.verdict == "True Positive"
        assert verdict.iterations == 2
        mock_provider.get_additional_context.assert_called_once()

    @patch("vuln_hunter_x.llm.client.litellm.completion")
    def test_llm_exception_returns_error_verdict(self, mock_completion, finding, questions):
        mock_completion.side_effect = ConnectionError("Network unreachable")

        verdict = self.client.analyze(
            finding=finding,
            context="code",
            questions=questions,
            func_name="func",
            max_iterations=1,
            quiet=True,
        )

        assert verdict.verdict == "Error"
        assert "Network unreachable" in verdict.reasoning
