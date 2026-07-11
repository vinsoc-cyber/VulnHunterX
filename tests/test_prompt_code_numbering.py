# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for absolute-line-number rendering of verifier code slices."""

import inspect
from unittest.mock import MagicMock, patch

from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.llm.prompts import PromptBuilder, render_code_for_prompt


def test_numbers_lines_with_absolute_offset_and_marks_flagged():
    code = "int a;\nfree(buff1);\nreturn a;"
    out = render_code_for_prompt(code, start_line=60, flagged_line=61)
    assert "→ 61: free(buff1);" in out
    assert "  60: int a;" in out
    assert "  62: return a;" in out


def test_flagged_line_outside_slice_emits_note_and_no_marker():
    out = render_code_for_prompt("int a;\nint b;", start_line=10, flagged_line=99)
    assert "NOTE: flagged line 99 is NOT within this slice (lines 10-11)" in out
    assert not any(line.startswith("→") for line in out.splitlines())


def test_window_trims_around_flagged_line_keeping_absolute_numbers():
    code = "\n".join(f"line{n}" for n in range(1, 21))  # file lines 1..20
    out = render_code_for_prompt(code, start_line=1, flagged_line=10, window=2)
    assert "→ 10: line10" in out
    assert "  8: line8" in out
    assert "  12: line12" in out
    assert "line7" not in out
    assert "line13" not in out
    assert "windowed around flagged line 10" in out


def test_empty_code_returns_unchanged():
    assert render_code_for_prompt("", start_line=5, flagged_line=5) == ""


def test_marks_first_line_when_flagged_is_start():
    out = render_code_for_prompt("a();\nb();", start_line=42, flagged_line=42)
    assert "→ 42: a();" in out
    assert "  43: b();" in out


def test_start_line_below_one_clamps_to_one():
    out = render_code_for_prompt("a();\nb();", start_line=0, flagged_line=1)
    assert "→ 1: a();" in out
    assert "  2: b();" in out


def test_build_user_prompt_numbers_and_marks_flagged_line():
    builder = PromptBuilder()
    finding = Finding(
        rule_id="cpp/double-free",
        message="double free of buff1",
        file="imgRead.c",
        start_line=62,
        end_line=62,
        repo_name="dvcp",
        lang="cpp",
    )
    questions = GuidedQuestions(
        rule_id="cpp/double-free",
        short_description="double free",
        questions=["Is buff1 freed twice?"],
        context_hint="",
    )
    # Slice starts at file line 61, so line 62 is "free(buff1);".
    code = "void ProcessImage() {\nfree(buff1);\n}"
    prompt = builder.build_user_prompt(
        finding, code, questions, "ProcessImage", context_start_line=61
    )
    assert "→ 62: free(buff1);" in prompt
    assert "  61: void ProcessImage() {" in prompt
    assert "cpp/double-free" in prompt  # existing finding metadata still present


def test_client_methods_accept_context_start_line():
    for name in ("analyze", "analyze_with_voting", "request_second_opinion"):
        params = inspect.signature(getattr(LLMClient, name)).parameters
        assert "context_start_line" in params, f"{name} missing context_start_line"


@patch("vuln_hunter_x.llm.client.litellm.completion")
def test_analyze_forwards_context_start_line_to_build_user_prompt(mock_completion):
    """Behavioral test: analyze() must forward context_start_line to build_user_prompt."""
    choice = MagicMock()
    choice.message.content = '{"verdict": "True Positive", "confidence": "High", "reasoning": "r", "answers": []}'
    mock_completion.return_value = MagicMock(choices=[choice])

    client = LLMClient(provider="openai", model="gpt-4o")
    client.prompt_builder.build_user_prompt = MagicMock(return_value="<prompt>")

    finding = Finding(
        rule_id="cpp/double-free",
        message="double free",
        file="src/buf.c",
        start_line=42,
        end_line=42,
        repo_name="myrepo",
        lang="c",
    )
    questions = GuidedQuestions(
        rule_id="cpp/double-free",
        short_description="double free",
        questions=["Is buff freed twice?"],
        context_hint="",
    )

    client.analyze(
        finding=finding,
        context="void f() { free(p); free(p); }",
        questions=questions,
        func_name="f",
        max_iterations=1,
        quiet=True,
        context_start_line=99,
    )

    call = client.prompt_builder.build_user_prompt.call_args
    # context_start_line is the 5th positional arg (index 4) or keyword arg
    positional_value = call.args[4] if len(call.args) > 4 else None
    keyword_value = call.kwargs.get("context_start_line")
    actual = positional_value if positional_value is not None else keyword_value
    assert actual == 99, (
        f"build_user_prompt was called with context_start_line={actual!r}, expected 99"
    )


def test_system_prompt_has_locate_and_quote_guard():
    sp = PromptBuilder().get_system_prompt(tool_name="CodeQL", lang="cpp")
    assert "LOCATE the flagged line" in sp
    assert "Needs More Data" in sp


def test_force_decision_prompt_is_consequence_first():
    from vuln_hunter_x.llm.client import LLMClient
    fd = LLMClient._FORCE_DECISION_PROMPT
    assert "lean toward True Positive" not in fd  # old absence-of-defense thumb gone
    assert "decide by CONSEQUENCE at the flagged sink" in fd  # new impact-first guideline
    assert "EXCEPTION for correctness" in fd  # correctness-rule carve-out preserved


def test_system_prompt_rule_is_locator_not_straitjacket():
    sp = PromptBuilder().get_system_prompt(tool_name="Semgrep", lang="php")  # live (YAML)
    assert "LOCATES a suspicious sink" in sp
    assert 'NEVER return "True Positive" for a vulnerability class other than' not in sp
    assert "LOCATE the flagged line" in sp and "Needs More Data" in sp  # #118 guards preserved


def test_rule_scope_reframe_in_live_prompt():
    # The single packaged prompt carries the locator reframe and has dropped the
    # old cross-class prohibition (DEFAULT_SYSTEM_PROMPT fallback removed, #144).
    sp = PromptBuilder().get_system_prompt(tool_name="Semgrep", lang="php")
    assert "LOCATES a suspicious sink" in sp
    assert "do not relabel" not in sp
    assert 'NEVER return "True Positive" for a vulnerability class other than' not in sp
