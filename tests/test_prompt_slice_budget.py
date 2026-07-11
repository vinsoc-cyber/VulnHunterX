# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""#151 — an oversized enclosing-function slice is windowed to a char budget so
the assembled prompt can't overflow the context window (which would truncate the
response and force a spurious abstention). Small slices are untouched."""

from __future__ import annotations

from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.prompts import PromptBuilder


def _finding(line: int) -> Finding:
    return Finding(rule_id="r", message="", file="big.py", start_line=line,
                   end_line=line, repo_name="app", lang="python", cwe_ids=["CWE-89"])


def _q(window: int | None = None) -> GuidedQuestions:
    return GuidedQuestions(rule_id="r", short_description="d", questions=["q1"],
                           snippet_window_lines=window)


def test_small_slice_not_windowed() -> None:
    code = "\n".join(f"line {i}" for i in range(1, 20))
    out = PromptBuilder().build_user_prompt(
        _finding(10), code, _q(), "fn", context_start_line=1
    )
    assert "snippet windowed" not in out


def test_oversized_slice_is_windowed() -> None:
    # ~1000 lines * ~50 chars > the 24000-char budget; flagged line 500 mid-slice.
    code = "\n".join(
        f"    do_something_number_{i}()  # padding padding pad" for i in range(1, 1001)
    )
    out = PromptBuilder().build_user_prompt(
        _finding(500), code, _q(), "fn", context_start_line=1
    )
    assert "snippet windowed" in out   # budget guard fired
    assert "→ 500:" in out              # flagged line still present after windowing


def test_explicit_window_takes_precedence() -> None:
    code = "\n".join(f"    line_{i}" for i in range(1, 1001))
    out = PromptBuilder().build_user_prompt(
        _finding(500), code, _q(window=5), "fn", context_start_line=1
    )
    assert "showing lines 495-505" in out   # honored the explicit ±5, not the budget's window
