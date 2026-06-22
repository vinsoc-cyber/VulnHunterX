# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for absolute-line-number rendering of verifier code slices."""

from vuln_hunter_x.llm.prompts import render_code_for_prompt


def test_numbers_lines_with_absolute_offset_and_marks_flagged():
    code = "int a;\nfree(buff1);\nreturn a;"
    out = render_code_for_prompt(code, start_line=60, flagged_line=61)
    assert "→ 61: free(buff1);" in out
    assert "  60: int a;" in out
    assert "  62: return a;" in out


def test_flagged_line_outside_slice_emits_note_and_no_marker():
    out = render_code_for_prompt("int a;\nint b;", start_line=10, flagged_line=99)
    assert "NOTE: flagged line 99 is NOT within this slice (lines 10-11)" in out
    assert "→" not in out


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
