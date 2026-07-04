# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for the markdown report generator, focused on the Findings Overview section."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_hunter_x.core.types import (
    Finding,
    Verdict,
    VerdictType,
    VerificationResult,
)
from vuln_hunter_x.reporting.markdown import MarkdownReportGenerator


def _make_finding(rule_id: str, file: str, line: int, severity: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        message=f"fake message for {rule_id}",
        file=file,
        start_line=line,
        end_line=line,
        repo_name="demo",
        lang="c",
        severity=severity,
    )


def _make_verdict(
    rule_id: str,
    file: str,
    line: int,
    severity: str,
    verdict: str,
    confidence: str = "High",
) -> Verdict:
    return Verdict(
        finding=_make_finding(rule_id, file, line, severity),
        verdict=verdict,
        confidence=confidence,
        reasoning="because",
        answers=[],
        raw_response="",
        model="test-model",
    )


def _make_result(verdicts: list[Verdict]) -> VerificationResult:
    stats: dict[str, int] = {}
    for v in verdicts:
        stats[v.verdict] = stats.get(v.verdict, 0) + 1
    return VerificationResult(
        verdicts=verdicts,
        stats=stats,
        model="test-model",
        provider="test-provider",
        total_time_seconds=1.23,
    )


class TestFindingsOverviewSection:
    """The new per-finding before/after table inserted between Executive Summary and Severity Breakdown."""

    def test_section_header_present(self, tmp_path: Path):
        result = _make_result(
            [
                _make_verdict("cpp/uaf", "a.c", 10, "error", VerdictType.TRUE_POSITIVE.value),
            ]
        )
        out = MarkdownReportGenerator().generate(result, tmp_path / "r.md")
        body = out.read_text()
        assert "## Findings Overview" in body

    def _overview_section(self, body: str) -> str:
        """Slice the report content between Findings Overview and the next section."""
        after_header = body.split("## Findings Overview", 1)[1]
        # Next section starts at "## Severity Breakdown"
        return after_header.split("## Severity Breakdown", 1)[0]

    def test_one_row_per_verdict(self, tmp_path: Path):
        result = _make_result(
            [
                _make_verdict("cpp/uaf", "a.c", 10, "error", VerdictType.TRUE_POSITIVE.value),
                _make_verdict("cpp/bof", "b.c", 20, "warning", VerdictType.FALSE_POSITIVE.value),
                _make_verdict("cpp/null", "c.c", 30, "note", VerdictType.NEEDS_MORE_DATA.value),
            ]
        )
        body = MarkdownReportGenerator().generate(result, tmp_path / "r.md").read_text()
        overview = self._overview_section(body)
        data_rows = [
            ln for ln in overview.splitlines()
            if ln.startswith("|") and "/" in ln  # rows that contain a rule_id like "cpp/uaf"
        ]
        assert len(data_rows) == 3

    def test_sorted_by_severity_then_verdict(self, tmp_path: Path):
        # High-severity FP should still come before low-severity TP (severity wins).
        # Within the same severity, TP must come before FP.
        result = _make_result(
            [
                _make_verdict("low/tp", "x.c", 1, "note", VerdictType.TRUE_POSITIVE.value),
                _make_verdict("high/fp", "y.c", 2, "error", VerdictType.FALSE_POSITIVE.value),
                _make_verdict("high/tp", "z.c", 3, "error", VerdictType.TRUE_POSITIVE.value),
            ]
        )
        body = MarkdownReportGenerator().generate(result, tmp_path / "r.md").read_text()
        overview = self._overview_section(body)
        data_rows = [
            ln for ln in overview.splitlines()
            if ln.startswith("|") and "/" in ln  # rows that contain a rule_id like "high/tp"
        ]
        order = [next(c for c in row.split("|") if "/" in c).strip() for row in data_rows]
        assert order == ["high/tp", "high/fp", "low/tp"]

    def test_empty_result_does_not_emit_section(self, tmp_path: Path):
        result = _make_result([])
        body = MarkdownReportGenerator().generate(result, tmp_path / "r.md").read_text()
        # No verdicts → section omitted entirely, executive summary still renders.
        assert "## Findings Overview" not in body
        assert "Executive Summary" in body

    def test_vietnamese_header(self, tmp_path: Path):
        result = _make_result(
            [_make_verdict("cpp/uaf", "a.c", 10, "error", VerdictType.TRUE_POSITIVE.value)]
        )
        body = MarkdownReportGenerator().generate(
            result, tmp_path / "r_vi.md", report_lang="vi"
        ).read_text()
        assert "## Tổng quan phát hiện" in body
        assert "Mức độ (trước)" in body
        assert "Kết luận (sau)" in body

    def test_section_appears_before_severity_breakdown(self, tmp_path: Path):
        result = _make_result(
            [_make_verdict("cpp/uaf", "a.c", 10, "error", VerdictType.TRUE_POSITIVE.value)]
        )
        body = MarkdownReportGenerator().generate(result, tmp_path / "r.md").read_text()
        overview_pos = body.find("## Findings Overview")
        severity_pos = body.find("## Severity Breakdown")
        exec_pos = body.find("## Executive Summary")
        assert exec_pos < overview_pos < severity_pos


def test_translate_dynamic_text_bounds_litellm_call_with_timeout(monkeypatch):
    """#127: the opt-in translation path must pass an explicit timeout to
    litellm.completion. Otherwise the wall-clock guard fires but the still-running
    worker keeps litellm's default timeout, and shutdown(wait=True) re-blocks —
    deadlocking verify."""
    from types import SimpleNamespace

    import litellm

    from vuln_hunter_x.reporting.markdown import _translate_dynamic_text

    monkeypatch.setenv("OPENAI_API_KEY", "test-key")
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o")
    monkeypatch.delenv("OPENAI_BASE_URL", raising=False)
    monkeypatch.delenv("OPENAI_API_BASE", raising=False)

    captured: dict = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="[1] xin chào"))]
        )

    monkeypatch.setattr(litellm, "completion", fake_completion)

    result = _translate_dynamic_text(["hello"], "vi")

    assert captured.get("timeout") is not None
    assert result == ["xin chào"]


def test_translate_dynamic_text_gemini_uses_native_route_and_key(monkeypatch):
    """provider=gemini must route via gemini/<model> with the Gemini key — not
    fall into the OpenAI-compat path just because OPENAI_API_KEY is also set."""
    from types import SimpleNamespace

    import litellm

    from vuln_hunter_x.reporting.markdown import _translate_dynamic_text

    monkeypatch.setenv("LLM_PROVIDER", "gemini")
    monkeypatch.setenv("LLM_MODEL", "gemini-2.5-flash")
    monkeypatch.delenv("GEMINI_API_KEYS", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "gemini-key")
    monkeypatch.setenv("OPENAI_API_KEY", "openai-key")
    monkeypatch.delenv("GEMINI_API_BASE", raising=False)

    captured: dict = {}

    def fake_completion(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content="[1] xin chào"))]
        )

    monkeypatch.setattr(litellm, "completion", fake_completion)

    result = _translate_dynamic_text(["hello"], "vi")

    assert captured["model"] == "gemini/gemini-2.5-flash"
    assert captured["api_key"] == "gemini-key"
    assert "api_base" not in captured
    assert result == ["xin chào"]
