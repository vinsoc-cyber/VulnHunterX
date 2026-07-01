# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for opt-in report translation on the `verify` command (issue #126)."""

from __future__ import annotations

from pathlib import Path

import vuln_hunter_x.reporting.markdown as markdown
from vuln_hunter_x.cli import commands
from vuln_hunter_x.cli.main import create_parser
from vuln_hunter_x.core.types import (
    Finding,
    Verdict,
    VerdictType,
    VerificationResult,
)


def _make_result_with_one_verdict() -> VerificationResult:
    finding = Finding(
        rule_id="cpp/uaf",
        message="fake",
        file="a.c",
        start_line=10,
        end_line=10,
        repo_name="demo",
        lang="c",
        severity="error",
    )
    verdict = Verdict(
        finding=finding,
        verdict=VerdictType.TRUE_POSITIVE.value,
        confidence="High",
        reasoning="because reasons",
        answers=["answer one"],
        raw_response="",
        model="test-model",
    )
    return VerificationResult(
        verdicts=[verdict],
        stats={verdict.verdict: 1},
        model="test-model",
        provider="test-provider",
        total_time_seconds=1.23,
    )


def _spy_translation(monkeypatch) -> list[str]:
    """Replace the LLM translation call with a passthrough that records languages."""
    calls: list[str] = []

    def _fake(texts, lang):
        calls.append(lang)
        return texts

    monkeypatch.setattr(markdown, "_translate_dynamic_text", _fake)
    return calls


# --- parser flag ---


def test_verify_translate_report_defaults_false():
    args = create_parser().parse_args(["verify"])
    assert args.translate_report is False


def test_verify_translate_report_flag_sets_true():
    args = create_parser().parse_args(["verify", "--translate-report"])
    assert args.translate_report is True


# --- report generation gating ---


def test_default_generates_english_report_only(tmp_path: Path, monkeypatch):
    calls = _spy_translation(monkeypatch)
    result = _make_result_with_one_verdict()

    reports = commands._generate_verify_reports(result, tmp_path, translate_report=False)

    assert [label for label, _ in reports] == ["EN"]
    assert (tmp_path / "report.md").exists()
    assert not (tmp_path / "report_vi.md").exists()
    assert calls == []  # no translation call fired


def test_translate_report_also_generates_vietnamese(tmp_path: Path, monkeypatch):
    calls = _spy_translation(monkeypatch)
    result = _make_result_with_one_verdict()

    reports = commands._generate_verify_reports(result, tmp_path, translate_report=True)

    assert [label for label, _ in reports] == ["EN", "VI"]
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report_vi.md").exists()
    assert calls == ["vi"]  # translation fired once, for VI


def test_no_verdicts_generates_no_reports(tmp_path: Path):
    result = VerificationResult(
        verdicts=[],
        stats={},
        model="test-model",
        provider="test-provider",
        total_time_seconds=0.0,
    )

    reports = commands._generate_verify_reports(result, tmp_path, translate_report=True)

    assert reports == []
    assert not (tmp_path / "report.md").exists()
    assert not (tmp_path / "report_vi.md").exists()
