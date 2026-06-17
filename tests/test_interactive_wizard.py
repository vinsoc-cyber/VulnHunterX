# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for the interactive wizard's prerequisite gate and per-stage validation."""

from __future__ import annotations

import argparse

import pytest

from vuln_hunter_x.cli import env as envmod
from vuln_hunter_x.cli import interactive


def _feed(monkeypatch, answers: list[str]) -> None:
    """Make builtins.input return the queued answers in order."""
    it = iter(answers)
    monkeypatch.setattr("builtins.input", lambda prompt="": next(it))


def _patch_tools(monkeypatch, *, codeql=False, semgrep=True, opengrep=False, git=True):
    monkeypatch.setattr(envmod, "check_codeql", lambda *a, **k: (codeql, "codeql"))
    monkeypatch.setattr(envmod, "check_semgrep", lambda *a, **k: (semgrep, "semgrep"))
    monkeypatch.setattr(envmod, "check_opengrep", lambda *a, **k: (opengrep, "opengrep"))
    monkeypatch.setattr(envmod, "check_treesitter", lambda *a, **k: (True, "tree-sitter"))
    monkeypatch.setattr(interactive.shutil, "which", lambda name: "/usr/bin/git" if git else None)


def _capture_scan(monkeypatch) -> dict:
    captured: dict = {}

    def fake_scan(ns):
        captured["ns"] = ns
        return 0

    monkeypatch.setattr(interactive, "cmd_scan", fake_scan)
    return captured


def test_exits_when_no_analyzer_available(monkeypatch):
    """All three analyzers missing → hard exit (rc 1) before any prompt."""
    _patch_tools(monkeypatch, codeql=False, semgrep=False, opengrep=False)
    called = _capture_scan(monkeypatch)
    # No input is fed; any prompt would raise StopIteration and fail the test.
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("prompted despite missing analyzers"))

    rc = interactive.cmd_interactive(argparse.Namespace())

    assert rc == 1
    assert "ns" not in called  # cmd_scan never reached


def test_bad_local_path_reprompts_then_proceeds(monkeypatch, tmp_path):
    """An invalid path is rejected and re-prompted; a valid dir is accepted."""
    _patch_tools(monkeypatch, semgrep=True)
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setattr(envmod, "check_openai", lambda *a, **k: (True, "OpenAI OK"))
    (tmp_path / "a.py").write_text("x = 1\n")
    captured = _capture_scan(monkeypatch)

    _feed(
        monkeypatch,
        [
            "2",                 # source: local directory
            "/no/such/dir",      # bad path → re-prompt
            str(tmp_path),       # valid path
            "3",                 # language: python
            "",                  # name (auto)
            "1",                 # profile: standard
            "3",                 # analyzer: semgrep (available)
            "1",                 # provider: config default (openai)
            "",                  # limit: none
            "y",                 # proceed
        ],
    )

    rc = interactive.cmd_interactive(argparse.Namespace())

    assert rc == 0
    ns = captured["ns"]
    assert ns.local_path == tmp_path
    assert ns.lang == "python"
    assert ns.tool == "semgrep"
    assert ns.skip_verify is False


def test_llm_failure_offers_skip_verify(monkeypatch, tmp_path):
    """A failed LLM live-test lets the user continue with verification skipped."""
    _patch_tools(monkeypatch, semgrep=True)
    monkeypatch.setenv("LLM_PROVIDER", "openai")
    monkeypatch.setattr(envmod, "check_openai", lambda *a, **k: (False, "OPENAI_API_KEY not set"))
    (tmp_path / "a.py").write_text("x = 1\n")
    captured = _capture_scan(monkeypatch)

    _feed(
        monkeypatch,
        [
            "2",            # source: local
            str(tmp_path),  # valid path
            "3",            # language: python
            "",             # name
            "1",            # profile
            "3",            # analyzer: semgrep
            "1",            # provider: config default (openai) → live test fails
            "2",            # recovery: continue without verification
            "",             # limit
            "y",            # proceed
        ],
    )

    rc = interactive.cmd_interactive(argparse.Namespace())

    assert rc == 0
    assert captured["ns"].skip_verify is True
