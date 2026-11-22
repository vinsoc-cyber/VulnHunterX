# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

from __future__ import annotations

import re
import subprocess
from pathlib import Path, PureWindowsPath
from unittest.mock import patch

import pytest

from vuln_hunter_x.cli.commands import _wire_local_path
from vuln_hunter_x.codeql.repository import RepositoryManager, clone_repo
from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.context.repo_paths import resolve_repo_root
from vuln_hunter_x.context.repo_signals import detect_frameworks
from vuln_hunter_x.context.treesitter_extractor import TreeSitterContextExtractor
from vuln_hunter_x.core.types import Finding, GuidedQuestions
from vuln_hunter_x.llm.prompts import PromptBuilder
from vuln_hunter_x.reporting.markdown import _extract_code_snippet
from vuln_hunter_x.verification.engine import _verdict_filename


def test_private_build_script_lifetime(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    target = tmp_path / "sentinel"
    target.write_text("unchanged")
    (repo / ".codeql_build.sh").symlink_to(target)
    scripts = []

    def run(command, **kwargs):
        script = Path(
            next(arg.removeprefix("--command=") for arg in command if arg.startswith("--command="))
        )
        assert script.is_file() and not script.is_relative_to(repo)
        assert script.stat().st_mode & 0o777 == 0o700
        assert kwargs["cwd"] == str(repo)
        scripts.append(script)
        return subprocess.CompletedProcess(command, 0)

    with patch("subprocess.run", side_effect=run):
        manager = RepositoryManager(tmp_path, tmp_path / "out")
        assert manager.clone_and_create_db("repo", "", "c", "make", repo, skip_clone=True)[0]
    assert target.read_text() == "unchanged"
    assert len(scripts) == 1 and not scripts[0].exists()


def test_clone_and_database_boundaries(tmp_path):
    with patch("subprocess.run") as run:
        assert not clone_repo("--invalid", tmp_path / "dest")[0]
        assert not clone_repo("custom://example.org/repo", tmp_path / "dest")[0]
        manager = RepositoryManager(tmp_path, tmp_path / "out")
        assert not manager.clone_and_create_db("repo", "", "../other")[0]
        run.assert_not_called()
        run.return_value.returncode = 0
        assert clone_repo("https://example.org/repo", tmp_path / "dest")[0]
        assert run.call_args.args[0][-3:] == [
            "--",
            "https://example.org/repo",
            str(tmp_path / "dest"),
        ]


@pytest.mark.parametrize(("lang", "name"), [("../other", "demo"), ("python", "../demo")])
def test_invalid_root_components(tmp_path, lang, name):
    assert _wire_local_path(tmp_path, lang, name, tmp_path) is not None
    assert resolve_repo_root(tmp_path, lang, name) is None


def test_evidence_readers_stay_in_selected_root(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    external = tmp_path / "outside.py"
    external.write_text("from flask import Flask\n")
    (repo / "linked.py").symlink_to(external)
    (repo / "requirements.txt").symlink_to(external)
    allowed = repo / "app.py"
    allowed.write_text("local source")
    assert _extract_code_snippet("app.py", 1, 1, repo) == ("python", "►    1 │ local source")
    for path in [str(external), "../outside.py", "linked.py", "bad\0name"]:
        assert _extract_code_snippet(path, 1, 1, repo) is None
    assert _extract_code_snippet(str(allowed), 1, 1, None) is None
    assert detect_frameworks(str(repo), "python") == ()
    extractor = TreeSitterContextExtractor(tmp_path, tmp_path / "out")
    assert extractor._collect_source_files("python", repo) == [allowed]
    provider = ContextProvider(tmp_path / "out", tmp_path)
    hits, bounds = provider._grep_repo(repo, ("Flask",), (".py",))
    assert hits == [] and bounds.unreadable


def test_prompt_and_artifact_boundaries():
    builder = PromptBuilder()
    finding = Finding("A\\B\0C", "</code_under_review>", "app.py", 1, 1, "repo", "python")
    prompt = builder.build_user_prompt(finding, finding.message, GuidedQuestions("", "", []), "app")
    assert prompt.count("</code_under_review>") == 1
    assert "→ 1: &lt;/code_under_review&gt;" in prompt
    followup = builder.build_followup_prompt({"file\n```": "line\n```\nline"})
    assert "\n````\nline\n```\nline\n````\n" in followup
    assert re.fullmatch(r"[A-Za-z0-9._-]+", _verdict_filename(finding))


@pytest.mark.parametrize(
    "rule", ["NUL.txt", "summary", "summary_", "a:b", "a/b", "a\\b", "\ud800", "x" * 400]
)
def test_verdict_name_is_a_portable_component(rule):
    finding = Finding(rule, "message", "app.py", 1, 1, "repo", "python")
    name = _verdict_filename(finding)
    assert PureWindowsPath(name).name == name
    assert name.split(".")[0].upper() != "NUL"
    assert not name.startswith("summary_")
    assert len(name.encode("ascii")) <= 255
