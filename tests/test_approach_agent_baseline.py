# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber
"""agent-baseline approach: argv, containment, error handling (mocked subprocess)."""

from __future__ import annotations

import json
import subprocess
from unittest.mock import patch

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.approaches import agent_baseline as ab
from benchmarks.approaches.registry import build_approach


def _entry(**meta):
    return GroundTruthEntry(
        id="e1",
        source_dataset="t",
        cwe_id="CWE-79",
        rule_id="r",
        file_path="a.py",
        function_name="f",
        start_line=3,
        lang="python",
        label="TP",
        code_snippet="",
        metadata=meta,
        sink_line=3,
    )


@pytest.fixture()
def repos(tmp_path):
    (tmp_path / "python" / "proj").mkdir(parents=True)
    return tmp_path


def _cp(stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


VERDICT = '{"verdict":"FP","confidence":"Medium","rationale":"escaped"}'


def test_registered():
    assert isinstance(
        build_approach("agent-baseline", options={"agent": "codex"}), ab.AgentBaselineApproach
    )


def test_claude_argv_is_read_only():
    argv = ab.build_argv("claude", model="m", max_budget_usd=1.5, binary="/x/claude")
    assert argv[:4] == ["/x/claude", "-p", "--output-format", "json"]
    assert argv[argv.index("--allowedTools") + 1] == "Read,Grep,Glob"
    assert argv[argv.index("--permission-mode") + 1] == "dontAsk"
    denied = argv[argv.index("--disallowedTools") + 1].split(",")
    assert {"Edit", "Write", "Bash"} <= set(denied)
    assert argv[argv.index("--model") + 1] == "m"
    assert argv[argv.index("--max-budget-usd") + 1] == "1.5"
    assert "--dangerously-skip-permissions" not in argv


def test_codex_argv_read_only_sandbox():
    argv = ab.build_argv("codex", model="o", binary="/x/codex")
    assert argv[:2] == ["/x/codex", "exec"]
    assert argv[argv.index("--sandbox") + 1] == "read-only"
    assert argv[-1] == "-" and "danger-full-access" not in argv


def test_unsupported_agent():
    with pytest.raises(ValueError):
        ab.AgentBaselineApproach(agent="evil")


def test_claude_success_parses_envelope(repos):
    env = {
        "result": f"analysis\n{VERDICT}",
        "total_cost_usd": 0.12,
        "num_turns": 4,
        "usage": {"input_tokens": 100, "output_tokens": 20, "cache_read_input_tokens": 7},
    }
    a = ab.AgentBaselineApproach(agent="claude", repos_dir=repos, timeout=9)
    with (
        patch.object(ab.shutil, "which", return_value="/bin/claude"),
        patch.object(ab.subprocess, "run", return_value=_cp(json.dumps(env))) as run,
    ):
        r = a.evaluate(_entry(repo_name="proj"))
    assert (r.predicted_label, r.confidence) == ("FP", "Medium")
    assert (r.cost_usd, r.iterations, r.input_tokens, r.cached_input_tokens) == (0.12, 4, 100, 7)
    kw = run.call_args.kwargs
    assert kw["cwd"].endswith("proj")
    assert kw["timeout"] == 9 and "shell" not in kw
    assert "Finding:" in kw["input"] and "untrusted" in kw["input"]
    assert set(kw["env"]) <= set(ab._ENV_ALLOW)


def test_codex_success_plain_stdout(repos):
    a = ab.AgentBaselineApproach(agent="codex", repos_dir=repos)
    with (
        patch.object(ab.shutil, "which", return_value="/bin/codex"),
        patch.object(ab.subprocess, "run", return_value=_cp("thinking...\n" + VERDICT)),
    ):
        r = a.evaluate(_entry(repo_name="proj"))
    assert r.predicted_label == "FP"


def test_missing_binary_is_error(repos):
    a = ab.AgentBaselineApproach(repos_dir=repos)
    with patch.object(ab.shutil, "which", return_value=None):
        r = a.evaluate(_entry(repo_name="proj"))
    assert r.predicted_label == "ERROR" and "not found" in r.reasoning


def test_timeout_is_error(repos):
    a = ab.AgentBaselineApproach(repos_dir=repos)
    with (
        patch.object(ab.shutil, "which", return_value="/bin/claude"),
        patch.object(ab.subprocess, "run", side_effect=subprocess.TimeoutExpired("claude", 1)),
    ):
        r = a.evaluate(_entry(repo_name="proj"))
    assert r.predicted_label == "ERROR" and "timed out" in r.reasoning


def test_nonzero_exit_is_error(repos):
    a = ab.AgentBaselineApproach(repos_dir=repos)
    with (
        patch.object(ab.shutil, "which", return_value="/bin/claude"),
        patch.object(ab.subprocess, "run", return_value=_cp("", 2, "bad auth")),
    ):
        r = a.evaluate(_entry(repo_name="proj"))
    assert r.predicted_label == "ERROR" and "bad auth" in r.reasoning


def test_malformed_output_is_nmd(repos):
    a = ab.AgentBaselineApproach(agent="codex", repos_dir=repos)
    with (
        patch.object(ab.shutil, "which", return_value="/bin/codex"),
        patch.object(ab.subprocess, "run", return_value=_cp("no json here")),
    ):
        r = a.evaluate(_entry(repo_name="proj"))
    assert r.predicted_label == "NMD"


@pytest.mark.parametrize(
    "meta",
    [
        {"repo_path": "../outside"},
        {"repo_path": "/etc"},
        {"repo_name": "../x"},
        {"repo_name": "a/b"},
        {"repo_name": "missing"},
        {},
    ],
)
def test_unsafe_or_missing_repo_rejected_without_running(repos, meta):
    a = ab.AgentBaselineApproach(repos_dir=repos)
    with patch.object(ab.subprocess, "run") as run:
        r = a.evaluate(_entry(**meta))
    assert r.predicted_label == "ERROR"
    run.assert_not_called()


def test_repo_path_inside_root_ok(repos):
    assert (
        ab.resolve_agent_repo(_entry(repo_path="python/proj"), repos)
        == (repos / "python" / "proj").resolve()
    )


def test_symlink_escape_rejected(repos, tmp_path_factory):
    outside = tmp_path_factory.mktemp("outside")
    (repos / "link").symlink_to(outside)
    with pytest.raises(ab.RepoPathError):
        ab.resolve_agent_repo(_entry(repo_path="link"), repos)
