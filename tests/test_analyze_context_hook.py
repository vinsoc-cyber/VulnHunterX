# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Post-analyze context extraction hook (#159).

A source-only analyze (Semgrep/OpenGrep) now produces SARIF *and* extracts
tree-sitter context, so verification is not silently starved of context CSVs.
"""

from __future__ import annotations

import argparse
from unittest.mock import patch

from vuln_hunter_x.cli.commands import cmd_analyze


def _analyze_args(**overrides) -> argparse.Namespace:
    defaults = {
        "tool": "semgrep",
        "local_path": None,
        "name": None,
        "lang": "python",
        "repo": "myrepo",
        "config": None,
        "semgrep_configs": None,
        "opengrep_configs": None,
        "codeql_suite": None,
        "profile": None,
        "categories": None,
        "verbose": False,
        "force": False,
        "dry_run": False,
        "jobs": None,
        "json": False,
        "skip_context": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


class TestPostAnalyzeContextHook:
    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=0)
    def test_semgrep_success_triggers_context(self, mock_semgrep, mock_ctx, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="semgrep", lang="python", repo="myrepo"))

        assert rc == 0
        mock_ctx.assert_called_once()
        kw = mock_ctx.call_args[1]
        assert kw["lang_filter"] == "python"
        assert kw["repo_filter"] == "myrepo"
        assert kw["backend"] == "auto"
        assert kw["force"] is False
        # Must NOT forward local_path / name (that is #158's stale-symlink block).
        assert "local_path" not in kw
        assert "name" not in kw

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_opengrep_analyze", return_value=0)
    def test_opengrep_success_triggers_context(self, mock_opengrep, mock_ctx, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="opengrep"))
        assert rc == 0
        mock_ctx.assert_called_once()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_codeql_analyze", return_value=1)
    def test_both_codeql_fail_source_success_triggers_once(
        self, mock_codeql, mock_semgrep, mock_ctx, tmp_path
    ):
        # both = "any analyzer succeeds"; CodeQL failed but Semgrep produced
        # SARIF, so context must still reconcile — exactly once.
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="both"))
        assert rc == 0
        mock_ctx.assert_called_once()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=1)
    @patch("vuln_hunter_x.cli.commands._run_codeql_analyze", return_value=0)
    def test_both_codeql_success_source_fail_triggers_once(
        self, mock_codeql, mock_semgrep, mock_ctx, tmp_path
    ):
        # both = "any analyzer succeeds"; CodeQL succeeded so the run is a
        # success, and auto reconciliation is still correct (addition-only,
        # honours the skip filter — see the neutrality regression).
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="both"))
        assert rc == 0
        mock_ctx.assert_called_once()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_opengrep_analyze", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_codeql_analyze", return_value=0)
    def test_all_triggers_context_once(
        self, mock_codeql, mock_semgrep, mock_opengrep, mock_ctx, tmp_path
    ):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="all"))
        assert rc == 0
        mock_ctx.assert_called_once()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_codeql_analyze", return_value=0)
    def test_codeql_only_does_not_trigger_context(self, mock_codeql, mock_ctx, tmp_path):
        # CodeQL's context lifecycle stays at prepare time (out of #159 scope).
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="codeql"))
        assert rc == 0
        mock_ctx.assert_not_called()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=1)
    def test_failed_analyze_does_not_trigger_context(self, mock_semgrep, mock_ctx, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="semgrep"))
        assert rc == 1
        mock_ctx.assert_not_called()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=0)
    def test_dry_run_does_not_trigger_context(self, mock_semgrep, mock_ctx, tmp_path):
        # dry-run counts as success without producing SARIF, so the hook must skip.
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="semgrep", dry_run=True))
        assert rc == 0
        mock_ctx.assert_not_called()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=0)
    def test_skip_context_flag_does_not_trigger(self, mock_semgrep, mock_ctx, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="semgrep", skip_context=True))
        assert rc == 0
        mock_ctx.assert_not_called()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=0)
    def test_analyze_force_does_not_forward_to_context(self, mock_semgrep, mock_ctx, tmp_path):
        # analyze --force means re-analysis; it must NOT overwrite existing CSVs.
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="semgrep", force=True))
        assert rc == 0
        assert mock_ctx.call_args[1]["force"] is False

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=1)
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=0)
    def test_context_failure_is_nonfatal(self, mock_semgrep, mock_ctx, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="semgrep"))
        assert rc == 0  # scanner success preserved despite context rc=1
        mock_ctx.assert_called_once()

    @patch(
        "vuln_hunter_x.cli.commands._run_context_extraction",
        side_effect=RuntimeError("boom"),
    )
    @patch("vuln_hunter_x.cli.commands._run_semgrep_analyze", return_value=0)
    def test_context_exception_is_nonfatal(self, mock_semgrep, mock_ctx, tmp_path):
        with patch("pathlib.Path.cwd", return_value=tmp_path):
            rc = cmd_analyze(_analyze_args(tool="semgrep"))
        assert rc == 0  # a raised context error must not fail a successful analyze
