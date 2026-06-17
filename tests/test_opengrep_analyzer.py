# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for OpenGrepAnalyzer."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.opengrep.analyzer import OpenGrepAnalyzer


def _write_sarif(path: Path, results_count: int = 2, rules_count: int = 3) -> None:
    """Write a minimal SARIF file with the given counts."""
    rules = [{"id": f"rule-{i}"} for i in range(rules_count)]
    results = [
        {
            "ruleId": f"rule-{i % rules_count}",
            "message": {"text": f"finding {i}"},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f"src/file{i}.c"},
                        "region": {"startLine": i + 1},
                    }
                }
            ],
        }
        for i in range(results_count)
    ]
    data = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "opengrep", "rules": rules}},
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(data))


class TestOpenGrepAnalyzerClassConstants:
    def test_tool_name(self):
        assert OpenGrepAnalyzer.TOOL_NAME == "opengrep"

    def test_tool_label(self):
        assert OpenGrepAnalyzer.TOOL_LABEL == "OpenGrep"

    def test_sarif_suffix(self):
        assert OpenGrepAnalyzer.SARIF_SUFFIX == "_opengrep"

    def test_env_var(self):
        assert OpenGrepAnalyzer.ENV_VAR == "OPENGREP_PATH"

    def test_default_binary(self):
        assert OpenGrepAnalyzer.DEFAULT_BINARY == "opengrep"


class TestOpenGrepAnalyzerInit:
    def test_default_binary_path(self):
        analyzer = OpenGrepAnalyzer()
        assert analyzer.binary_path == "opengrep"

    def test_custom_binary_path(self):
        analyzer = OpenGrepAnalyzer(semgrep_path="/usr/local/bin/opengrep")
        assert analyzer.binary_path == "/usr/local/bin/opengrep"

    def test_env_var_override(self):
        with patch.dict("os.environ", {"OPENGREP_PATH": "/custom/opengrep"}):
            analyzer = OpenGrepAnalyzer()
            assert analyzer.binary_path == "/custom/opengrep"


class TestOpenGrepAnalyzerRunAnalysis:
    def test_success_writes_sarif_and_returns_ok(self, tmp_path):
        repos_dir = tmp_path / "repos" / "c" / "myrepo"
        repos_dir.mkdir(parents=True)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        analyzer = OpenGrepAnalyzer(semgrep_path="opengrep", output_dir=output_dir)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/opengrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            sarif_path = output_dir / "c" / "myrepo" / "myrepo_opengrep.sarif"
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            _write_sarif(sarif_path, results_count=3, rules_count=4)

            ok, result_path, msg = analyzer.run_analysis(
                repo_path=repos_dir,
                lang="c",
                repo_name="myrepo",
                output_dir=output_dir,
                configs=["auto"],
            )

        assert ok is True
        assert result_path is not None
        assert result_path.name == "myrepo_opengrep.sarif"
        assert "3 findings" in msg
        assert "4 rules" in msg
        assert "OpenGrep" in msg

    def test_opengrep_not_found_returns_failure(self, tmp_path):
        analyzer = OpenGrepAnalyzer(semgrep_path="opengrep", output_dir=tmp_path)

        with patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value=None):
            ok, result_path, msg = analyzer.run_analysis(
                repo_path=tmp_path,
                lang="c",
                repo_name="myrepo",
                output_dir=tmp_path,
            )

        assert ok is False
        assert result_path is None
        assert "opengrep" in msg.lower()
        assert "OPENGREP_PATH" in msg

    def test_subprocess_nonzero_returns_failure(self, tmp_path):
        analyzer = OpenGrepAnalyzer(semgrep_path="opengrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/opengrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="",
                stderr="fatal: invalid config",
            )

            ok, result_path, msg = analyzer.run_analysis(
                repo_path=tmp_path,
                lang="c",
                repo_name="myrepo",
                output_dir=tmp_path,
            )

        assert ok is False
        assert result_path is None
        assert "invalid config" in msg

    def test_timeout_returns_failure(self, tmp_path):
        import subprocess

        analyzer = OpenGrepAnalyzer(semgrep_path="opengrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/opengrep"),
            patch(
                "vuln_hunter_x.semgrep.analyzer.subprocess.run",
                side_effect=subprocess.TimeoutExpired("opengrep", 3600),
            ),
        ):
            ok, result_path, msg = analyzer.run_analysis(
                repo_path=tmp_path,
                lang="c",
                repo_name="myrepo",
                output_dir=tmp_path,
            )

        assert ok is False
        assert "timed out" in msg.lower()
        assert "OpenGrep" in msg

    def test_default_config_is_auto(self, tmp_path):
        analyzer = OpenGrepAnalyzer(semgrep_path="opengrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/opengrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            analyzer.run_analysis(
                repo_path=tmp_path,
                lang="c",
                repo_name="myrepo",
                output_dir=tmp_path,
                configs=None,
            )

            call_args = mock_run.call_args[0][0]
            assert "--config" in call_args
            auto_idx = call_args.index("--config")
            assert call_args[auto_idx + 1] == "auto"

    def test_multiple_configs_all_passed(self, tmp_path):
        analyzer = OpenGrepAnalyzer(semgrep_path="opengrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/opengrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            analyzer.run_analysis(
                repo_path=tmp_path,
                lang="c",
                repo_name="myrepo",
                output_dir=tmp_path,
                configs=["auto", "p/security-audit"],
            )

            call_args = mock_run.call_args[0][0]
            config_indices = [i for i, x in enumerate(call_args) if x == "--config"]
            config_values = [call_args[i + 1] for i in config_indices]
            assert "auto" in config_values
            assert "p/security-audit" in config_values

    def test_uses_opengrep_binary(self, tmp_path):
        analyzer = OpenGrepAnalyzer(semgrep_path="opengrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/opengrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            analyzer.run_analysis(
                repo_path=tmp_path,
                lang="c",
                repo_name="myrepo",
                output_dir=tmp_path,
            )

            call_args = mock_run.call_args[0][0]
            assert call_args[0] == "opengrep"


class TestOpenGrepAnalyzerCountMethods:
    def test_count_results_in_sarif(self, tmp_path):
        sarif_path = tmp_path / "test.sarif"
        _write_sarif(sarif_path, results_count=5, rules_count=2)
        analyzer = OpenGrepAnalyzer()
        assert analyzer._count_sarif_results(sarif_path) == 5

    def test_count_rules_in_sarif(self, tmp_path):
        sarif_path = tmp_path / "test.sarif"
        _write_sarif(sarif_path, results_count=1, rules_count=7)
        analyzer = OpenGrepAnalyzer()
        assert analyzer._count_sarif_rules(sarif_path) == 7

    def test_count_missing_file_returns_zero(self, tmp_path):
        analyzer = OpenGrepAnalyzer()
        assert analyzer._count_sarif_results(tmp_path / "missing.sarif") == 0
        assert analyzer._count_sarif_rules(tmp_path / "missing.sarif") == 0
