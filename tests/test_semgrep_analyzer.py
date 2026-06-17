# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for SemgrepAnalyzer."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.semgrep.analyzer import SemgrepAnalyzer


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
                "tool": {"driver": {"name": "Semgrep", "rules": rules}},
                "results": results,
            }
        ],
    }
    path.write_text(json.dumps(data))


class TestSemgrepAnalyzerRunAnalysis:
    def test_success_writes_sarif_and_returns_ok(self, tmp_path):
        repos_dir = tmp_path / "repos" / "c" / "myrepo"
        repos_dir.mkdir(parents=True)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        analyzer = SemgrepAnalyzer(semgrep_path="semgrep", output_dir=output_dir)

        # Simulate: which(semgrep) found, subprocess returns 0, SARIF written by "semgrep"
        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/semgrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            # Simulate semgrep writing the SARIF output file
            sarif_path = output_dir / "c" / "myrepo" / "myrepo_semgrep.sarif"
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
        assert "3 findings" in msg
        assert "4 rules" in msg

    def test_semgrep_not_found_returns_failure(self, tmp_path):
        analyzer = SemgrepAnalyzer(semgrep_path="semgrep", output_dir=tmp_path)

        with patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value=None):
            ok, result_path, msg = analyzer.run_analysis(
                repo_path=tmp_path,
                lang="c",
                repo_name="myrepo",
                output_dir=tmp_path,
            )

        assert ok is False
        assert result_path is None
        assert "not found" in msg.lower()

    def test_subprocess_nonzero_returns_failure(self, tmp_path):
        analyzer = SemgrepAnalyzer(semgrep_path="semgrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/semgrep"),
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

        analyzer = SemgrepAnalyzer(semgrep_path="semgrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/semgrep"),
            patch(
                "vuln_hunter_x.semgrep.analyzer.subprocess.run",
                side_effect=subprocess.TimeoutExpired("semgrep", 3600),
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

    def test_default_config_is_auto(self, tmp_path):
        analyzer = SemgrepAnalyzer(semgrep_path="semgrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/semgrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

            analyzer.run_analysis(
                repo_path=tmp_path,
                lang="c",
                repo_name="myrepo",
                output_dir=tmp_path,
                configs=None,  # Should default to ["auto"]
            )

            call_args = mock_run.call_args[0][0]
            assert "--config" in call_args
            auto_idx = call_args.index("--config")
            assert call_args[auto_idx + 1] == "auto"

    def test_multiple_configs_all_passed(self, tmp_path):
        analyzer = SemgrepAnalyzer(semgrep_path="semgrep", output_dir=tmp_path)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/semgrep"),
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


class TestSemgrepAnalyzerEmptyResultsWarning:
    """The silent-failure guard: rules loaded but 0 results on a real path."""

    def test_zero_results_with_rules_warns_but_succeeds(self, tmp_path, caplog):
        import logging

        repos_dir = tmp_path / "repos" / "go" / "myrepo"
        repos_dir.mkdir(parents=True)
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        analyzer = SemgrepAnalyzer(semgrep_path="semgrep", output_dir=output_dir)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/semgrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
            caplog.at_level(logging.WARNING, logger="vuln_hunter_x.semgrep.analyzer"),
        ):
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout="",
                stderr="Rule pack p/gosec not found in registry; network unreachable",
            )
            sarif_path = output_dir / "go" / "myrepo" / "myrepo_semgrep.sarif"
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            _write_sarif(sarif_path, results_count=0, rules_count=5)

            ok, result_path, msg = analyzer.run_analysis(
                repo_path=repos_dir,
                lang="go",
                repo_name="myrepo",
                output_dir=output_dir,
                configs=["auto"],
            )

        assert ok is True  # tool itself succeeded
        assert "WARNING" in msg and "0 results" in msg
        # The warning and the registry/network hint are both logged.
        assert any("0 results" in r.message for r in caplog.records)
        assert any("registry" in r.message.lower() for r in caplog.records)

    def test_zero_results_no_rules_does_not_warn(self, tmp_path, caplog):
        import logging

        output_dir = tmp_path / "output"
        output_dir.mkdir()
        analyzer = SemgrepAnalyzer(semgrep_path="semgrep", output_dir=output_dir)

        with (
            patch("vuln_hunter_x.semgrep.analyzer.shutil.which", return_value="/usr/bin/semgrep"),
            patch("vuln_hunter_x.semgrep.analyzer.subprocess.run") as mock_run,
            caplog.at_level(logging.WARNING, logger="vuln_hunter_x.semgrep.analyzer"),
        ):
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            sarif_path = output_dir / "go" / "myrepo" / "myrepo_semgrep.sarif"
            sarif_path.parent.mkdir(parents=True, exist_ok=True)
            _write_sarif(sarif_path, results_count=0, rules_count=0)

            ok, _, msg = analyzer.run_analysis(
                repo_path=tmp_path,
                lang="go",
                repo_name="myrepo",
                output_dir=output_dir,
                configs=["auto"],
            )

        assert ok is True
        assert "WARNING" not in msg
        assert not any("0 results" in r.message for r in caplog.records)


class TestSemgrepAnalyzerCountMethods:
    def test_count_results_in_sarif(self, tmp_path):
        sarif_path = tmp_path / "test.sarif"
        _write_sarif(sarif_path, results_count=5, rules_count=2)
        analyzer = SemgrepAnalyzer()
        assert analyzer._count_sarif_results(sarif_path) == 5

    def test_count_rules_in_sarif(self, tmp_path):
        sarif_path = tmp_path / "test.sarif"
        _write_sarif(sarif_path, results_count=1, rules_count=7)
        analyzer = SemgrepAnalyzer()
        assert analyzer._count_sarif_rules(sarif_path) == 7

    def test_count_missing_file_returns_zero(self, tmp_path):
        analyzer = SemgrepAnalyzer()
        assert analyzer._count_sarif_results(tmp_path / "missing.sarif") == 0
        assert analyzer._count_sarif_rules(tmp_path / "missing.sarif") == 0

    def test_count_malformed_json_returns_zero(self, tmp_path):
        sarif_path = tmp_path / "bad.sarif"
        sarif_path.write_text("not json {{{")
        analyzer = SemgrepAnalyzer()
        assert analyzer._count_sarif_results(sarif_path) == 0
        assert analyzer._count_sarif_rules(sarif_path) == 0
