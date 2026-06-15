# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for Stage 1 plumbing of the custom-rules coverage plan:

* ``_expand_per_repo_configs`` in ``vuln_hunter_x.cli.commands`` template-expands
  ``${LANG}`` and appends the active profile's ``custom_semgrep_path`` when the
  resolved file exists.

* ``CodeQLAnalyzer.run_analysis`` accepts ``extra_suites`` and splats them into
  the ``codeql database analyze`` command line.
"""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.cli.commands import _expand_per_repo_configs
from vuln_hunter_x.codeql.analysis import CodeQLAnalyzer


def _args(**overrides) -> argparse.Namespace:
    """Minimal Namespace with the attributes our helper checks."""
    defaults = {
        "_profile_custom_semgrep_path": "",
        "_profile_language_specific_configs": {},
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ── _expand_per_repo_configs ─────────────────────────────────────────────────


class TestExpandPerRepoConfigs:
    def test_passthrough_when_no_template_no_custom(self) -> None:
        args = _args()
        out = _expand_per_repo_configs(args, ["auto", "p/security-audit"], "python")
        assert out == ["auto", "p/security-audit"]

    def test_expands_lang_placeholder_when_file_exists(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        custom_dir = tmp_path / "config" / "semgrep-custom"
        custom_dir.mkdir(parents=True)
        (custom_dir / "python.yaml").write_text("rules: []\n")
        monkeypatch.chdir(tmp_path)

        args = _args()
        out = _expand_per_repo_configs(
            args, ["auto", "config/semgrep-custom/${LANG}.yaml"], "python",
        )
        assert out == ["auto", "config/semgrep-custom/python.yaml"]

    def test_drops_template_when_resolved_file_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        args = _args()
        out = _expand_per_repo_configs(
            args, ["auto", "config/semgrep-custom/${LANG}.yaml"], "python",
        )
        assert out == ["auto"]

    def test_appends_custom_semgrep_path_from_profile(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        custom_dir = tmp_path / "config" / "semgrep-custom"
        custom_dir.mkdir(parents=True)
        (custom_dir / "javascript.yaml").write_text("rules: []\n")
        monkeypatch.chdir(tmp_path)

        args = _args(_profile_custom_semgrep_path="config/semgrep-custom/${LANG}.yaml")
        out = _expand_per_repo_configs(args, ["auto"], "javascript")
        assert out == ["auto", "config/semgrep-custom/javascript.yaml"]

    def test_does_not_duplicate_when_template_already_in_configs(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        custom_dir = tmp_path / "config" / "semgrep-custom"
        custom_dir.mkdir(parents=True)
        (custom_dir / "go.yaml").write_text("rules: []\n")
        monkeypatch.chdir(tmp_path)

        args = _args(_profile_custom_semgrep_path="config/semgrep-custom/${LANG}.yaml")
        out = _expand_per_repo_configs(
            args, ["auto", "config/semgrep-custom/${LANG}.yaml"], "go",
        )
        # Expanded once, not twice
        assert out.count("config/semgrep-custom/go.yaml") == 1

    def test_keeps_registry_template_in_input(self) -> None:
        """When the input contains ``p/${LANG}`` style refs, they should expand
        and be kept (registry refs aren't filesystem-checked)."""
        args = _args()
        out = _expand_per_repo_configs(args, ["p/${LANG}"], "python")
        assert "p/python" in out

    def test_appends_language_specific_packs_from_profile(self) -> None:
        args = _args(_profile_language_specific_configs={
            "python": ["p/django", "p/flask"],
            "java": ["p/java"],
        })
        out = _expand_per_repo_configs(args, ["auto"], "python")
        assert out == ["auto", "p/django", "p/flask"]

    def test_language_specific_uses_correct_lang(self) -> None:
        args = _args(_profile_language_specific_configs={
            "python": ["p/django"],
            "go": ["p/gosec"],
        })
        out = _expand_per_repo_configs(args, ["auto"], "go")
        assert "p/gosec" in out
        assert "p/django" not in out

    def test_language_specific_no_match_for_unknown_lang(self) -> None:
        args = _args(_profile_language_specific_configs={"python": ["p/django"]})
        out = _expand_per_repo_configs(args, ["auto"], "cpp")
        assert out == ["auto"]

    def test_language_specific_does_not_duplicate(self) -> None:
        args = _args(_profile_language_specific_configs={"python": ["p/django"]})
        out = _expand_per_repo_configs(args, ["auto", "p/django"], "python")
        assert out.count("p/django") == 1

    # ── engine-aware decoupling (Semgrep registry vs registry-free OpenGrep) ──

    def test_opengrep_skips_registry_language_packs(self) -> None:
        # Registry language packs are Semgrep-only; OpenGrep must not receive them.
        args = _args(_profile_language_specific_configs={"python": ["p/django", "p/flask"]})
        out = _expand_per_repo_configs(
            args, ["config/opengrep-rules/${LANG}"], "python", engine="opengrep",
        )
        assert "p/django" not in out
        assert "p/flask" not in out

    def test_semgrep_still_gets_registry_language_packs(self) -> None:
        args = _args(_profile_language_specific_configs={"python": ["p/django"]})
        out = _expand_per_repo_configs(args, ["auto"], "python", engine="semgrep")
        assert "p/django" in out

    def test_opengrep_still_gets_custom_semgrep_path(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The project's own custom YAML (not a registry pack) flows to both engines.
        custom_dir = tmp_path / "config" / "semgrep-custom"
        custom_dir.mkdir(parents=True)
        (custom_dir / "python.yaml").write_text("rules: []\n")
        monkeypatch.chdir(tmp_path)
        args = _args(_profile_custom_semgrep_path="config/semgrep-custom/${LANG}.yaml")
        out = _expand_per_repo_configs(
            args, ["config/opengrep-rules/${LANG}"], "python", engine="opengrep",
        )
        assert "config/semgrep-custom/python.yaml" in out

    def test_directory_template_resolves(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # A ${LANG} template pointing at a directory (the vendored rule tree) must
        # be kept, not dropped — the analyzer accepts --config <dir>.
        rules_dir = tmp_path / "config" / "opengrep-rules" / "python"
        rules_dir.mkdir(parents=True)
        monkeypatch.chdir(tmp_path)
        args = _args()
        out = _expand_per_repo_configs(
            args, ["config/opengrep-rules/${LANG}"], "python", engine="opengrep",
        )
        assert out == ["config/opengrep-rules/python"]

    def test_directory_template_dropped_when_missing(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        args = _args()
        out = _expand_per_repo_configs(
            args, ["config/opengrep-rules/${LANG}"], "python", engine="opengrep",
        )
        assert out == []


# ── CodeQLAnalyzer.run_analysis(extra_suites=...) ────────────────────────────


def _patch_analyzer_for_run(analyzer: CodeQLAnalyzer) -> None:
    """Stub finalization and lock cleanup so run_analysis reaches the analyze
    subprocess call without touching a real database."""
    analyzer._clean_stale_locks = MagicMock()  # type: ignore[method-assign]
    analyzer._is_finalized = MagicMock(return_value=True)  # type: ignore[method-assign]
    analyzer._count_sarif_results = MagicMock(return_value=0)  # type: ignore[method-assign]


class TestRunAnalysisExtraSuites:
    def test_extra_suites_appended_after_primary(self, tmp_path: Path) -> None:
        analyzer = CodeQLAnalyzer(output_dir=tmp_path)
        _patch_analyzer_for_run(analyzer)

        # Make the extra suite a real file so the validity filter keeps it
        extra = tmp_path / "custom" / "suite.qls"
        extra.parent.mkdir(parents=True)
        extra.write_text("- queries: src\n")

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            ok, _, _ = analyzer.run_analysis(
                db_path=tmp_path / "db",
                lang="python",
                output_name="repo",
                extra_suites=[str(extra)],
            )

        assert ok
        cmd = captured["cmd"]
        # Position 4 is the primary suite, position 5 is the extra
        assert cmd[3] == str(tmp_path / "db")
        assert "python-security-extended" in cmd[4]
        assert cmd[5] == str(extra)
        # The --format flag must come after suites
        format_idx = next(i for i, a in enumerate(cmd) if a.startswith("--format"))
        assert format_idx > 5

    def test_missing_extra_suite_filtered_out(self, tmp_path: Path) -> None:
        analyzer = CodeQLAnalyzer(output_dir=tmp_path)
        _patch_analyzer_for_run(analyzer)

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            ok, _, _ = analyzer.run_analysis(
                db_path=tmp_path / "db",
                lang="python",
                output_name="repo",
                extra_suites=[str(tmp_path / "does-not-exist.qls")],
            )

        assert ok
        cmd = captured["cmd"]
        # Only the primary suite is present, no extra (since file missing)
        assert all("does-not-exist" not in a for a in cmd)

    def test_registry_extra_suite_kept_even_without_filesystem(
        self, tmp_path: Path,
    ) -> None:
        """Registry refs like ``codeql/cpp-queries:codeql-suites/foo.qls`` contain
        ``:`` and should not be filtered as missing files."""
        analyzer = CodeQLAnalyzer(output_dir=tmp_path)
        _patch_analyzer_for_run(analyzer)

        registry_ref = "codeql/python-queries:codeql-suites/python-code-scanning.qls"

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            analyzer.run_analysis(
                db_path=tmp_path / "db",
                lang="python",
                output_name="repo",
                extra_suites=[registry_ref],
            )

        assert registry_ref in captured["cmd"]

    def test_default_no_extra_suites_preserves_old_behavior(self, tmp_path: Path) -> None:
        analyzer = CodeQLAnalyzer(output_dir=tmp_path)
        _patch_analyzer_for_run(analyzer)

        captured: dict = {}

        def fake_run(cmd, **kwargs):
            captured["cmd"] = cmd
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=fake_run):
            analyzer.run_analysis(
                db_path=tmp_path / "db",
                lang="python",
                output_name="repo",
            )

        cmd = captured["cmd"]
        # Primary suite at index 4, --format immediately after (index 5)
        assert "python-security-extended" in cmd[4]
        assert cmd[5].startswith("--format")
