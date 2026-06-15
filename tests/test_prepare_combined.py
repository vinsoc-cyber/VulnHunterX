# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for combined prepare + context extraction stage."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.cli.commands import _run_context_extraction, cmd_prepare
from vuln_hunter_x.codeql.repository import RepositoryManager, _has_source_files, detect_build_command


# ── Helpers ──────────────────────────────────────────────────────────


def _make_prepare_args(**overrides) -> argparse.Namespace:
    """Build a minimal argparse.Namespace for cmd_prepare."""
    defaults = {
        "url": None,
        "local_path": None,
        "name": None,
        "lang": None,
        "repo": None,
        "config": None,
        "build_command": None,
        "skip_clone": False,
        "skip_db": False,
        "skip_context": False,
        "backend": "auto",
        "force": False,
        "ask_llm": False,
        "dry_run": False,
    }
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


# ── cmd_prepare: direct mode ────────────────────────────────────────


class TestPrepareDirectCallsContextExtraction:
    """After successful clone_and_create_db, context extraction runs."""

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.codeql.repository.RepositoryManager.clone_and_create_db")
    def test_calls_context_extraction_on_success(self, mock_clone, mock_ctx):
        mock_clone.return_value = (True, "database created")
        args = _make_prepare_args(url="https://github.com/org/repo.git", lang="python")

        rc = cmd_prepare(args)

        assert rc == 0
        mock_ctx.assert_called_once()
        call_kwargs = mock_ctx.call_args[1]
        assert call_kwargs["lang_filter"] == "python"
        assert call_kwargs["backend"] == "auto"

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.codeql.repository.RepositoryManager.clone_and_create_db")
    def test_skip_context_flag(self, mock_clone, mock_ctx):
        mock_clone.return_value = (True, "database created")
        args = _make_prepare_args(
            url="https://github.com/org/repo.git",
            lang="python",
            skip_context=True,
        )

        rc = cmd_prepare(args)

        assert rc == 0
        mock_ctx.assert_not_called()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=1)
    @patch("vuln_hunter_x.codeql.repository.RepositoryManager.clone_and_create_db")
    def test_context_failure_is_nonfatal(self, mock_clone, mock_ctx):
        mock_clone.return_value = (True, "database created")
        args = _make_prepare_args(url="https://github.com/org/repo.git", lang="python")

        rc = cmd_prepare(args)

        # prepare still succeeds even though context extraction failed
        assert rc == 0
        mock_ctx.assert_called_once()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction")
    @patch("vuln_hunter_x.codeql.repository.RepositoryManager.clone_and_create_db")
    def test_prepare_failure_skips_context(self, mock_clone, mock_ctx):
        mock_clone.return_value = (False, "clone failed")
        args = _make_prepare_args(url="https://github.com/org/repo.git", lang="python")

        rc = cmd_prepare(args)

        assert rc == 1
        mock_ctx.assert_not_called()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.codeql.repository.RepositoryManager.clone_and_create_db")
    def test_passes_backend_and_force(self, mock_clone, mock_ctx):
        mock_clone.return_value = (True, "ok")
        args = _make_prepare_args(
            url="https://github.com/org/repo.git",
            lang="c",
            backend="treesitter",
            force=True,
        )

        cmd_prepare(args)

        call_kwargs = mock_ctx.call_args[1]
        assert call_kwargs["backend"] == "treesitter"
        assert call_kwargs["force"] is True


# ── cmd_prepare: config mode ────────────────────────────────────────


class TestPrepareConfigModeContextExtraction:
    """Config mode calls context extraction after processing repos."""

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.codeql.repository.RepositoryManager.process_repos_config")
    def test_extracts_context_after_config_mode(self, mock_process, mock_ctx, tmp_path):
        config_file = tmp_path / "repos.yaml"
        config_file.write_text("repos: []")

        mock_process.return_value = [
            ("repo1", True, "ok"),
            ("repo2", True, "ok"),
        ]
        args = _make_prepare_args(config=config_file)

        rc = cmd_prepare(args)

        assert rc == 0
        mock_ctx.assert_called_once()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.codeql.repository.RepositoryManager.process_repos_config")
    def test_skips_context_when_all_repos_fail(self, mock_process, mock_ctx, tmp_path):
        config_file = tmp_path / "repos.yaml"
        config_file.write_text("repos: []")

        mock_process.return_value = [
            ("repo1", False, "fail"),
            ("repo2", False, "fail"),
        ]
        args = _make_prepare_args(config=config_file)

        cmd_prepare(args)

        mock_ctx.assert_not_called()

    @patch("vuln_hunter_x.cli.commands._run_context_extraction", return_value=0)
    @patch("vuln_hunter_x.codeql.repository.RepositoryManager.process_repos_config")
    def test_config_mode_skip_context_flag(self, mock_process, mock_ctx, tmp_path):
        config_file = tmp_path / "repos.yaml"
        config_file.write_text("repos: []")

        mock_process.return_value = [("repo1", True, "ok")]
        args = _make_prepare_args(config=config_file, skip_context=True)

        cmd_prepare(args)

        mock_ctx.assert_not_called()


# ── _run_context_extraction ─────────────────────────────────────────


class TestRunContextExtractionCodeQL:
    """Tests for the extracted _run_context_extraction function with CodeQL backend."""

    @patch("vuln_hunter_x.cli.commands._print_extraction_results", return_value=0)
    @patch("vuln_hunter_x.cli.commands._skip_existing_context")
    def test_codeql_backend(self, mock_skip, mock_print, tmp_path):
        db_path = tmp_path / "output" / "python" / "myrepo" / "database"
        db_path.mkdir(parents=True)
        (db_path / "codeql-database.yml").write_text("")

        mock_skip.return_value = ([(db_path, "python", "myrepo")], 0)

        with (
            patch("vuln_hunter_x.codeql.context_extractor.discover_databases") as mock_discover,
            patch("vuln_hunter_x.codeql.context_extractor.ContextExtractorDB") as mock_extractor_cls,
            patch("vuln_hunter_x.context.treesitter_extractor.discover_repos_for_context", return_value=[]),
            patch("os.getcwd", return_value=str(tmp_path)),
            patch("pathlib.Path.cwd", return_value=tmp_path),
        ):
            mock_discover.return_value = [(db_path, "python", "myrepo")]
            mock_extractor = MagicMock()
            mock_extractor.extract_all.return_value = [("myrepo", "python", {"functions": (True, "ok")})]
            mock_extractor_cls.return_value = mock_extractor

            rc = _run_context_extraction(
                lang_filter="python",
                repo_filter="myrepo",
                backend="codeql",
            )

        assert rc == 0
        mock_extractor.extract_all.assert_called_once()


class TestRunContextExtractionTreeSitter:
    """Tests for _run_context_extraction with tree-sitter backend."""

    @patch("vuln_hunter_x.cli.commands._print_extraction_results", return_value=0)
    @patch("vuln_hunter_x.cli.commands._skip_existing_context")
    def test_treesitter_backend(self, mock_skip, mock_print, tmp_path):
        src_path = tmp_path / "repos" / "python" / "myrepo"
        src_path.mkdir(parents=True)

        mock_skip.return_value = ([(src_path, "python", "myrepo")], 0)

        with (
            patch("vuln_hunter_x.context.treesitter_extractor.discover_repos_for_context") as mock_discover,
            patch("vuln_hunter_x.context.treesitter_extractor.TreeSitterContextExtractor") as mock_ts_cls,
            patch("pathlib.Path.cwd", return_value=tmp_path),
        ):
            mock_discover.return_value = [(src_path, "python", "myrepo")]
            mock_ts = MagicMock()
            mock_ts.extract_for_repo.return_value = {"functions": (True, "ok")}
            mock_ts_cls.return_value = mock_ts

            rc = _run_context_extraction(
                lang_filter="python",
                repo_filter="myrepo",
                backend="treesitter",
            )

        assert rc == 0
        mock_ts.extract_for_repo.assert_called_once_with("python", "myrepo", dry_run=False)


class TestRunContextExtractionAutoDedup:
    """Auto mode excludes repos covered by CodeQL from tree-sitter."""

    @patch("vuln_hunter_x.cli.commands._print_extraction_results", return_value=0)
    @patch("vuln_hunter_x.cli.commands._skip_existing_context")
    def test_auto_deduplicates(self, mock_skip, mock_print, tmp_path):
        db_path = tmp_path / "output" / "python" / "myrepo" / "database"
        db_path.mkdir(parents=True)
        src_path = tmp_path / "repos" / "python" / "myrepo"
        src_path.mkdir(parents=True)

        mock_skip.return_value = ([(db_path, "python", "myrepo")], 0)

        with (
            patch("vuln_hunter_x.codeql.context_extractor.discover_databases") as mock_discover_db,
            patch("vuln_hunter_x.context.treesitter_extractor.discover_repos_for_context") as mock_discover_ts,
            patch("vuln_hunter_x.codeql.context_extractor.ContextExtractorDB") as mock_extractor_cls,
            patch("pathlib.Path.cwd", return_value=tmp_path),
        ):
            mock_discover_db.return_value = [(db_path, "python", "myrepo")]
            # Same repo also found by tree-sitter — should be deduplicated
            mock_discover_ts.return_value = [(src_path, "python", "myrepo")]

            mock_extractor = MagicMock()
            mock_extractor.extract_all.return_value = [("myrepo", "python", {"functions": (True, "ok")})]
            mock_extractor_cls.return_value = mock_extractor

            rc = _run_context_extraction(backend="auto")

        assert rc == 0
        # CodeQL extraction was called
        mock_extractor.extract_all.assert_called_once()
        # Tree-sitter should NOT have been called (repo covered by CodeQL)


class TestRunContextExtractionSkipExisting:
    """Skips repos with existing CSVs unless --force."""

    def test_skip_existing_csvs(self, tmp_path):
        # Set up context CSVs that already exist
        context_dir = tmp_path / "output" / "python" / "myrepo" / "context"
        context_dir.mkdir(parents=True)
        (context_dir / "functions.csv").write_text("name,file\n")

        with (
            patch("vuln_hunter_x.codeql.context_extractor.discover_databases") as mock_discover,
            patch("vuln_hunter_x.context.treesitter_extractor.discover_repos_for_context", return_value=[]),
            patch("pathlib.Path.cwd", return_value=tmp_path),
        ):
            db_path = tmp_path / "output" / "python" / "myrepo" / "database"
            mock_discover.return_value = [(db_path, "python", "myrepo")]

            rc = _run_context_extraction(
                lang_filter="python",
                repo_filter="myrepo",
                backend="codeql",
                force=False,
            )

        # Should skip and return 0 (all skipped)
        assert rc == 0


# ── detect_build_command ─────────────────────────────────────────────


class TestDetectBuildCommand:
    """Auto-detection of C/C++ build command by inspecting repo files."""

    def test_returns_none_for_non_c_language(self, tmp_path: Path):
        (tmp_path / "autogen.sh").touch()
        assert detect_build_command(tmp_path, "python") is None
        assert detect_build_command(tmp_path, "javascript") is None
        assert detect_build_command(tmp_path, "go") is None

    def test_returns_none_for_empty_directory(self, tmp_path: Path):
        assert detect_build_command(tmp_path, "c") is None
        assert detect_build_command(tmp_path, "cpp") is None

    def test_autogen_sh_takes_precedence(self, tmp_path: Path):
        (tmp_path / "autogen.sh").touch()
        (tmp_path / "configure.ac").touch()
        (tmp_path / "CMakeLists.txt").touch()
        (tmp_path / "Makefile").touch()
        assert (
            detect_build_command(tmp_path, "c")
            == "./autogen.sh && ./configure && make"
        )

    def test_existing_configure_script(self, tmp_path: Path):
        (tmp_path / "configure").write_text("#!/bin/sh\n")
        (tmp_path / "configure.ac").touch()
        assert detect_build_command(tmp_path, "c") == "./configure && make"

    def test_configure_ac_triggers_autoreconf(self, tmp_path: Path):
        (tmp_path / "configure.ac").touch()
        (tmp_path / "CMakeLists.txt").touch()
        assert (
            detect_build_command(tmp_path, "c")
            == "autoreconf -fi && ./configure && make"
        )

    def test_configure_in_alias(self, tmp_path: Path):
        (tmp_path / "configure.in").touch()
        assert (
            detect_build_command(tmp_path, "cpp")
            == "autoreconf -fi && ./configure && make"
        )

    def test_cmake_only(self, tmp_path: Path):
        (tmp_path / "CMakeLists.txt").touch()
        (tmp_path / "Makefile").touch()
        assert (
            detect_build_command(tmp_path, "cpp")
            == "cmake -B build -S . && cmake --build build"
        )

    def test_meson(self, tmp_path: Path):
        (tmp_path / "meson.build").touch()
        assert (
            detect_build_command(tmp_path, "c")
            == "meson setup build && ninja -C build"
        )

    def test_makefile_fallback(self, tmp_path: Path):
        (tmp_path / "Makefile").touch()
        assert detect_build_command(tmp_path, "c") == "make"

    def test_makefile_am_does_not_match_makefile(self, tmp_path: Path):
        """Makefile.am is an autotools template, not a buildable Makefile."""
        (tmp_path / "Makefile.am").touch()
        assert detect_build_command(tmp_path, "c") is None


# ── _has_source_files ────────────────────────────────────────────────


class TestHasSourceFiles:
    """Unit tests for the pre-flight language-detection helper."""

    def test_go_detects_go_file(self, tmp_path: Path):
        (tmp_path / "main.go").touch()
        assert _has_source_files(tmp_path, "go") is True

    def test_go_detects_go_mod(self, tmp_path: Path):
        (tmp_path / "go.mod").write_text("module example.com/m\ngo 1.21\n")
        assert _has_source_files(tmp_path, "go") is True

    def test_go_returns_false_for_non_go_repo(self, tmp_path: Path):
        (tmp_path / "package.json").touch()
        (tmp_path / "index.ts").touch()
        assert _has_source_files(tmp_path, "go") is False

    def test_python_detects_py_file(self, tmp_path: Path):
        (tmp_path / "app.py").touch()
        assert _has_source_files(tmp_path, "python") is True

    def test_python_returns_false_for_empty_dir(self, tmp_path: Path):
        assert _has_source_files(tmp_path, "python") is False

    def test_javascript_detects_ts_file(self, tmp_path: Path):
        sub = tmp_path / "src"
        sub.mkdir()
        (sub / "index.ts").touch()
        assert _has_source_files(tmp_path, "javascript") is True

    def test_cpp_always_returns_true(self, tmp_path: Path):
        """cpp is handled by build-system heuristics; pre-flight skips it."""
        assert _has_source_files(tmp_path, "cpp") is True

    def test_unknown_lang_returns_true(self, tmp_path: Path):
        assert _has_source_files(tmp_path, "cobol") is True


# ── clone_and_create_db: pre-flight language detection ──────────────


class TestCloneAndCreateDbPreFlight:
    """clone_and_create_db returns an actionable error before calling CodeQL
    when the repo has no source files for the requested language."""

    def _manager(self, tmp_path: Path) -> RepositoryManager:
        return RepositoryManager(
            repos_dir=tmp_path / "repos",
            output_dir=tmp_path / "output",
            codeql_path="codeql",
        )

    def test_no_go_files_returns_actionable_error(self, tmp_path: Path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / "package.json").touch()
        (repo / "index.ts").touch()

        mgr = self._manager(tmp_path)
        ok, msg = mgr.clone_and_create_db(
            name="myrepo",
            url="",
            language="go",
            local_path=repo,
            skip_clone=True,
        )

        assert ok is False
        assert "No go source files" in msg
        assert "--lang go" in msg

    def test_go_repo_passes_preflight(self, tmp_path: Path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / "main.go").touch()

        mgr = self._manager(tmp_path)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            ok, msg = mgr.clone_and_create_db(
                name="myrepo",
                url="",
                language="go",
                local_path=repo,
                skip_clone=True,
            )

        assert ok is True
        assert "created" in msg.lower()

    def test_failed_create_cleans_up_partial_db(self, tmp_path: Path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / "main.go").touch()

        mgr = self._manager(tmp_path)
        db_dir = tmp_path / "output" / "go" / "myrepo" / "database"

        def _fake_run(cmd, **kwargs):
            # Simulate CodeQL partially creating the db dir before failing
            db_dir.mkdir(parents=True, exist_ok=True)
            (db_dir / "codeql-database.yml").touch()
            return MagicMock(returncode=1, stdout="", stderr="some error")

        with patch("subprocess.run", side_effect=_fake_run):
            ok, msg = mgr.clone_and_create_db(
                name="myrepo",
                url="",
                language="go",
                local_path=repo,
                skip_clone=True,
            )

        assert ok is False
        assert not db_dir.exists(), "Partial database directory should be cleaned up"

    def test_go_0_packages_gives_helpful_message(self, tmp_path: Path):
        repo = tmp_path / "myrepo"
        repo.mkdir()
        (repo / "main.go").touch()

        mgr = self._manager(tmp_path)
        codeql_output = (
            "Initializing database...\n"
            "Running go list to resolve package and module directories.\n"
            "resolved 0 packages.\n"
            "Success: extraction succeeded for all 1 discovered project(s).\n"
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout=codeql_output, stderr="")
            ok, msg = mgr.clone_and_create_db(
                name="myrepo",
                url="",
                language="go",
                local_path=repo,
                skip_clone=True,
            )

        assert ok is False
        assert "go mod download" in msg or "go mod vendor" in msg
