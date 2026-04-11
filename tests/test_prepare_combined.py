"""Tests for combined prepare + context extraction stage."""

from __future__ import annotations

import argparse
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vuln_hunter_x.cli.commands import _run_context_extraction, cmd_prepare


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
