# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Tests for `cmd_analyze`'s source-root → DB-name resolution.

This covers the case where a user runs:
    vuln-hunter-x prepare --local-path test-apps/foo --name libfoo --lang c
    vuln-hunter-x analyze --local-path test-apps/foo --lang c   # no --name

Without resolution, analyze auto-derives the basename `foo` and misses
the DB stored under `output/c/libfoo/database`. The fix scans existing
DBs' codeql-database.yml for a matching `sourceLocationPrefix`.
"""

from __future__ import annotations

from pathlib import Path

from vuln_hunter_x.cli.commands import _find_db_name_by_source_root


def _make_db(output_dir: Path, lang: str, name: str, source_root: Path) -> None:
    """Create a fake CodeQL DB layout with the minimal yaml we read."""
    db_dir = output_dir / lang / name / "database"
    db_dir.mkdir(parents=True, exist_ok=True)
    yml = db_dir / "codeql-database.yml"
    yml.write_text(
        f"---\nsourceLocationPrefix: {source_root}\nprimaryLanguage: cpp\n",
        encoding="utf-8",
    )


class TestFindDbBySourceRoot:
    def test_unique_match_returns_db_name(self, tmp_path: Path):
        output = tmp_path / "output"
        src = tmp_path / "test-apps" / "vorbis-main"
        src.mkdir(parents=True)
        _make_db(output, "c", "libvorbis", src.resolve())

        assert _find_db_name_by_source_root(src, "c", output) == "libvorbis"

    def test_no_match_returns_none(self, tmp_path: Path):
        output = tmp_path / "output"
        src_a = tmp_path / "a"
        src_b = tmp_path / "b"
        src_a.mkdir()
        src_b.mkdir()
        _make_db(output, "c", "libfoo", src_a.resolve())

        # Querying for `b` should not match the DB built from `a`.
        assert _find_db_name_by_source_root(src_b, "c", output) is None

    def test_ambiguous_match_returns_none(self, tmp_path: Path):
        output = tmp_path / "output"
        src = tmp_path / "shared"
        src.mkdir()
        _make_db(output, "c", "libfoo", src.resolve())
        _make_db(output, "c", "libfoo_again", src.resolve())

        assert _find_db_name_by_source_root(src, "c", output) is None

    def test_missing_lang_dir_returns_none(self, tmp_path: Path):
        output = tmp_path / "output"
        src = tmp_path / "x"
        src.mkdir()
        # output/c does not exist at all.
        assert _find_db_name_by_source_root(src, "c", output) is None

    def test_missing_yaml_skipped(self, tmp_path: Path):
        output = tmp_path / "output"
        src = tmp_path / "x"
        src.mkdir()
        # DB dir exists but yaml is missing — skipped.
        (output / "c" / "ghost" / "database").mkdir(parents=True)
        assert _find_db_name_by_source_root(src, "c", output) is None

    def test_match_handles_relative_local_path(self, tmp_path: Path, monkeypatch):
        """User passes a relative path; resolution must compare resolved absolutes."""
        output = tmp_path / "output"
        src = tmp_path / "test-apps" / "vorbis"
        src.mkdir(parents=True)
        _make_db(output, "c", "libvorbis", src.resolve())

        monkeypatch.chdir(tmp_path)
        relative = Path("test-apps/vorbis")
        assert _find_db_name_by_source_root(relative, "c", output) == "libvorbis"

    def test_other_languages_isolated(self, tmp_path: Path):
        """A python DB for the same source root should not match a c-language query."""
        output = tmp_path / "output"
        src = tmp_path / "shared-src"
        src.mkdir()
        _make_db(output, "python", "libfoo", src.resolve())

        assert _find_db_name_by_source_root(src, "c", output) is None
