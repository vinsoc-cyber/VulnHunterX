"""Tests for verification engine (e.g. test path exclusion)."""

from __future__ import annotations

import pytest

from vuln_hunter_x.verification.engine import _is_test_path


class TestIsTestPath:
    """Tests for _is_test_path helper."""

    def test_tests_segment(self):
        assert _is_test_path("repo/tests/foo.c") is True
        assert _is_test_path("tests/unit/bar.py") is True
        assert _is_test_path("/abs/path/tests/baz.js") is True

    def test_test_segment(self):
        assert _is_test_path("repo/test/foo.c") is True
        assert _is_test_path("test/unit/bar.py") is True
        assert _is_test_path("/abs/path/test/baz.js") is True

    def test_file_uri(self):
        assert _is_test_path("file:///repo/tests/foo.c") is True
        assert _is_test_path("file:///repo/test/bar.py") is True

    def test_not_test_path(self):
        assert _is_test_path("src/foo.c") is False
        assert _is_test_path("contest.c") is False
        assert _is_test_path("lib/testing/helper.py") is False
        assert _is_test_path("") is False

    def test_backslash_normalized(self):
        assert _is_test_path("repo\\tests\\foo.c") is True
        assert _is_test_path("repo\\test\\bar.py") is True

    def test_spec_directory_not_matched(self):
        # spec/ is not in the default exclusion list
        assert _is_test_path("src/spec/foo.js") is False

    def test_test_word_in_filename_not_matched(self):
        # "testing_helper.py" or "contest.c" should NOT be excluded
        assert _is_test_path("src/testing/helper.py") is False
        assert _is_test_path("src/contest.c") is False
        assert _is_test_path("unittest_utils.py") is False

    def test_deeply_nested_test_dir(self):
        assert _is_test_path("a/b/c/d/tests/e/f.c") is True
        assert _is_test_path("a/b/c/d/test/e/f.c") is True
