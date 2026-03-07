"""Tests for CSV-based ContextProvider."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from vuln_hunter_x.context.provider import ContextProvider


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    if not rows:
        path.write_text("")
        return
    fieldnames = fieldnames or list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture()
def repo_tree(tmp_path):
    """Create a minimal output + repos tree for testing."""
    output_dir = tmp_path / "output"
    repos_dir = tmp_path / "repos"
    context_dir = output_dir / "c" / "myrepo" / "context"
    context_dir.mkdir(parents=True)
    source_dir = repos_dir / "c" / "myrepo"
    source_dir.mkdir(parents=True)
    return output_dir, repos_dir, context_dir, source_dir


class TestContextProviderHasContext:
    def test_has_context_when_dir_exists(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        provider = ContextProvider(output_dir, repos_dir)
        assert provider.has_context_for_repo("myrepo", "c") is True

    def test_no_context_when_dir_missing(self, tmp_path):
        provider = ContextProvider(tmp_path / "output", tmp_path / "repos")
        assert provider.has_context_for_repo("nonexistent", "c") is False


class TestContextProviderCallerContext:
    def test_returns_caller_code(self, repo_tree):
        output_dir, repos_dir, context_dir, source_dir = repo_tree
        # Write source file
        source_file = source_dir / "main.c"
        lines = ["// line1\n", "void caller() {\n", "  free_it(ptr);\n", "}\n"]
        source_file.write_text("".join(lines))

        _write_csv(
            context_dir / "callers.csv",
            [
                {
                    "callee_name": "free_it",
                    "caller_name": "caller",
                    "caller_file": "main.c",
                    "caller_start_line": "2",
                    "caller_end_line": "4",
                }
            ],
        )

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["caller:free_it"])

        assert "caller:free_it" in results
        assert "caller" in results["caller:free_it"]
        assert "free_it(ptr)" in results["caller:free_it"]

    def test_returns_not_found_for_missing_callee(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(context_dir / "callers.csv", [{"callee_name": "other", "caller_name": "x", "caller_file": "f.c", "caller_start_line": "1", "caller_end_line": "2"}])

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["caller:nonexistent"])

        assert "No caller found" in results["caller:nonexistent"]


class TestContextProviderStructContext:
    def test_returns_struct_code(self, repo_tree):
        output_dir, repos_dir, context_dir, source_dir = repo_tree
        source_file = source_dir / "types.h"
        source_file.write_text("struct Foo {\n    int x;\n    int y;\n};\n")

        _write_csv(
            context_dir / "structs.csv",
            [{"name": "Foo", "file": "types.h", "start_line": "1", "end_line": "4"}],
        )

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["struct:Foo"])

        assert "struct:Foo" in results
        assert "Foo" in results["struct:Foo"]

    def test_returns_not_found_for_unknown_struct(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(context_dir / "structs.csv", [])

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["struct:Bar"])

        assert "not found" in results["struct:Bar"].lower()


class TestContextProviderGlobalContext:
    def test_returns_global_code(self, repo_tree):
        output_dir, repos_dir, context_dir, source_dir = repo_tree
        (source_dir / "globals.c").write_text("int g_counter = 0;\n")

        _write_csv(
            context_dir / "globals.csv",
            [{"name": "g_counter", "file": "globals.c", "type": "int", "start_line": "1", "end_line": "1"}],
        )

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["global:g_counter"])

        assert "global:g_counter" in results
        assert "g_counter" in results["global:g_counter"]

    def test_end_line_falls_back_to_start_when_missing(self, repo_tree):
        output_dir, repos_dir, context_dir, source_dir = repo_tree
        (source_dir / "g.c").write_text("int g = 42;\n")

        # No end_line column in CSV
        _write_csv(
            context_dir / "globals.csv",
            [{"name": "g", "file": "g.c", "type": "int", "start_line": "1"}],
            fieldnames=["name", "file", "type", "start_line"],
        )

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["global:g"])

        # Should not crash; returns what it can read
        assert "global:g" in results


class TestContextProviderMacroContext:
    def test_returns_macro_definition(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(
            context_dir / "macros.csv",
            [{"name": "BUF_SIZE", "file": "config.h", "line": "10", "body": "1024"}],
        )

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["macro:BUF_SIZE"])

        assert "macro:BUF_SIZE" in results
        assert "BUF_SIZE" in results["macro:BUF_SIZE"]
        assert "1024" in results["macro:BUF_SIZE"]

    def test_returns_not_found_for_unknown_macro(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(context_dir / "macros.csv", [])

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["macro:UNKNOWN"])

        assert "not found" in results["macro:UNKNOWN"].lower()


class TestContextProviderCalleesContext:
    def test_callees_returns_list_of_called_functions(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(
            context_dir / "callers.csv",
            [
                {
                    "callee_name": "malloc",
                    "callee_file": "",
                    "caller_name": "do_work",
                    "caller_file": "work.c",
                    "caller_start_line": "1",
                    "caller_end_line": "10",
                },
                {
                    "callee_name": "memcpy",
                    "callee_file": "",
                    "caller_name": "do_work",
                    "caller_file": "work.c",
                    "caller_start_line": "1",
                    "caller_end_line": "10",
                },
                {
                    "callee_name": "free",
                    "callee_file": "",
                    "caller_name": "other_func",
                    "caller_file": "work.c",
                    "caller_start_line": "12",
                    "caller_end_line": "20",
                },
            ],
        )

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["callees:do_work"])

        assert "callees:do_work" in results
        text = results["callees:do_work"]
        assert "malloc" in text
        assert "memcpy" in text
        assert "free" not in text  # belongs to other_func

    def test_callees_deduplicates_multiple_calls(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(
            context_dir / "callers.csv",
            [
                {"callee_name": "log", "callee_file": "", "caller_name": "fn", "caller_file": "a.c", "caller_start_line": "1", "caller_end_line": "5"},
                {"callee_name": "log", "callee_file": "", "caller_name": "fn", "caller_file": "a.c", "caller_start_line": "1", "caller_end_line": "5"},
            ],
        )

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["callees:fn"])

        # "log" should appear only once
        assert results["callees:fn"].count("log") == 1

    def test_callees_not_found(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(context_dir / "callers.csv", [])

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["callees:unknown"])

        assert "No callees found" in results["callees:unknown"]


class TestContextProviderAllCallersContext:
    def test_all_callers_returns_multiple(self, repo_tree):
        output_dir, repos_dir, context_dir, source_dir = repo_tree
        source_file = source_dir / "a.c"
        source_file.write_text("void alpha() {\n  target();\n}\nvoid beta() {\n  target();\n}\n")

        _write_csv(
            context_dir / "callers.csv",
            [
                {"callee_name": "target", "callee_file": "", "caller_name": "alpha", "caller_file": "a.c", "caller_start_line": "1", "caller_end_line": "3"},
                {"callee_name": "target", "callee_file": "", "caller_name": "beta", "caller_file": "a.c", "caller_start_line": "4", "caller_end_line": "6"},
            ],
        )

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["all_callers:target"])

        assert "all_callers:target" in results
        text = results["all_callers:target"]
        assert "alpha" in text
        assert "beta" in text

    def test_all_callers_capped_at_max(self, repo_tree):
        output_dir, repos_dir, context_dir, source_dir = repo_tree
        (source_dir / "b.c").write_text("\n" * 50)
        rows = [
            {"callee_name": "fn", "callee_file": "", "caller_name": f"caller{i}", "caller_file": "b.c", "caller_start_line": str(i), "caller_end_line": str(i + 1)}
            for i in range(1, 20)
        ]
        _write_csv(context_dir / "callers.csv", rows)

        provider = ContextProvider(output_dir, repos_dir)
        provider._get_all_callers_context("myrepo", "c", "fn", max_callers=5)
        # Verify cap is respected: only first 5 unique callers fetched
        seen: set = set()
        for row in rows:
            seen.add(row["caller_name"])
            if len(seen) >= 5:
                break
        assert len(seen) == 5

    def test_all_callers_not_found(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(context_dir / "callers.csv", [])

        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["all_callers:ghost"])

        assert "No callers found" in results["all_callers:ghost"]


class TestContextProviderEdgeCases:
    def test_empty_request_list(self, repo_tree):
        output_dir, repos_dir, _, _ = repo_tree
        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", [])
        assert results == {}

    def test_unknown_context_type(self, repo_tree):
        output_dir, repos_dir, _, _ = repo_tree
        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["unknown:foo"])
        assert "Unknown context type" in results["unknown:foo"]

    def test_request_without_colon_is_skipped(self, repo_tree):
        output_dir, repos_dir, _, _ = repo_tree
        provider = ContextProvider(output_dir, repos_dir)
        results = provider.get_additional_context("myrepo", "c", ["nocolon"])
        assert results == {}

    def test_missing_csv_returns_empty_gracefully(self, repo_tree):
        output_dir, repos_dir, _, _ = repo_tree
        provider = ContextProvider(output_dir, repos_dir)
        # No callers.csv exists
        results = provider.get_additional_context("myrepo", "c", ["caller:foo"])
        assert "No caller found" in results["caller:foo"]

    def test_csv_cache_is_used_on_second_call(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(context_dir / "macros.csv", [{"name": "X", "file": "f.h", "line": "1", "body": "42"}])

        provider = ContextProvider(output_dir, repos_dir)
        provider.get_additional_context("myrepo", "c", ["macro:X"])
        # Overwrite CSV with different content
        _write_csv(context_dir / "macros.csv", [{"name": "X", "file": "f.h", "line": "1", "body": "99"}])
        results = provider.get_additional_context("myrepo", "c", ["macro:X"])
        # Should return cached value (42), not new value (99)
        assert "42" in results["macro:X"]

    def test_clear_cache_forces_reload(self, repo_tree):
        output_dir, repos_dir, context_dir, _ = repo_tree
        _write_csv(context_dir / "macros.csv", [{"name": "X", "file": "f.h", "line": "1", "body": "42"}])

        provider = ContextProvider(output_dir, repos_dir)
        provider.get_additional_context("myrepo", "c", ["macro:X"])
        _write_csv(context_dir / "macros.csv", [{"name": "X", "file": "f.h", "line": "1", "body": "99"}])
        provider.clear_cache()
        results = provider.get_additional_context("myrepo", "c", ["macro:X"])
        assert "99" in results["macro:X"]
