"""Tests for tree-sitter context extraction."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from vuln_hunter_x.context.treesitter_extractor import (
    CSV_FIELDS,
    TreeSitterContextExtractor,
    discover_repos_for_context,
)


# ── Fixtures ──────────────────────────────────────────────────────


@pytest.fixture()
def setup_repo(tmp_path: Path):
    """Create a minimal repo layout for testing.

    Returns (repos_dir, output_dir, lang, repo_name).
    """

    def _setup(lang: str, repo_name: str, files: dict[str, str]):
        repos_dir = tmp_path / "repos"
        output_dir = tmp_path / "output"

        # Create source files
        repo_src = repos_dir / lang / repo_name
        repo_src.mkdir(parents=True)
        for name, content in files.items():
            fpath = repo_src / name
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content)

        # Create output dir with a dummy SARIF (so discover works)
        repo_out = output_dir / lang / repo_name
        repo_out.mkdir(parents=True)
        (repo_out / f"{repo_name}_semgrep.sarif").write_text("{}")

        return repos_dir, output_dir, lang, repo_name

    return _setup


def _read_csv(path: Path) -> list[dict]:
    """Read a CSV file and return list of dicts."""
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


# ── discover_repos_for_context ────────────────────────────────────


class TestDiscoverRepos:
    def test_finds_repo_with_sarif_and_source(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "c", "myrepo", {"main.c": "int main() { return 0; }"}
        )
        result = discover_repos_for_context(output_dir, repos_dir)
        assert len(result) == 1
        assert result[0][1] == "c"
        assert result[0][2] == "myrepo"

    def test_skips_repo_with_codeql_db(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "c", "myrepo", {"main.c": "int main() {}"}
        )
        # Add CodeQL database marker
        db_dir = output_dir / "c" / "myrepo" / "database"
        db_dir.mkdir(parents=True)
        (db_dir / "codeql-database.yml").write_text("")

        result = discover_repos_for_context(output_dir, repos_dir)
        assert len(result) == 0

    def test_skips_repo_without_sarif(self, tmp_path):
        repos_dir = tmp_path / "repos" / "c" / "myrepo"
        repos_dir.mkdir(parents=True)
        (repos_dir / "main.c").write_text("int main() {}")
        output_dir = tmp_path / "output" / "c" / "myrepo"
        output_dir.mkdir(parents=True)
        # No SARIF file

        result = discover_repos_for_context(tmp_path / "output", tmp_path / "repos")
        assert len(result) == 0

    def test_skips_repo_without_source(self, tmp_path):
        output_dir = tmp_path / "output" / "c" / "myrepo"
        output_dir.mkdir(parents=True)
        (output_dir / "myrepo_semgrep.sarif").write_text("{}")
        # No repos dir

        result = discover_repos_for_context(tmp_path / "output", tmp_path / "repos")
        assert len(result) == 0


# ── C function extraction ─────────────────────────────────────────

C_SOURCE = """\
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

void greet(const char *name) {
    printf("Hello %s\\n", name);
}

int main(int argc, char **argv) {
    int result = add(1, 2);
    greet("world");
    return 0;
}
"""


class TestExtractFunctionsC:
    def test_extracts_all_functions(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo("c", "testrepo", {"main.c": C_SOURCE})
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        results = ext.extract_for_repo("c", "testrepo")

        assert results["functions"][0] is True
        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "functions.csv")
        names = {r["name"] for r in rows}
        assert "add" in names
        assert "greet" in names
        assert "main" in names

    def test_function_csv_schema(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo("c", "testrepo", {"main.c": C_SOURCE})
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "functions.csv")
        assert len(rows) > 0
        for row in rows:
            assert set(row.keys()) == set(CSV_FIELDS["functions"])
            assert int(row["start_line"]) >= 1
            assert int(row["end_line"]) >= int(row["start_line"])

    def test_param_count(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo("c", "testrepo", {"main.c": C_SOURCE})
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "functions.csv")
        by_name = {r["name"]: r for r in rows}
        assert int(by_name["add"]["param_count"]) == 2
        assert int(by_name["greet"]["param_count"]) == 1


# ── C caller extraction ──────────────────────────────────────────


class TestExtractCallersC:
    def test_extracts_callers(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo("c", "testrepo", {"main.c": C_SOURCE})
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "callers.csv")
        # main() calls add() and greet()
        callee_names = {r["callee_name"] for r in rows}
        assert "add" in callee_names
        assert "greet" in callee_names

    def test_caller_info_correct(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo("c", "testrepo", {"main.c": C_SOURCE})
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "callers.csv")
        add_callers = [r for r in rows if r["callee_name"] == "add"]
        assert len(add_callers) >= 1
        assert add_callers[0]["caller_name"] == "main"
        assert set(add_callers[0].keys()) == set(CSV_FIELDS["callers"])


# ── C struct extraction ──────────────────────────────────────────

C_STRUCT_SOURCE = """\
struct Point {
    int x;
    int y;
};

struct Color {
    unsigned char r;
    unsigned char g;
    unsigned char b;
};
"""


class TestExtractStructsC:
    def test_extracts_structs(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "c", "testrepo", {"types.c": C_STRUCT_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "structs.csv")
        struct_names = {r["name"] for r in rows}
        assert "Point" in struct_names
        assert "Color" in struct_names

    def test_struct_members(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "c", "testrepo", {"types.c": C_STRUCT_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "structs.csv")
        point_members = {r["member_name"] for r in rows if r["name"] == "Point"}
        assert "x" in point_members
        assert "y" in point_members


# ── C global extraction ──────────────────────────────────────────

C_GLOBAL_SOURCE = """\
int global_count = 0;
const char *app_name = "test";

void foo() {
    int local_var = 1;
}
"""


class TestExtractGlobalsC:
    def test_extracts_globals(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "c", "testrepo", {"globals.c": C_GLOBAL_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "globals.csv")
        names = {r["name"] for r in rows}
        assert "global_count" in names
        assert set(rows[0].keys()) == set(CSV_FIELDS["globals"])


# ── C macro extraction ───────────────────────────────────────────

C_MACRO_SOURCE = """\
#define MAX_SIZE 1024
#define MIN(a, b) ((a) < (b) ? (a) : (b))
"""


class TestExtractMacrosC:
    def test_extracts_macros(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "c", "testrepo", {"macros.c": C_MACRO_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "macros.csv")
        names = {r["name"] for r in rows}
        assert "MAX_SIZE" in names
        assert "MIN" in names

    def test_macro_body(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "c", "testrepo", {"macros.c": C_MACRO_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("c", "testrepo")

        rows = _read_csv(output_dir / "c" / "testrepo" / "context" / "macros.csv")
        by_name = {r["name"]: r for r in rows}
        assert "1024" in by_name["MAX_SIZE"]["body"]


# ── Python extraction ────────────────────────────────────────────

PYTHON_SOURCE = """\
class Animal:
    def __init__(self, name):
        self.name = name

    def speak(self):
        pass

class Dog(Animal):
    def speak(self):
        return "Woof"

def greet(name):
    print(f"Hello {name}")

def main():
    dog = Dog("Rex")
    dog.speak()
    greet("world")
"""


class TestExtractPython:
    def test_extracts_functions(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "python", "pyrepo", {"app.py": PYTHON_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("python", "pyrepo")

        rows = _read_csv(output_dir / "python" / "pyrepo" / "context" / "functions.csv")
        names = {r["name"] for r in rows}
        assert "greet" in names
        assert "main" in names
        assert "__init__" in names
        assert "speak" in names

    def test_extracts_classes(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "python", "pyrepo", {"app.py": PYTHON_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("python", "pyrepo")

        rows = _read_csv(output_dir / "python" / "pyrepo" / "context" / "classes.csv")
        names = {r["name"] for r in rows}
        assert "Animal" in names
        assert "Dog" in names

    def test_extracts_callers(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "python", "pyrepo", {"app.py": PYTHON_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("python", "pyrepo")

        rows = _read_csv(output_dir / "python" / "pyrepo" / "context" / "callers.csv")
        callee_names = {r["callee_name"] for r in rows}
        assert "greet" in callee_names


# ── JavaScript extraction ────────────────────────────────────────

JS_SOURCE = """\
class Calculator {
    add(a, b) {
        return a + b;
    }
}

function multiply(a, b) {
    return a * b;
}

function main() {
    const calc = new Calculator();
    calc.add(1, 2);
    multiply(3, 4);
}
"""


class TestExtractJavaScript:
    def test_extracts_functions(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "javascript", "jsrepo", {"app.js": JS_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("javascript", "jsrepo")

        rows = _read_csv(output_dir / "javascript" / "jsrepo" / "context" / "functions.csv")
        names = {r["name"] for r in rows}
        assert "multiply" in names
        assert "main" in names

    def test_extracts_classes(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "javascript", "jsrepo", {"app.js": JS_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        ext.extract_for_repo("javascript", "jsrepo")

        rows = _read_csv(output_dir / "javascript" / "jsrepo" / "context" / "classes.csv")
        names = {r["name"] for r in rows}
        assert "Calculator" in names


# ── Integration: extract_for_repo ─────────────────────────────────


class TestExtractForRepoIntegration:
    def test_all_csvs_produced_for_c(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "c",
            "fullrepo",
            {
                "main.c": C_SOURCE,
                "types.h": C_STRUCT_SOURCE,
                "macros.h": C_MACRO_SOURCE,
            },
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        results = ext.extract_for_repo("c", "fullrepo")

        for qt in ["functions", "callers", "structs", "globals", "macros"]:
            assert qt in results
            assert results[qt][0] is True, f"{qt} should succeed"
            csv_path = output_dir / "c" / "fullrepo" / "context" / f"{qt}.csv"
            assert csv_path.exists(), f"{qt}.csv should exist"

    def test_all_csvs_produced_for_python(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo(
            "python", "pyrepo", {"app.py": PYTHON_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        results = ext.extract_for_repo("python", "pyrepo")

        for qt in ["functions", "callers", "classes"]:
            assert qt in results
            assert results[qt][0] is True
            csv_path = output_dir / "python" / "pyrepo" / "context" / f"{qt}.csv"
            assert csv_path.exists()

    def test_dry_run_produces_no_files(self, setup_repo):
        repos_dir, output_dir, lang, name = setup_repo("c", "testrepo", {"main.c": C_SOURCE})
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        results = ext.extract_for_repo("c", "testrepo", dry_run=True)

        for qt, (ok, msg) in results.items():
            assert ok is True
            assert "dry-run" in msg
        context_dir = output_dir / "c" / "testrepo" / "context"
        assert not context_dir.exists() or not list(context_dir.glob("*.csv"))

    def test_no_source_files_reports_failure(self, setup_repo):
        repos_dir, output_dir, _, _ = setup_repo("c", "emptyrepo", {})
        # Remove the empty repo dir content (setup created it)
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        results = ext.extract_for_repo("c", "emptyrepo")

        for qt, (ok, msg) in results.items():
            assert ok is False
            assert "No source files" in msg


# ── extract_all ───────────────────────────────────────────────────


class TestExtractAll:
    def test_filters_by_lang(self, setup_repo):
        repos_dir, output_dir, _, _ = setup_repo("c", "crepo", {"main.c": C_SOURCE})
        # Add a Python repo too
        py_src = repos_dir / "python" / "pyrepo"
        py_src.mkdir(parents=True)
        (py_src / "app.py").write_text(PYTHON_SOURCE)
        py_out = output_dir / "python" / "pyrepo"
        py_out.mkdir(parents=True)
        (py_out / "pyrepo_semgrep.sarif").write_text("{}")

        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        results = ext.extract_all(lang_filter="python")

        assert len(results) == 1
        assert results[0][0] == "pyrepo"

    def test_filters_by_repo(self, setup_repo):
        repos_dir, output_dir, _, _ = setup_repo("c", "repo1", {"main.c": C_SOURCE})
        # Add another C repo
        repo2 = repos_dir / "c" / "repo2"
        repo2.mkdir(parents=True)
        (repo2 / "main.c").write_text(C_SOURCE)
        repo2_out = output_dir / "c" / "repo2"
        repo2_out.mkdir(parents=True)
        (repo2_out / "repo2_semgrep.sarif").write_text("{}")

        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        results = ext.extract_all(repo_filter="repo1")

        assert len(results) == 1
        assert results[0][0] == "repo1"
