# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for tree-sitter context extraction."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from vuln_hunter_x.codeql.context_extractor import discover_databases
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

    def test_discovers_source_repo_even_with_codeql_db(self, setup_repo):
        # Discovery no longer excludes a repo that also has a CodeQL DB: it
        # returns every source+SARIF candidate, and backend preference (prefer
        # CodeQL when it covers the repo) is applied by the caller's auto-dedup.
        repos_dir, output_dir, lang, name = setup_repo("c", "myrepo", {"main.c": "int main() {}"})
        db_dir = output_dir / "c" / "myrepo" / "database"
        db_dir.mkdir(parents=True)
        (db_dir / "codeql-database.yml").write_text("")

        result = discover_repos_for_context(output_dir, repos_dir)
        assert len(result) == 1
        assert result[0][2] == "myrepo"

    def test_finds_csharp_repo_with_db(self, setup_repo):
        # C# is tree-sitter-supported but has no CodeQL context queries, so a
        # C# repo with a DB must still be reachable via tree-sitter — it would
        # otherwise get context from neither backend.
        repos_dir, output_dir, lang, name = setup_repo(
            "csharp", "csrepo", {"Foo.cs": "class Foo {}"}
        )
        db_dir = output_dir / "csharp" / "csrepo" / "database"
        db_dir.mkdir(parents=True)
        (db_dir / "codeql-database.yml").write_text("")

        result = discover_repos_for_context(output_dir, repos_dir)
        assert len(result) == 1
        assert result[0][1] == "csharp"

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


# ── discover_databases (CodeQL side) ──────────────────────────────


class TestDiscoverDatabases:
    def test_yml_marker_is_a_database(self, tmp_path):
        db_dir = tmp_path / "output" / "c" / "myrepo" / "database"
        db_dir.mkdir(parents=True)
        (db_dir / "codeql-database.yml").write_text("")

        result = discover_databases(tmp_path / "output")
        assert len(result) == 1
        assert result[0][1] == "c"
        assert result[0][2] == "myrepo"

    def test_log_only_is_not_a_database(self, tmp_path):
        # A failed CodeQL DB attempt leaves only database/log/ (no yml). It
        # must NOT count as a database, else it shadows the tree-sitter path.
        db_dir = tmp_path / "output" / "c" / "myrepo" / "database"
        (db_dir / "log").mkdir(parents=True)

        result = discover_databases(tmp_path / "output")
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


# ── Coverage regressions (callbacks, constructors, qualified calls) ──


def _extract(setup_repo, lang: str, files: dict[str, str]) -> dict[str, list[dict]]:
    repos_dir, output_dir, _, name = setup_repo(lang, "covrepo", files)
    TreeSitterContextExtractor(repos_dir, output_dir).extract_for_repo(lang, name)
    ctx = output_dir / lang / name / "context"
    return {p.stem: _read_csv(p) for p in ctx.glob("*.csv")}


def _edges(rows: list[dict]) -> set[tuple[str, str]]:
    return {(r["caller_name"], r["callee_name"]) for r in rows}


class TestCallerAttribution:
    def test_js_call_inside_anonymous_callback_is_attributed_to_outer(self, setup_repo):
        src = (
            "function outer(app) {\n"
            "  app.get('/', (req, res) => {\n"
            "    exec(req.query.x);\n"
            "  });\n"
            "}\n"
        )
        csvs = _extract(setup_repo, "javascript", {"app.js": src})
        assert ("outer", "exec") in _edges(csvs["callers"])
        row = next(r for r in csvs["callers"] if r["callee_name"] == "exec")
        assert (row["caller_start_line"], row["caller_end_line"]) == ("1", "5")

    def test_js_bound_function_expressions_are_functions(self, setup_repo):
        src = (
            "const handler = async (req, res) => { run(req); };\n"
            "obj.method = function () { other(); };\n"
            "const single = x => x + 1;\n"
        )
        csvs = _extract(setup_repo, "javascript", {"h.js": src})
        funcs = {r["name"]: r for r in csvs["functions"]}
        assert {"handler", "method", "single"} <= set(funcs)
        assert funcs["handler"]["param_count"] == "2"
        # An arrow's single parameter is not mistaken for its name.
        assert "x" not in funcs
        assert funcs["single"]["param_count"] == "1"
        assert {("handler", "run"), ("method", "other")} <= _edges(csvs["callers"])

    def test_c_pointer_returning_function_is_extracted(self, setup_repo):
        src = "char *dup(const char *s) {\n  return strcpy(malloc(9), s);\n}\n"
        csvs = _extract(setup_repo, "c", {"a.c": src})
        assert [r["name"] for r in csvs["functions"]] == ["dup"]
        assert csvs["functions"][0]["param_count"] == "1"
        assert {("dup", "strcpy"), ("dup", "malloc")} <= _edges(csvs["callers"])

    def test_java_method_call_records_method_not_receiver(self, setup_repo):
        src = (
            "class A {\n"
            "  A() { init(); }\n"
            "  void run(String q) { stmt.executeQuery(q); }\n"
            "}\n"
        )
        csvs = _extract(setup_repo, "java", {"A.java": src})
        edges = _edges(csvs["callers"])
        assert ("run", "executeQuery") in edges
        assert not any(callee == "stmt" for _, callee in edges)
        # Constructors are functions and enclose calls.
        assert "A" in {r["name"] for r in csvs["functions"]}
        assert ("A", "init") in edges

    def test_go_selector_calls_are_recorded(self, setup_repo):
        src = "package m\nfunc Run(q string) {\n  db.Query(q)\n  exec.Command(q)\n}\n"
        csvs = _extract(setup_repo, "go", {"m.go": src})
        assert {("Run", "Query"), ("Run", "Command")} <= _edges(csvs["callers"])

    def test_go_types_are_classes(self, setup_repo):
        src = "package m\ntype Server struct {\n  addr string\n}\n"
        csvs = _extract(setup_repo, "go", {"m.go": src})
        assert [r["name"] for r in csvs["classes"]] == ["Server"]

    def test_cpp_qualified_names_are_unqualified(self, setup_repo):
        src = "int Foo::bar(int x) {\n  std::move(x);\n  return 0;\n}\n"
        csvs = _extract(setup_repo, "cpp", {"f.cpp": src})
        assert [r["name"] for r in csvs["functions"]] == ["bar"]
        assert ("bar", "move") in _edges(csvs["callers"])

    def test_php_member_and_static_calls(self, setup_repo):
        src = "<?php\nfunction h($q) {\n  $db->query($q);\n  Util::clean($q);\n}\n"
        csvs = _extract(setup_repo, "php", {"h.php": src})
        assert {("h", "query"), ("h", "clean")} <= _edges(csvs["callers"])

    def test_csharp_constructor_encloses_calls(self, setup_repo):
        src = "class S {\n  public S() { Init(); }\n}\n"
        csvs = _extract(setup_repo, "csharp", {"S.cs": src})
        assert ("S", "Init") in _edges(csvs["callers"])


class TestCalleeFileBinding:
    def test_unique_definition_binds_callee_file(self, setup_repo):
        csvs = _extract(
            setup_repo,
            "c",
            {"a.c": "void sink(void) {}\n", "b.c": "void f(void) { sink(); }\n"},
        )
        row = next(r for r in csvs["callers"] if r["callee_name"] == "sink")
        assert row["callee_file"] == "a.c"

    def test_homonym_leaves_callee_file_unbound(self, setup_repo):
        csvs = _extract(
            setup_repo,
            "c",
            {
                "a.c": "static void init(void) {}\n",
                "b.c": "static void init(void) {}\nvoid f(void) { init(); }\n",
            },
        )
        row = next(r for r in csvs["callers"] if r["callee_name"] == "init")
        assert row["callee_file"] == ""


class TestCSymbols:
    def test_anonymous_and_aliased_typedef_structs(self, setup_repo):
        src = (
            "typedef struct { int len; char *buf; } Msg;\n"
            "typedef struct node { struct node *next; } node_t;\n"
            "struct empty {};\n"
        )
        csvs = _extract(setup_repo, "c", {"t.h": src})
        by_name: dict[str, set[str]] = {}
        for r in csvs["structs"]:
            by_name.setdefault(r["name"], set()).add(r["member_name"])
        assert by_name["Msg"] == {"len", "buf"}
        assert by_name["node"] == {"next"} and by_name["node_t"] == {"next"}
        assert "empty" in by_name

    def test_pointer_array_and_multi_declarator_globals(self, setup_repo):
        src = (
            "char *gbuf = 0, *g2;\n"
            "int arr[10];\n"
            "static const int limit = 4;\n"
            "int proto(int);\n"
            "#ifdef DEBUG\n"
            "int dbg_level;\n"
            "#endif\n"
        )
        csvs = _extract(setup_repo, "c", {"g.c": src})
        globs = {r["name"]: r["type"] for r in csvs["globals"]}
        assert globs["gbuf"] == "char *" and globs["g2"] == "char *"
        assert "arr" in globs and "dbg_level" in globs
        assert globs["limit"] == "static const int"
        # A function prototype is not a global variable.
        assert "proto" not in globs


class TestExtractionRobustness:
    def test_each_file_is_parsed_once(self, setup_repo, monkeypatch):
        repos_dir, output_dir, _, name = setup_repo(
            "c", "once", {"main.c": C_SOURCE, "types.c": C_STRUCT_SOURCE}
        )
        ext = TreeSitterContextExtractor(repos_dir, output_dir)
        calls: list[Path] = []
        original = ext._parse_file

        def counting(parser, path):
            calls.append(path)
            return original(parser, path)

        monkeypatch.setattr(ext, "_parse_file", counting)
        ext.extract_for_repo("c", name)
        assert sorted(p.name for p in calls) == ["main.c", "types.c"]

    def test_deeply_nested_source_does_not_recurse_out(self, setup_repo):
        depth = 5000
        src = "function deep() { return " + "[" * depth + "]" * depth + "; }\n"
        csvs = _extract(setup_repo, "javascript", {"deep.js": src})
        assert [r["name"] for r in csvs["functions"]] == ["deep"]

    def test_node_modules_is_not_indexed(self, setup_repo):
        csvs = _extract(
            setup_repo,
            "javascript",
            {
                "src/app.js": "function mine() {}\n",
                "node_modules/lib/index.js": "function theirs() {}\n",
            },
        )
        assert {r["name"] for r in csvs["functions"]} == {"mine"}
        assert {r["file"] for r in csvs["functions"]} == {"src/app.js"}


class TestTypeScript:
    """.ts/.tsx are parsed with the TypeScript grammars into the javascript index."""

    TS_CONTROLLER = (
        "@Controller('rescue')\n"
        "export class RescueController {\n"
        "  constructor(private readonly svc: RescueService) {}\n"
        "  @Post()\n"
        "  create(@Body() dto: CreateRescueDto): Promise<void> {\n"
        "    return this.svc.merge(dto);\n"
        "  }\n"
        "}\n"
        "export const handler = async (req: Request): Promise<void> => {\n"
        "  exec(req.query.cmd as string);\n"
        "};\n"
        "function ident<T>(x: T): T { return wrap<T>(x); }\n"
    )

    def test_ts_functions_callers_and_classes(self, setup_repo):
        csvs = _extract(setup_repo, "javascript", {"src/rescue.controller.ts": self.TS_CONTROLLER})
        funcs = {r["name"] for r in csvs["functions"]}
        assert {"constructor", "create", "handler", "ident"} <= funcs
        edges = _edges(csvs["callers"])
        assert {("create", "merge"), ("handler", "exec"), ("ident", "wrap")} <= edges
        assert {r["file"] for r in csvs["functions"]} == {"src/rescue.controller.ts"}
        assert "RescueController" in {r["name"] for r in csvs["classes"]}

    def test_ts_dto_classes_and_interfaces_are_indexed(self, setup_repo):
        src = (
            "export class CreateRescueDto {\n"
            "  @IsString() name: string;\n"
            "}\n"
            "export abstract class Base { abstract run(): void; }\n"
            "interface Opts { a: string }\n"
        )
        csvs = _extract(setup_repo, "javascript", {"dto.ts": src})
        assert {"CreateRescueDto", "Base", "Opts"} <= {r["name"] for r in csvs["classes"]}

    def test_tsx_uses_tsx_grammar(self, setup_repo):
        src = (
            "export function View(props: { html: string }) {\n"
            "  track(props.html);\n"
            "  return <div dangerouslySetInnerHTML={{ __html: props.html }} />;\n"
            "}\n"
        )
        csvs = _extract(setup_repo, "javascript", {"view.tsx": src})
        assert ("View", "track") in _edges(csvs["callers"])

    def test_mixed_js_and_ts_repo(self, setup_repo):
        csvs = _extract(
            setup_repo,
            "javascript",
            {"a.js": "function fromJs() { fromTs(); }\n", "b.ts": "export function fromTs(): void {}\n"},
        )
        row = next(r for r in csvs["callers"] if r["callee_name"] == "fromTs")
        assert row["caller_name"] == "fromJs" and row["callee_file"] == "b.ts"
