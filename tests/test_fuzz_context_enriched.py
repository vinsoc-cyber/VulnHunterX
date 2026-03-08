"""Tests for enriched fuzz context: loaders, harness generation, scoring."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from vuln_hunter_x.fuzz.fuzz_context import (
    build_type_context_string,
    get_target_context,
    load_callers,
    load_globals,
    load_macros,
    load_structs,
)
from vuln_hunter_x.fuzz.driver_generator import (
    _generate_struct_init,
    _param_to_consumption,
    generate_harness,
)
from vuln_hunter_x.fuzz.target_selection import score_target


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str] | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    fieldnames = fieldnames or list(rows[0].keys())
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


@pytest.fixture()
def ctx_dir(tmp_path):
    d = tmp_path / "context"
    d.mkdir()
    return d


# ── load_structs ────────────────────────────────────────────────────────────

class TestLoadStructs:
    def test_groups_members(self, ctx_dir):
        _write_csv(
            ctx_dir / "structs.csv",
            [
                {"name": "Foo", "file": "a.c", "start_line": "1", "end_line": "5", "member_name": "x"},
                {"name": "Foo", "file": "a.c", "start_line": "1", "end_line": "5", "member_name": "y"},
                {"name": "Bar", "file": "a.c", "start_line": "7", "end_line": "10", "member_name": "z"},
            ],
        )
        result = load_structs(ctx_dir)
        assert result["Foo"] == ["x", "y"]
        assert result["Bar"] == ["z"]

    def test_missing_csv_returns_empty(self, ctx_dir):
        assert load_structs(ctx_dir) == {}

    def test_empty_csv_returns_empty(self, ctx_dir):
        _write_csv(ctx_dir / "structs.csv", [])
        assert load_structs(ctx_dir) == {}


# ── load_globals ────────────────────────────────────────────────────────────

class TestLoadGlobals:
    def test_returns_list(self, ctx_dir):
        _write_csv(
            ctx_dir / "globals.csv",
            [{"name": "g_count", "file": "main.c", "start_line": "3", "end_line": "3", "type": "int"}],
        )
        result = load_globals(ctx_dir)
        assert len(result) == 1
        assert result[0]["name"] == "g_count"
        assert result[0]["type"] == "int"

    def test_missing_csv_returns_empty(self, ctx_dir):
        assert load_globals(ctx_dir) == []


# ── load_macros ────────────────────────────────────────────────────────────

class TestLoadMacros:
    def test_returns_name_to_body(self, ctx_dir):
        _write_csv(
            ctx_dir / "macros.csv",
            [{"name": "BUF_SIZE", "file": "cfg.h", "line": "5", "body": "1024"}],
        )
        result = load_macros(ctx_dir)
        assert result["BUF_SIZE"] == "1024"

    def test_missing_csv_returns_empty(self, ctx_dir):
        assert load_macros(ctx_dir) == {}


# ── load_callers ────────────────────────────────────────────────────────────

class TestLoadCallers:
    def test_groups_callers_by_callee(self, ctx_dir):
        _write_csv(
            ctx_dir / "callers.csv",
            [
                {"callee_name": "fn", "callee_file": "", "caller_name": "alpha", "caller_file": "a.c", "caller_start_line": "1", "caller_end_line": "5"},
                {"callee_name": "fn", "callee_file": "", "caller_name": "beta", "caller_file": "a.c", "caller_start_line": "6", "caller_end_line": "10"},
            ],
        )
        result = load_callers(ctx_dir)
        assert set(result["fn"]) == {"alpha", "beta"}

    def test_deduplicates_callers(self, ctx_dir):
        _write_csv(
            ctx_dir / "callers.csv",
            [
                {"callee_name": "fn", "callee_file": "", "caller_name": "alpha", "caller_file": "a.c", "caller_start_line": "1", "caller_end_line": "5"},
                {"callee_name": "fn", "callee_file": "", "caller_name": "alpha", "caller_file": "a.c", "caller_start_line": "1", "caller_end_line": "5"},
            ],
        )
        result = load_callers(ctx_dir)
        assert result["fn"] == ["alpha"]

    def test_missing_csv_returns_empty(self, ctx_dir):
        assert load_callers(ctx_dir) == {}


# ── build_type_context_string ───────────────────────────────────────────────

class TestBuildTypeContextString:
    def test_includes_struct_and_macro(self, ctx_dir):
        _write_csv(
            ctx_dir / "structs.csv",
            [{"name": "Cfg", "file": "a.c", "start_line": "1", "end_line": "3", "member_name": "size"}],
        )
        _write_csv(
            ctx_dir / "macros.csv",
            [{"name": "MAX", "file": "a.h", "line": "1", "body": "100"}],
        )
        text = build_type_context_string(ctx_dir)
        assert "struct Cfg" in text
        assert "size" in text
        assert "#define MAX 100" in text

    def test_truncated_when_exceeds_max_chars(self, ctx_dir):
        rows = [
            {"name": f"Struct{i}", "file": "a.c", "start_line": str(i), "end_line": str(i + 1), "member_name": "x"}
            for i in range(100)
        ]
        _write_csv(ctx_dir / "structs.csv", rows)
        text = build_type_context_string(ctx_dir, max_chars=50)
        assert len(text) <= 50 + len("\n/* ... (truncated) */")
        assert "truncated" in text

    def test_empty_returns_empty_string(self, ctx_dir):
        assert build_type_context_string(ctx_dir) == ""


# ── get_target_context with struct enrichment ───────────────────────────────

class TestGetTargetContextWithStructs:
    def test_struct_defs_populated_for_matching_param_type(self, ctx_dir):
        # Write function_signatures.csv
        _write_csv(
            ctx_dir / "function_signatures.csv",
            [
                {"name": "do_work", "file": "a.c", "start_line": "1", "end_line": "10",
                 "param_index": "0", "param_type": "struct Config *", "param_name": "cfg"},
            ],
        )
        _write_csv(
            ctx_dir / "structs.csv",
            [
                {"name": "Config", "file": "a.c", "start_line": "1", "end_line": "5", "member_name": "timeout"},
                {"name": "Config", "file": "a.c", "start_line": "1", "end_line": "5", "member_name": "retries"},
            ],
        )
        ctx = get_target_context(
            {"name": "do_work", "file": "a.c", "start_line": 1, "end_line": 10},
            ctx_dir,
        )
        assert "Config" in ctx["struct_defs"]
        assert ctx["struct_defs"]["Config"] == ["timeout", "retries"]

    def test_struct_defs_empty_when_no_match(self, ctx_dir):
        _write_csv(
            ctx_dir / "function_signatures.csv",
            [{"name": "fn", "file": "a.c", "start_line": "1", "end_line": "5",
              "param_index": "0", "param_type": "int", "param_name": "n"}],
        )
        ctx = get_target_context(
            {"name": "fn", "file": "a.c", "start_line": 1, "end_line": 5},
            ctx_dir,
        )
        assert ctx["struct_defs"] == {}


# ── _generate_struct_init ───────────────────────────────────────────────────

class TestGenerateStructInit:
    def test_generates_memset_and_member_assignments(self):
        lines = _generate_struct_init("Config", ["timeout", "retries"], "fuzz_struct_Config")
        code = "\n".join(lines)
        assert "Config fuzz_struct_Config;" in code
        assert "memset(&fuzz_struct_Config, 0, sizeof(fuzz_struct_Config));" in code
        assert "fuzz_struct_Config.timeout = provider.ConsumeIntegral<uint32_t>();" in code
        assert "fuzz_struct_Config.retries = provider.ConsumeIntegral<uint32_t>();" in code

    def test_empty_members(self):
        lines = _generate_struct_init("Foo", [], "fuzz_struct_Foo")
        # Only declaration and memset
        assert len(lines) == 2


# ── generate_harness with struct_defs ───────────────────────────────────────

class TestGenerateHarnessWithStructs:
    def test_harness_with_struct_param(self, tmp_path):
        ctx = {
            "name": "process",
            "file": "a.c",
            "start_line": 1,
            "end_line": 10,
            "params": [{"type": "struct Cfg *", "name": "cfg"}],
            "includes": [],
            "struct_defs": {"Cfg": ["size", "flags"]},
        }
        out = generate_harness("rule/test", "a.c", 5, ctx, tmp_path / "harness.cc", "repo")
        code = out.read_text()
        assert "Cfg fuzz_struct_Cfg;" in code
        assert "memset(&fuzz_struct_Cfg" in code
        assert "&fuzz_struct_Cfg" in code
        assert "#include <cstring>" in code

    def test_harness_without_struct_defs_backward_compat(self, tmp_path):
        ctx = {
            "name": "simple",
            "file": "b.c",
            "start_line": 1,
            "end_line": 5,
            "params": [{"type": "int", "name": "n"}],
            "includes": [],
        }
        out = generate_harness("rule/simple", "b.c", 3, ctx, tmp_path / "simple.cc", "repo")
        code = out.read_text()
        assert "simple(" in code
        assert "LLVMFuzzerTestOneInput" in code


# ── score_target ────────────────────────────────────────────────────────────

class TestScoreTarget:
    def test_all_primitives_scores_high(self):
        info = {"name": "fn", "params": [
            {"type": "int", "name": "n"},
            {"type": "size_t", "name": "sz"},
        ]}
        score = score_target(info)
        assert score >= 20  # 10 per primitive

    def test_struct_param_with_known_def(self):
        info = {"name": "fn", "params": [{"type": "Config *", "name": "cfg"}]}
        score = score_target(info, struct_defs={"Config": ["x", "y"]})
        assert score >= 2

    def test_struct_param_without_known_def_scores_zero(self):
        info = {"name": "fn", "params": [{"type": "Config *", "name": "cfg"}]}
        score = score_target(info, struct_defs={})
        assert score == 0

    def test_penalty_for_many_params(self):
        # 8 int params: 8 * 10 - 3 penalty = 77
        info = {"name": "fn", "params": [{"type": "int", "name": f"a{i}"} for i in range(8)]}
        score_many = score_target(info)
        # 6 int params: 6 * 10, no penalty = 60 (> 6 triggers penalty, so exactly 6 is fine)
        info_six = {"name": "fn", "params": [{"type": "int", "name": f"a{i}"} for i in range(6)]}
        score_six = score_target(info_six)
        # 8 params without penalty would be 80; with penalty it's 77 < 80
        assert score_many < 8 * 10  # penalty applied
        assert score_six == 6 * 10  # no penalty at exactly 6 params

    def test_callers_bonus(self):
        info = {"name": "fn", "params": []}
        score_with = score_target(info, callers_map={"fn": ["a", "b", "c"]})
        score_without = score_target(info)
        assert score_with > score_without
