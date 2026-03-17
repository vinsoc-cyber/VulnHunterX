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
        assert result["Foo"] == [{"name": "x", "type": "uint32_t"}, {"name": "y", "type": "uint32_t"}]
        assert result["Bar"] == [{"name": "z", "type": "uint32_t"}]

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
        assert ctx["struct_defs"]["Config"] == [{"name": "timeout", "type": "uint32_t"}, {"name": "retries", "type": "uint32_t"}]

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


# ── _param_to_consumption ───────────────────────────────────────────────────

class TestParamToConsumption:
    """Cover each type branch in _param_to_consumption(), including new ones."""

    def test_char_pointer_returns_fuzz_str(self):
        assert _param_to_consumption("char *", "buf") == "fuzz_str_buf.c_str()"

    def test_const_char_pointer_returns_fuzz_str(self):
        assert _param_to_consumption("const char *", "name") == "fuzz_str_name.c_str()"

    def test_char_star_const_returns_fuzz_str(self):
        assert _param_to_consumption("char * const", "s") == "fuzz_str_s.c_str()"

    def test_uint8_pointer_returns_buffer_cast(self):
        result = _param_to_consumption("uint8_t *", "data")
        assert "ConsumeRemainingBytes" in result
        assert "reinterpret_cast" in result

    def test_void_pointer_returns_buffer_cast(self):
        result = _param_to_consumption("void *", "ptr")
        assert "ConsumeRemainingBytes" in result

    def test_file_pointer_returns_nullptr(self):
        assert _param_to_consumption("FILE *", "fp") == "nullptr"

    def test_file_pointer_lowercase(self):
        # Lower-cased variant should still match
        assert _param_to_consumption("file *", "fp") == "nullptr"

    def test_size_t_returns_integral(self):
        assert _param_to_consumption("size_t", "sz") == "provider.ConsumeIntegral<size_t>()"

    def test_size_t_pointer_returns_ref(self):
        assert _param_to_consumption("size_t *", "sz") == "&fuzz_size"

    def test_float_returns_floating_point(self):
        assert _param_to_consumption("float", "val") == "provider.ConsumeFloatingPoint<float>()"

    def test_float_pointer_does_not_use_floating_point(self):
        # float* should fall through to nullptr (pointer fallback), not ConsumeFloatingPoint
        result = _param_to_consumption("float *", "fptr")
        assert "ConsumeFloatingPoint" not in result
        assert result == "nullptr"

    def test_double_returns_floating_point(self):
        assert _param_to_consumption("double", "val") == "provider.ConsumeFloatingPoint<double>()"

    def test_double_pointer_does_not_use_floating_point(self):
        # double* should fall through to nullptr (pointer fallback), not ConsumeFloatingPoint
        result = _param_to_consumption("double *", "dptr")
        assert "ConsumeFloatingPoint" not in result
        assert result == "nullptr"

    def test_int_returns_integral(self):
        assert _param_to_consumption("int", "n") == "provider.ConsumeIntegral<int>()"

    def test_int_pointer_returns_nullptr(self):
        assert _param_to_consumption("int *", "ip") == "nullptr"

    def test_long_returns_integral(self):
        assert _param_to_consumption("long", "l") == "provider.ConsumeIntegral<long>()"

    def test_bool_returns_consume_bool(self):
        assert _param_to_consumption("bool", "flag") == "provider.ConsumeBool()"

    def test_generic_pointer_returns_nullptr(self):
        assert _param_to_consumption("struct Foo *", "foo") == "nullptr"

    def test_unknown_type_returns_uint32_integral(self):
        assert _param_to_consumption("MyCustomType", "x") == "provider.ConsumeIntegral<uint32_t>()"

    def test_custom_provider_var(self):
        result = _param_to_consumption("float", "val", provider_var="fdp")
        assert result == "fdp.ConsumeFloatingPoint<float>()"


# ── _generate_struct_init ───────────────────────────────────────────────────

class TestGenerateStructInit:
    def test_generates_memset_and_member_assignments(self):
        members = [{"name": "timeout", "type": "uint32_t"}, {"name": "retries", "type": "int"}]
        lines = _generate_struct_init("Config", members, "fuzz_struct_Config")
        code = "\n".join(lines)
        assert "Config fuzz_struct_Config;" in code
        assert "memset(&fuzz_struct_Config, 0, sizeof(fuzz_struct_Config));" in code
        assert "fuzz_struct_Config.timeout" in code
        assert "fuzz_struct_Config.retries" in code

    def test_legacy_string_members(self):
        """Backward compatibility: plain string member names default to uint32_t."""
        lines = _generate_struct_init("Config", ["timeout", "retries"], "fuzz_struct_Config")
        code = "\n".join(lines)
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
            "struct_defs": {"Cfg": [{"name": "size", "type": "size_t"}, {"name": "flags", "type": "uint32_t"}]},
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


# ── _param_to_consumption ───────────────────────────────────────────────────

class TestParamToConsumption:
    """Unit tests for _param_to_consumption() type-dispatch logic."""

    # --- char pointer variants ---
    def test_char_pointer(self):
        result = _param_to_consumption("char *", "buf")
        assert result == "fuzz_str_buf.c_str()"

    def test_char_pointer_no_space(self):
        result = _param_to_consumption("char*", "buf")
        assert result == "fuzz_str_buf.c_str()"

    def test_const_char_pointer(self):
        result = _param_to_consumption("const char *", "name")
        assert result == "fuzz_str_name.c_str()"

    # --- FILE* ---
    def test_file_pointer_with_space(self):
        result = _param_to_consumption("FILE *", "fp")
        assert result == "nullptr"

    def test_file_pointer_no_space(self):
        result = _param_to_consumption("FILE*", "fp")
        assert result == "nullptr"

    # --- float (non-pointer) ---
    def test_float_scalar(self):
        result = _param_to_consumption("float", "val")
        assert result == "provider.ConsumeFloatingPoint<float>()"

    def test_float_with_custom_provider_var(self):
        result = _param_to_consumption("float", "val", provider_var="fdp")
        assert result == "fdp.ConsumeFloatingPoint<float>()"

    def test_float_pointer_does_not_match_float_branch(self):
        # float* should fall through to the nullptr default (pointer, not scalar)
        result = _param_to_consumption("float *", "fptr")
        assert result == "nullptr"

    # --- double (non-pointer) ---
    def test_double_scalar(self):
        result = _param_to_consumption("double", "val")
        assert result == "provider.ConsumeFloatingPoint<double>()"

    def test_double_with_custom_provider_var(self):
        result = _param_to_consumption("double", "val", provider_var="fdp")
        assert result == "fdp.ConsumeFloatingPoint<double>()"

    def test_double_pointer_does_not_match_double_branch(self):
        # double* should fall through to the nullptr default (pointer, not scalar)
        result = _param_to_consumption("double *", "dptr")
        assert result == "nullptr"

    # --- size_t ---
    def test_size_t_scalar(self):
        result = _param_to_consumption("size_t", "sz")
        assert result == "provider.ConsumeIntegral<size_t>()"

    def test_size_t_pointer(self):
        result = _param_to_consumption("size_t *", "sz_ptr")
        assert result == "&fuzz_size"

    # --- int / long / bool ---
    def test_int_scalar(self):
        result = _param_to_consumption("int", "n")
        assert result == "provider.ConsumeIntegral<int>()"

    def test_long_scalar(self):
        result = _param_to_consumption("long", "l")
        assert result == "provider.ConsumeIntegral<long>()"

    def test_bool_scalar(self):
        result = _param_to_consumption("bool", "flag")
        assert result == "provider.ConsumeBool()"

    # --- generic pointer fallback ---
    def test_generic_pointer_returns_nullptr(self):
        # void* should generate a reinterpret_cast buffer expression
        result = _param_to_consumption("void *", "ptr")
        assert "reinterpret_cast" in result

    def test_unknown_pointer_type_returns_nullptr(self):
        result = _param_to_consumption("struct Foo *", "foo")
        assert result == "nullptr"

    # --- default integral fallback ---
    def test_unknown_scalar_returns_uint32_integral(self):
        # A type that matches none of the named branches falls back to ConsumeIntegral<uint32_t>
        result = _param_to_consumption("custom_type", "x")
        assert result == "provider.ConsumeIntegral<uint32_t>()"


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
        score = score_target(info, struct_defs={"Config": [{"name": "x", "type": "int"}, {"name": "y", "type": "int"}]})
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
