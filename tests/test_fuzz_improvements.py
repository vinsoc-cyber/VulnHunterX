"""Tests for Stage 7 improvements: enum support, typedef resolution,
buffer+size correlation, FILE* fmemopen, char array init, and bug fixes."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from vuln_hunter_x.fuzz.driver_generator import (
    _build_extern_declaration,
    _detect_buffer_size_pairs,
    _enum_consumption,
    _generate_struct_init,
    _member_consumption,
    _param_to_consumption,
    _parse_char_array,
    _resolve_type,
    generate_harness,
)
from vuln_hunter_x.fuzz.fuzz_context import get_target_context, load_enums, load_typedefs
from vuln_hunter_x.fuzz.target_selection import score_target
from vuln_hunter_x.fuzz.driver_fix_loop import classify_errors


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


# ── Bug Fix Tests ──────────────────────────────────────────────────────────


class TestBugFixes:
    """Regression tests for P0 bugs."""

    def test_score_target_buffer_bonus_applied_once(self):
        """Bug 1: duplicate buffer detection gave +16 instead of +8."""
        info = {
            "name": "fn",
            "params": [
                {"type": "const uint8_t *", "name": "data"},
                {"type": "size_t", "name": "len"},
            ],
        }
        score = score_target(info)
        # 2 primitives (10 each) + buffer+size bonus (8) = 28
        assert score == 28

    def test_classify_errors_callable(self):
        """Bug 3: _classify_errors NameError — ensure classify_errors works."""
        result = classify_errors("error: undefined reference to `foo'")
        assert result == "linker"

    def test_classify_errors_multiple_main(self):
        result = classify_errors("error: multiple definition of `main'")
        assert result == "multiple_main"

    def test_classify_errors_missing_include(self):
        result = classify_errors("fatal error: 'foo.h' no such file or directory\n#include <foo.h>")
        assert result == "missing_include"


# ── Typedef Resolution Tests ──────────────────────────────────────────────


class TestTypedefResolution:
    def test_simple_typedef(self):
        assert _resolve_type("ucl_type_t", {"ucl_type_t": "enum ucl_type"}) == "ucl_type"

    def test_chain(self):
        tdmap = {"counter_t": "myint", "myint": "int32_t"}
        assert _resolve_type("counter_t", tdmap) == "int32_t"

    def test_cycle_protection(self):
        tdmap = {"a": "b", "b": "a"}
        result = _resolve_type("a", tdmap)
        assert result in ("a", "b")  # doesn't infinite loop

    def test_no_match_returns_original(self):
        assert _resolve_type("unknown_type", {}) == "unknown_type"

    def test_strips_enum_prefix(self):
        assert _resolve_type("my_enum_t", {"my_enum_t": "enum MyEnum"}) == "MyEnum"


# ── Enum Support Tests ─────────────────────────────────────────────────────


class TestEnumSupport:
    def test_enum_consumption_generates_pick_value(self):
        values = [{"member": "UCL_INT", "value": "0"}, {"member": "UCL_FLOAT", "value": "1"}]
        result = _enum_consumption("ucl_type", values)
        assert "PickValueInArray" in result
        assert "UCL_INT" in result
        assert "UCL_FLOAT" in result

    def test_enum_consumption_single_value(self):
        values = [{"member": "ONLY_ONE", "value": "0"}]
        result = _enum_consumption("my_enum", values)
        assert "ONLY_ONE" in result

    def test_enum_consumption_empty_values_falls_back(self):
        result = _enum_consumption("empty_enum", [])
        assert "ConsumeIntegral<uint32_t>" in result

    def test_param_to_consumption_enum_type(self):
        enum_defs = {"ucl_type": [{"member": "UCL_INT", "value": "0"}, {"member": "UCL_FLOAT", "value": "1"}]}
        result = _param_to_consumption("ucl_type", "type", enum_defs=enum_defs)
        assert "PickValueInArray" in result

    def test_param_to_consumption_enum_via_typedef(self):
        enum_defs = {"ucl_type": [{"member": "UCL_INT", "value": "0"}]}
        typedef_map = {"ucl_type_t": "enum ucl_type"}
        result = _param_to_consumption("ucl_type_t", "type", enum_defs=enum_defs, typedef_map=typedef_map)
        assert "PickValueInArray" in result or "UCL_INT" in result

    def test_param_to_consumption_unknown_enum_falls_back(self):
        result = _param_to_consumption("UnknownType", "x", enum_defs={})
        assert "ConsumeIntegral<uint32_t>" in result

    def test_member_consumption_enum_type(self):
        enum_defs = {"Color": [{"member": "RED", "value": "0"}, {"member": "GREEN", "value": "1"}]}
        result = _member_consumption("Color", enum_defs=enum_defs)
        assert "PickValueInArray" in result or "RED" in result

    def test_generate_harness_enum_param(self, tmp_path):
        ctx = {
            "name": "set_mode",
            "file": "a.c",
            "start_line": 1,
            "end_line": 10,
            "params": [{"type": "enum Mode", "name": "mode"}],
            "includes": [],
            "struct_defs": {},
            "enum_defs": {"Mode": [{"member": "MODE_A", "value": "0"}, {"member": "MODE_B", "value": "1"}]},
            "typedef_map": {},
        }
        out = generate_harness("rule/test", "a.c", 5, ctx, tmp_path / "harness.cc", "repo")
        code = out.read_text()
        assert "PickValueInArray" in code or "MODE_A" in code

    def test_load_enums_from_csv(self, ctx_dir):
        _write_csv(ctx_dir / "enums.csv", [
            {"name": "Color", "member": "RED", "value": "0"},
            {"name": "Color", "member": "GREEN", "value": "1"},
        ])
        result = load_enums(ctx_dir)
        assert "Color" in result
        assert len(result["Color"]) == 2

    def test_load_typedefs_from_csv(self, ctx_dir):
        _write_csv(ctx_dir / "typedefs.csv", [
            {"name": "my_int_t", "underlying_type": "int"},
        ])
        result = load_typedefs(ctx_dir)
        assert result["my_int_t"] == "int"


# ── Buffer + Size Correlation Tests ────────────────────────────────────────


class TestBufferSizeCorrelation:
    def test_detect_adjacent_pair(self):
        params = [
            {"type": "const uint8_t *", "name": "data"},
            {"type": "size_t", "name": "len"},
        ]
        pairs = _detect_buffer_size_pairs(params)
        assert pairs == {0: 1}

    def test_detect_pair_by_name(self):
        params = [
            {"type": "const char *", "name": "buf"},
            {"type": "int", "name": "flags"},
            {"type": "size_t", "name": "buflen"},
        ]
        pairs = _detect_buffer_size_pairs(params)
        assert pairs == {0: 2}

    def test_no_false_positive_without_buffer(self):
        params = [
            {"type": "size_t", "name": "offset"},
            {"type": "int", "name": "flags"},
        ]
        pairs = _detect_buffer_size_pairs(params)
        assert pairs == {}

    def test_multiple_buffer_pairs(self):
        params = [
            {"type": "const uint8_t *", "name": "src"},
            {"type": "size_t", "name": "srclen"},
            {"type": "uint8_t *", "name": "dst"},
            {"type": "size_t", "name": "dstlen"},
        ]
        pairs = _detect_buffer_size_pairs(params)
        assert pairs == {0: 1, 2: 3}

    def test_generate_harness_correlated_buffer(self, tmp_path):
        ctx = {
            "name": "parse",
            "file": "a.c",
            "start_line": 1,
            "end_line": 10,
            "params": [
                {"type": "const uint8_t *", "name": "data"},
                {"type": "size_t", "name": "len"},
            ],
            "includes": [],
            "struct_defs": {},
            "enum_defs": {},
            "typedef_map": {},
        }
        out = generate_harness("rule/test", "a.c", 5, ctx, tmp_path / "harness.cc", "repo")
        code = out.read_text()
        assert "fuzz_buf_data" in code
        assert ".size()" in code
        assert "ConsumeRemainingBytes" not in code


# ── FILE* fmemopen Tests ──────────────────────────────────────────────────


class TestFileParam:
    def test_generate_harness_file_param_uses_fmemopen(self, tmp_path):
        ctx = {
            "name": "read_config",
            "file": "a.c",
            "start_line": 1,
            "end_line": 10,
            "params": [{"type": "FILE *", "name": "fp"}],
            "includes": [],
            "struct_defs": {},
            "enum_defs": {},
            "typedef_map": {},
        }
        out = generate_harness("rule/test", "a.c", 5, ctx, tmp_path / "harness.cc", "repo")
        code = out.read_text()
        assert "fmemopen" in code
        assert "fclose" in code
        assert "nullptr" not in code or "fuzz_fp_fp" in code


# ── Char Array Member Init Tests ──────────────────────────────────────────


class TestCharArrayInit:
    def test_parse_char_array(self):
        assert _parse_char_array("char [64]") == 64
        assert _parse_char_array("char[32]") == 32
        assert _parse_char_array("const char [16]") == 16
        assert _parse_char_array("int [10]") is None
        assert _parse_char_array("char *") is None

    def test_struct_init_char_array_gets_fuzzed(self):
        members = [{"name": "hostname", "type": "char [64]"}]
        lines = _generate_struct_init("Config", members, "fuzz_struct_Config")
        code = "\n".join(lines)
        assert "ConsumeBytesAsString" in code
        assert "memcpy" in code
        assert "hostname" in code

    def test_struct_init_int_array_stays_zero(self):
        members = [{"name": "table", "type": "int [16]"}]
        lines = _generate_struct_init("Config", members, "fuzz_struct_Config")
        code = "\n".join(lines)
        # int array is complex type — stays zero-initialized
        assert "table" not in code or "memset" in code

    def test_struct_init_with_enum_member(self):
        members = [{"name": "mode", "type": "Color"}]
        enum_defs = {"Color": [{"member": "RED", "value": "0"}, {"member": "GREEN", "value": "1"}]}
        lines = _generate_struct_init("Config", members, "cfg", enum_defs=enum_defs)
        code = "\n".join(lines)
        assert "cfg.mode" in code
        assert "PickValueInArray" in code or "RED" in code


# ── Consumption Ordering Tests ────────────────────────────────────────────


class TestConsumptionOrdering:
    def test_string_size_bounded(self, tmp_path):
        """String consumption should be bounded, not use full input size."""
        ctx = {
            "name": "process",
            "file": "a.c",
            "start_line": 1,
            "end_line": 10,
            "params": [
                {"type": "const char *", "name": "name"},
                {"type": "int", "name": "flags"},
            ],
            "includes": [],
            "struct_defs": {},
            "enum_defs": {},
            "typedef_map": {},
        }
        out = generate_harness("rule/test", "a.c", 5, ctx, tmp_path / "harness.cc", "repo")
        code = out.read_text()
        # String should use bounded consumption (256), not full size
        assert "ConsumeRandomLengthString(256)" in code
        # Should NOT contain "ConsumeIntegralInRange<size_t>(0, size)"
        assert "ConsumeIntegralInRange<size_t>(0, size)" not in code


# ── get_target_context Integration Tests ──────────────────────────────────


class TestGetTargetContextEnriched:
    def test_populates_enum_defs(self, ctx_dir):
        _write_csv(ctx_dir / "function_signatures.csv", [
            {"name": "set_mode", "file": "a.c", "start_line": "1", "end_line": "10",
             "param_index": "0", "param_type": "enum Mode", "param_name": "mode"},
        ])
        _write_csv(ctx_dir / "enums.csv", [
            {"name": "Mode", "member": "MODE_A", "value": "0"},
            {"name": "Mode", "member": "MODE_B", "value": "1"},
        ])
        ctx = get_target_context(
            {"name": "set_mode", "file": "a.c", "start_line": 1, "end_line": 10},
            ctx_dir,
        )
        assert "Mode" in ctx["enum_defs"]
        assert len(ctx["enum_defs"]["Mode"]) == 2

    def test_populates_typedef_map(self, ctx_dir):
        _write_csv(ctx_dir / "function_signatures.csv", [
            {"name": "fn", "file": "a.c", "start_line": "1", "end_line": "5",
             "param_index": "0", "param_type": "my_int_t", "param_name": "x"},
        ])
        _write_csv(ctx_dir / "typedefs.csv", [
            {"name": "my_int_t", "underlying_type": "int"},
        ])
        ctx = get_target_context(
            {"name": "fn", "file": "a.c", "start_line": 1, "end_line": 5},
            ctx_dir,
        )
        assert ctx["typedef_map"]["my_int_t"] == "int"

    def test_typedef_resolves_to_struct(self, ctx_dir):
        _write_csv(ctx_dir / "function_signatures.csv", [
            {"name": "fn", "file": "a.c", "start_line": "1", "end_line": "5",
             "param_index": "0", "param_type": "config_t *", "param_name": "cfg"},
        ])
        _write_csv(ctx_dir / "typedefs.csv", [
            {"name": "config_t", "underlying_type": "struct Config"},
        ])
        _write_csv(ctx_dir / "structs.csv", [
            {"name": "Config", "file": "a.c", "start_line": "1", "end_line": "5",
             "member_name": "timeout", "member_type": "int"},
        ])
        ctx = get_target_context(
            {"name": "fn", "file": "a.c", "start_line": 1, "end_line": 5},
            ctx_dir,
        )
        assert "Config" in ctx["struct_defs"]
