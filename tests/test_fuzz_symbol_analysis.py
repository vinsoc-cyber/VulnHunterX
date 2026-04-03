"""Tests for symbol analysis, linkability classification, and selective linking."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from vuln_hunter_x.fuzz.build_sanitized import (
    _build_library_exports,
    _build_symbol_map,
    _load_compile_commands,
)
from vuln_hunter_x.fuzz.driver_builder import (
    _extract_compile_flags,
    _resolve_link_deps,
)
from vuln_hunter_x.fuzz.target_selection import (
    LINKABILITY_EXECUTABLE_SOURCE,
    LINKABILITY_LIBRARY_EXPORTED,
    LINKABILITY_OBJECT_GLOBAL,
    LINKABILITY_STATIC,
    LINKABILITY_UNKNOWN,
    _file_has_main,
    classify_target_linkability,
    score_target,
)


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


# ── _build_symbol_map ──────────────────────────────────────────────────────


class TestBuildSymbolMap:
    def test_classifies_global_and_static(self, tmp_path):
        """nm output with T (global) and t (static) symbols."""
        obj = tmp_path / "test.o"
        obj.write_bytes(b"")  # dummy

        nm_output = (
            "0000000000000000 T jpeg_read_header\n"
            "0000000000000010 t alloc_funny_pointers\n"
            "0000000000000020 T jpeg_start_decompress\n"
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=nm_output)
            sym_map, static_syms = _build_symbol_map(tmp_path)

        assert "jpeg_read_header" in sym_map
        assert "jpeg_start_decompress" in sym_map
        assert "alloc_funny_pointers" not in sym_map
        assert "alloc_funny_pointers" in static_syms
        assert "jpeg_read_header" not in static_syms

    def test_symbol_global_in_one_obj_static_in_another(self, tmp_path):
        """A symbol that's global in one .o and static in another should be global."""
        obj1 = tmp_path / "a.o"
        obj1.write_bytes(b"")
        obj2 = tmp_path / "b.o"
        obj2.write_bytes(b"")

        outputs = [
            "0000000000000000 T shared_func\n",
            "0000000000000000 t shared_func\n",
        ]

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=outputs[0]),
                MagicMock(returncode=0, stdout=outputs[1]),
            ]
            sym_map, static_syms = _build_symbol_map(tmp_path)

        assert "shared_func" in sym_map
        assert "shared_func" not in static_syms

    def test_empty_dir(self, tmp_path):
        sym_map, static_syms = _build_symbol_map(tmp_path)
        assert sym_map == {}
        assert static_syms == set()


# ── _build_library_exports ─────────────────────────────────────────────────


class TestBuildLibraryExports:
    def test_extracts_exports(self, tmp_path):
        lib = tmp_path / "libjpeg.a"
        lib.write_bytes(b"")

        nm_output = (
            "0000000000000000 T jpeg_read_header\n0000000000000010 T jpeg_start_decompress\n"
        )

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=nm_output)
            exports = _build_library_exports(tmp_path, ["libjpeg.a"])

        assert "jpeg_read_header" in exports
        assert exports["jpeg_read_header"] == ["libjpeg.a"]

    def test_missing_lib(self, tmp_path):
        exports = _build_library_exports(tmp_path, ["nonexistent.a"])
        assert exports == {}


# ── _load_compile_commands ─────────────────────────────────────────────────


class TestLoadCompileCommands:
    def test_parses_json(self, tmp_path):
        cc = [
            {
                "directory": str(tmp_path / "build"),
                "command": "clang -DFOO=1 -Iinclude -c src/foo.c -o foo.o",
                "file": str(tmp_path / "src" / "foo.c"),
            }
        ]
        cc_path = tmp_path / "build" / "compile_commands.json"
        cc_path.parent.mkdir(parents=True, exist_ok=True)
        cc_path.write_text(json.dumps(cc))

        result = _load_compile_commands(tmp_path)
        assert len(result) == 1
        key = list(result.keys())[0]
        assert "foo.c" in key

    def test_no_file(self, tmp_path):
        result = _load_compile_commands(tmp_path)
        assert result == {}


# ── classify_target_linkability ────────────────────────────────────────────


class TestClassifyTargetLinkability:
    def test_library_exported(self):
        manifest = {
            "lib_exports": {"jpeg_read_header": ["libjpeg.a"]},
            "static_symbols": [],
            "symbol_to_objects": {},
        }
        result = classify_target_linkability("jpeg_read_header", "src/jdapimin.c", manifest)
        assert result == LINKABILITY_LIBRARY_EXPORTED

    def test_static_from_nm(self):
        manifest = {
            "lib_exports": {},
            "static_symbols": ["decomp"],
            "symbol_to_objects": {},
        }
        result = classify_target_linkability("decomp", "src/tjbench.c", manifest)
        assert result == LINKABILITY_STATIC

    def test_static_from_codeql(self):
        manifest = {
            "lib_exports": {},
            "static_symbols": [],
            "symbol_to_objects": {},
        }
        result = classify_target_linkability(
            "decomp", "src/tjbench.c", manifest, is_static_from_codeql=True
        )
        assert result == LINKABILITY_STATIC

    def test_object_global(self, tmp_path):
        ctx_dir = tmp_path / "context"
        _write_csv(
            ctx_dir / "functions.csv",
            [
                {
                    "name": "helper",
                    "file": "src/util.c",
                    "start_line": "1",
                    "end_line": "10",
                    "param_count": "0",
                }
            ],
        )
        manifest = {
            "lib_exports": {},
            "static_symbols": [],
            "symbol_to_objects": {"helper": ["build/util.c.o"]},
        }
        result = classify_target_linkability(
            "helper", "src/util.c", manifest, repo_context_dir=ctx_dir
        )
        assert result == LINKABILITY_OBJECT_GLOBAL

    def test_executable_source(self, tmp_path):
        ctx_dir = tmp_path / "context"
        _write_csv(
            ctx_dir / "functions.csv",
            [
                {
                    "name": "main",
                    "file": "src/djpeg.c",
                    "start_line": "100",
                    "end_line": "200",
                    "param_count": "2",
                },
                {
                    "name": "parse_switches",
                    "file": "src/djpeg.c",
                    "start_line": "50",
                    "end_line": "90",
                    "param_count": "3",
                },
            ],
        )
        manifest = {
            "lib_exports": {},
            "static_symbols": [],
            "symbol_to_objects": {"parse_switches": ["build/djpeg.c.o"]},
        }
        result = classify_target_linkability(
            "parse_switches", "src/djpeg.c", manifest, repo_context_dir=ctx_dir
        )
        assert result == LINKABILITY_EXECUTABLE_SOURCE

    def test_unknown(self):
        manifest = {
            "lib_exports": {},
            "static_symbols": [],
            "symbol_to_objects": {},
        }
        result = classify_target_linkability("mystery", "src/x.c", manifest)
        assert result == LINKABILITY_UNKNOWN


# ── _file_has_main ─────────────────────────────────────────────────────────


class TestFileHasMain:
    def test_found(self, tmp_path):
        ctx_dir = tmp_path / "context"
        _write_csv(
            ctx_dir / "functions.csv",
            [
                {
                    "name": "main",
                    "file": "src/djpeg.c",
                    "start_line": "100",
                    "end_line": "200",
                    "param_count": "2",
                }
            ],
        )
        assert _file_has_main("src/djpeg.c", ctx_dir) is True

    def test_not_found(self, tmp_path):
        ctx_dir = tmp_path / "context"
        _write_csv(
            ctx_dir / "functions.csv",
            [
                {
                    "name": "helper",
                    "file": "src/util.c",
                    "start_line": "1",
                    "end_line": "10",
                    "param_count": "0",
                }
            ],
        )
        assert _file_has_main("src/util.c", ctx_dir) is False

    def test_no_csv(self, tmp_path):
        assert _file_has_main("src/x.c", tmp_path / "context") is False


# ── score_target with linkability ──────────────────────────────────────────


class TestScoreTargetLinkability:
    def test_library_exported_bonus(self):
        info = {"name": "foo", "params": [{"type": "int", "name": "x"}]}
        base = score_target(info, linkability=LINKABILITY_UNKNOWN)
        boosted = score_target(info, linkability=LINKABILITY_LIBRARY_EXPORTED)
        assert boosted == base + 20

    def test_static_penalty(self):
        info = {"name": "foo", "params": [{"type": "int", "name": "x"}]}
        base = score_target(info, linkability=LINKABILITY_UNKNOWN)
        penalized = score_target(info, linkability=LINKABILITY_STATIC)
        assert penalized == base - 15

    def test_executable_source_penalty(self):
        info = {"name": "foo", "params": [{"type": "int", "name": "x"}]}
        base = score_target(info, linkability=LINKABILITY_UNKNOWN)
        penalized = score_target(info, linkability=LINKABILITY_EXECUTABLE_SOURCE)
        assert penalized == base - 25


# ── _extract_compile_flags ─────────────────────────────────────────────────


class TestExtractCompileFlags:
    def test_extracts_d_and_i(self):
        cc = {"src/foo.c": {"command": "clang -DFOO=1 -Iinclude -DBAR -I/usr/include -c src/foo.c"}}
        flags = _extract_compile_flags(cc, "src/foo.c")
        assert "-DFOO=1" in flags
        assert "-Iinclude" in flags
        assert "-DBAR" in flags

    def test_no_match(self):
        cc = {"src/foo.c": {"command": "clang -c src/foo.c"}}
        flags = _extract_compile_flags(cc, "src/bar.c")
        assert flags == []


# ── _resolve_link_deps ─────────────────────────────────────────────────────


class TestResolveLinkDeps:
    def test_library_exported(self, tmp_path):
        manifest = {
            "lib_exports": {"jpeg_read_header": ["build_sanitized/libjpeg.a"]},
            "static_symbols": [],
            "symbol_to_objects": {},
            "libs": ["build_sanitized/libjpeg.a"],
        }
        objs, libs, srcs = _resolve_link_deps("jpeg_read_header", manifest, tmp_path)
        assert objs == []
        assert srcs == []
        assert len(libs) == 1
        assert "libjpeg.a" in str(libs[0])

    def test_unknown_falls_back(self, tmp_path):
        # Create a dummy object for _sanitized_entries
        manifest = {
            "lib_exports": {},
            "static_symbols": [],
            "symbol_to_objects": {},
            "libs": ["lib.a"],
            "objects": ["obj.o"],
        }
        objs, libs, srcs = _resolve_link_deps("unknown_func", manifest, tmp_path)
        # Falls back to all objects + libs
        assert srcs == []

    def test_object_global(self, tmp_path):
        manifest = {
            "lib_exports": {},
            "static_symbols": [],
            "symbol_to_objects": {"helper": ["build_sanitized/helper.c.o"]},
            "libs": ["build_sanitized/libjpeg.a"],
        }
        objs, libs, srcs = _resolve_link_deps("helper", manifest, tmp_path)
        assert len(objs) == 1
        assert "helper.c.o" in str(objs[0])
        assert srcs == []
