# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for harness generation with linkability-aware strategies."""

from __future__ import annotations

from vuln_hunter_x.fuzz.driver_generator import (
    _build_extern_declaration,
    generate_harness,
)


class TestBuildExternDeclaration:
    def test_simple(self):
        params = [{"type": "int", "name": "x"}, {"type": "const char *", "name": "s"}]
        decl = _build_extern_declaration("foo", params)
        assert 'extern "C"' in decl
        assert "foo" in decl
        assert "int x" in decl
        assert "const char * s" in decl

    def test_no_params(self):
        decl = _build_extern_declaration("bar", [])
        assert "void" in decl
        assert "bar" in decl


class TestGenerateHarnessLinkability:
    def test_library_exported_has_extern_decl(self, tmp_path):
        ctx = {
            "name": "jpeg_read_header",
            "file": "src/jdapimin.c",
            "start_line": 10,
            "end_line": 50,
            "params": [{"type": "int", "name": "x"}],
            "includes": ["<stdio.h>"],
            "struct_defs": {},
        }
        out = tmp_path / "harness.cc"
        generate_harness(
            "rule/test",
            "src/jdapimin.c",
            20,
            ctx,
            out,
            "test",
            linkability="library_exported",
        )
        content = out.read_text()
        assert "LLVMFuzzerTestOneInput" in content
        assert 'extern "C"' in content
        assert "jpeg_read_header" in content

    def test_static_has_source_inclusion(self, tmp_path):
        ctx = {
            "name": "decomp",
            "file": "src/tjbench.c",
            "start_line": 176,
            "end_line": 300,
            "params": [{"type": "int", "name": "x"}],
            "includes": ["<stdio.h>"],
            "struct_defs": {},
        }
        out = tmp_path / "harness.cc"
        generate_harness(
            "rule/test",
            "src/tjbench.c",
            180,
            ctx,
            out,
            "test",
            linkability="static",
            source_root="/opt/src",
            file_has_main=True,
        )
        content = out.read_text()
        assert "LLVMFuzzerTestOneInput" in content
        assert '#include "' in content
        assert "tjbench.c" in content
        assert "#define main __original_main_disabled" in content
        assert "#undef main" in content

    def test_static_without_main(self, tmp_path):
        ctx = {
            "name": "internal_helper",
            "file": "src/internal.c",
            "start_line": 10,
            "end_line": 30,
            "params": [],
            "includes": [],
            "struct_defs": {},
        }
        out = tmp_path / "harness.cc"
        generate_harness(
            "rule/test",
            "src/internal.c",
            15,
            ctx,
            out,
            "test",
            linkability="static",
            source_root="/opt/src",
            file_has_main=False,
        )
        content = out.read_text()
        assert "LLVMFuzzerTestOneInput" in content
        assert '#include "' in content
        assert "internal.c" in content
        assert "#define main" not in content

    def test_unknown_linkability_no_extern_decl(self, tmp_path):
        ctx = {
            "name": "mystery",
            "file": "src/x.c",
            "start_line": 1,
            "end_line": 10,
            "params": [{"type": "int", "name": "n"}],
            "includes": ["<stdlib.h>"],
            "struct_defs": {},
        }
        out = tmp_path / "harness.cc"
        generate_harness(
            "rule/test",
            "src/x.c",
            5,
            ctx,
            out,
            "test",
            linkability="unknown",
        )
        content = out.read_text()
        assert "LLVMFuzzerTestOneInput" in content
        # unknown linkability: uses normal includes, no extern decl
        assert "#include <stdlib.h>" in content
