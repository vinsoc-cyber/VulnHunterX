# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P2a — typed status/scope/exhaustive assertions for ContextProvider handlers.

These assert the NEW structured fields. Byte-for-byte prompt_content parity is
covered separately by tests/test_context_prompt_parity.py.
"""

from __future__ import annotations

import csv
from types import SimpleNamespace

import pytest

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceRequest,
    EvidenceScope,
    EvidenceStatus,
)
from vuln_hunter_x.context.provider import ContextProvider


def _write_csv(path, rows, fieldnames):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        w.writerows(rows)


def _req(raw: str) -> EvidenceRequest:
    r = EvidenceRequest.parse(raw)
    assert r is not None
    return r


@pytest.fixture()
def prov(tmp_path):
    out = tmp_path / "output"
    repos = tmp_path / "repos"
    ctx = out / "cpp" / "app" / "context"
    ctx.mkdir(parents=True)
    src = repos / "cpp" / "app"
    src.mkdir(parents=True)
    (src / "m.cpp").write_text("\n".join(f"line {i}" for i in range(1, 30)), encoding="utf-8")

    _write_csv(
        ctx / "functions.csv",
        [
            {"name": "helper", "file": "m.cpp", "start_line": "10", "end_line": "12"},
            {"name": "dup", "file": "m.cpp", "start_line": "1", "end_line": "2"},
            {"name": "dup", "file": "m.cpp", "start_line": "3", "end_line": "4"},
            {"name": "many", "file": "m.cpp", "start_line": "1", "end_line": "2"},
            {"name": "many", "file": "m.cpp", "start_line": "3", "end_line": "4"},
            {"name": "many", "file": "m.cpp", "start_line": "5", "end_line": "6"},
            {"name": "many", "file": "m.cpp", "start_line": "7", "end_line": "8"},
            {"name": "bad", "file": "m.cpp", "start_line": "0", "end_line": "0"},
        ],
        ["name", "file", "start_line", "end_line"],
    )
    _write_csv(ctx / "structs.csv", [{"name": "W", "file": "m.cpp", "start_line": "4", "end_line": "7"}], ["name", "file", "start_line", "end_line"])
    _write_csv(ctx / "globals.csv", [{"name": "g", "file": "m.cpp", "start_line": "8", "end_line": "8", "type": "int"}], ["name", "file", "start_line", "end_line", "type"])
    _write_csv(ctx / "macros.csv", [{"name": "M", "file": "m.cpp", "line": "2", "body": "128"}], ["name", "file", "line", "body"])
    _write_csv(ctx / "typedefs.csv", [{"name": "T", "file": "m.cpp", "line": "3", "underlying_type": "struct N"}], ["name", "file", "line", "underlying_type"])
    _write_csv(ctx / "enums.csv", [{"name": "E", "file": "m.cpp", "member": "RED", "value": "0"}], ["name", "file", "member", "value"])
    _write_csv(
        ctx / "callers.csv",
        [
            {"callee_name": "sink", "caller_name": "caller1", "caller_file": "m.cpp", "caller_start_line": "10", "caller_end_line": "12"},
            {"callee_name": "helper", "caller_name": "fn", "caller_file": "m.cpp", "caller_start_line": "1", "caller_end_line": "2"},
        ],
        ["callee_name", "caller_name", "caller_file", "caller_start_line", "caller_end_line"],
    )
    _write_csv(
        ctx / "free_sites.csv",
        [
            {"pointer_name": "p", "free_kind": "free", "in_function": "helper", "file": "m.cpp", "line": "11"},
            {"pointer_name": "inbuf", "free_kind": "free", "in_function": "fn", "file": "m.cpp", "line": "2"},
        ],
        ["pointer_name", "free_kind", "in_function", "file", "line"],
    )
    _write_csv(ctx / "destructors.csv", [{"type_name": "W", "method_name": "~W", "file": "m.cpp", "start_line": "4", "end_line": "7"}], ["type_name", "method_name", "file", "start_line", "end_line"])
    _write_csv(ctx / "field_writes.csv", [{"type_field": "W.buf", "in_function": "fn", "file": "m.cpp", "line": "2"}], ["type_field", "in_function", "file", "line"])

    # JS repo for framework grep (sanitizer markers present; no guard markers).
    js_src = repos / "javascript" / "web"
    js_src.mkdir(parents=True)
    (js_src / "app.ts").write_text(
        "app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));\n",
        encoding="utf-8",
    )

    return ContextProvider(out, repos)


class TestCallGraphTyped:
    def test_caller_found(self, prov):
        assert prov._resolve_caller(_req("caller:sink"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_caller_absent_function_exists_incomplete(self, prov):
        # 'bad' is in functions.csv but has no caller edge -> best-effort graph miss.
        assert prov._resolve_caller(_req("caller:bad"), "app", "cpp").status is EvidenceStatus.INCOMPLETE_INDEX

    def test_caller_absent_function_missing_incomplete(self, prov):
        assert prov._resolve_caller(_req("caller:ghost"), "app", "cpp").status is EvidenceStatus.INCOMPLETE_INDEX

    def test_all_callers_found(self, prov):
        assert prov._resolve_all_callers(_req("all_callers:helper"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_all_callers_absent_incomplete(self, prov):
        assert prov._resolve_all_callers(_req("all_callers:ghost"), "app", "cpp").status is EvidenceStatus.INCOMPLETE_INDEX

    def test_callees_found(self, prov):
        assert prov._resolve_callees(_req("callees:fn"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_callees_absent_incomplete(self, prov):
        assert prov._resolve_callees(_req("callees:ghost"), "app", "cpp").status is EvidenceStatus.INCOMPLETE_INDEX

    def test_callee_bodies_found(self, prov):
        assert prov._resolve_callee_bodies(_req("callee_bodies:fn"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_callee_bodies_none_incomplete(self, prov):
        assert prov._resolve_callee_bodies(_req("callee_bodies:ghost"), "app", "cpp").status is EvidenceStatus.INCOMPLETE_INDEX

    def test_call_graph_found_not_exhaustive(self, prov):
        # call graph is best-effort; positive results are never claimed exhaustive.
        assert prov._resolve_caller(_req("caller:sink"), "app", "cpp").exhaustive is False


class TestBoundedSearchTyped:
    def test_free_sites_exact_found(self, prov):
        assert prov._resolve_free_sites(_req("free_sites:p"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_free_sites_substring_ambiguous(self, prov):
        # 'buf' has no exact row but is a substring of 'inbuf' -> fallback match.
        assert prov._resolve_free_sites(_req("free_sites:buf"), "app", "cpp").status is EvidenceStatus.AMBIGUOUS

    def test_free_sites_none_incomplete(self, prov):
        assert prov._resolve_free_sites(_req("free_sites:zzz"), "app", "cpp").status is EvidenceStatus.INCOMPLETE_INDEX

    def test_free_sites_csv_missing_incomplete_cpp(self, prov):
        assert prov._resolve_free_sites(_req("free_sites:p"), "other", "cpp").status is EvidenceStatus.INCOMPLETE_INDEX

    def test_free_sites_unsupported_python(self, prov):
        assert prov._resolve_free_sites(_req("free_sites:p"), "app", "python").status is EvidenceStatus.UNSUPPORTED

    def test_destructor_found(self, prov):
        assert prov._resolve_destructor(_req("destructor:W"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_destructor_csv_missing_incomplete_cpp(self, prov):
        assert prov._resolve_destructor(_req("destructor:W"), "other", "cpp").status is EvidenceStatus.INCOMPLETE_INDEX

    def test_field_writes_exact_found(self, prov):
        assert prov._resolve_field_writes(_req("field_writes:W.buf"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_field_writes_substring_ambiguous(self, prov):
        assert prov._resolve_field_writes(_req("field_writes:buf"), "app", "cpp").status is EvidenceStatus.AMBIGUOUS


class TestFrameworkGrepTyped:
    def test_sanitizers_found(self, prov):
        res = prov._resolve_framework_sanitizers(
            EvidenceRequest(EvidenceKind.FRAMEWORK_SANITIZERS, "", "framework_sanitizers:x"), "web", "javascript"
        )
        assert res.status is EvidenceStatus.FOUND
        assert res.scope is EvidenceScope.REPOSITORY_SOURCE

    def test_guards_no_hit_complete(self, prov):
        # guard markers absent; grep completes under bounds -> NOT_FOUND_COMPLETE of markers.
        res = prov._resolve_framework_guards(
            EvidenceRequest(EvidenceKind.FRAMEWORK_GUARDS, "", "framework_guards:x"), "web", "javascript"
        )
        assert res.status is EvidenceStatus.NOT_FOUND_COMPLETE

    def test_repo_source_unavailable_incomplete(self, prov):
        res = prov._resolve_framework_guards(
            EvidenceRequest(EvidenceKind.FRAMEWORK_GUARDS, "", "framework_guards:x"), "nonexistent", "javascript"
        )
        assert res.status is EvidenceStatus.INCOMPLETE_INDEX

    def test_bound_out_incomplete(self, prov, monkeypatch):
        # grep hit the max_files bound before finishing -> the search is incomplete.
        monkeypatch.setattr(
            prov, "_grep_repo",
            lambda *a, **k: ([], SimpleNamespace(hit_max_files=True, hit_max_hits=False)),
        )
        res = prov._resolve_framework_sanitizers(
            EvidenceRequest(EvidenceKind.FRAMEWORK_SANITIZERS, "", "framework_sanitizers:x"), "web", "javascript"
        )
        assert res.status is EvidenceStatus.INCOMPLETE_INDEX


class TestGrepBounds:
    def test_hit_max_files(self, prov):
        root = prov._repo_root("javascript", "web")
        _, bounds = prov._grep_repo(root, ("ValidationPipe",), exts=(".ts",), max_files=0)
        assert bounds.hit_max_files is True

    def test_hit_max_hits(self, prov):
        root = prov._repo_root("javascript", "web")
        hits, bounds = prov._grep_repo(root, ("ValidationPipe",), exts=(".ts",), max_hits=1)
        # single marker file, max_hits=1 -> found one, loop returns on next file check
        assert len(hits) == 1


class TestFunctionTyped:
    def test_found_single(self, prov):
        res = prov._resolve_function(_req("function:helper"), "app", "cpp")
        assert res.status is EvidenceStatus.FOUND
        assert res.scope is EvidenceScope.FILE
        assert res.exhaustive is True
        assert res.provenance and res.provenance[0].file == "m.cpp"

    def test_multi_def_ambiguous(self, prov):
        res = prov._resolve_function(_req("function:dup"), "app", "cpp")
        assert res.status is EvidenceStatus.AMBIGUOUS
        assert res.exhaustive is True  # 2 <= max_matches(3)

    def test_over_cap_not_exhaustive(self, prov):
        res = prov._resolve_function(_req("function:many"), "app", "cpp")
        assert res.status is EvidenceStatus.AMBIGUOUS
        assert res.exhaustive is False  # 4 > max_matches(3)

    def test_metadata_unreadable(self, prov):
        res = prov._resolve_function(_req("function:bad"), "app", "cpp")
        assert res.status is EvidenceStatus.INCOMPLETE_INDEX

    def test_absent_present_index_incomplete(self, prov):
        # functions.csv exists but 'ghost' absent; symbol index is not authoritative.
        res = prov._resolve_function(_req("function:ghost"), "app", "cpp")
        assert res.status is EvidenceStatus.INCOMPLETE_INDEX

    def test_absent_missing_index_incomplete_when_supported(self, prov):
        # No functions.csv for this repo; FUNCTION is supported -> INCOMPLETE_INDEX.
        res = prov._resolve_function(_req("function:x"), "other", "cpp")
        assert res.status is EvidenceStatus.INCOMPLETE_INDEX


class TestSimpleSymbolsTyped:
    def test_struct_found(self, prov):
        assert prov._resolve_struct(_req("struct:W"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_global_found(self, prov):
        assert prov._resolve_global(_req("global:g"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_macro_found(self, prov):
        assert prov._resolve_macro(_req("macro:M"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_typedef_found(self, prov):
        assert prov._resolve_typedef(_req("typedef:T"), "app", "cpp").status is EvidenceStatus.FOUND

    def test_enum_found(self, prov):
        assert prov._resolve_enum(_req("enum:E"), "app", "cpp").status is EvidenceStatus.FOUND


class TestUnsupportedForLanguage:
    def test_typedef_unsupported_python(self, prov):
        # typedef is C-family only; missing artifact for python -> UNSUPPORTED.
        res = prov._resolve_typedef(_req("typedef:T"), "app", "python")
        assert res.status is EvidenceStatus.UNSUPPORTED

    def test_global_unsupported_python(self, prov):
        res = prov._resolve_global(_req("global:g"), "app", "python")
        assert res.status is EvidenceStatus.UNSUPPORTED

    def test_function_incomplete_python_missing(self, prov):
        # function IS supported for python; missing artifact -> INCOMPLETE_INDEX.
        res = prov._resolve_function(_req("function:f"), "app", "python")
        assert res.status is EvidenceStatus.INCOMPLETE_INDEX
