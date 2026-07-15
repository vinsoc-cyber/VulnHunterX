# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P2a — typed status/scope/exhaustive assertions for ContextProvider handlers.

These assert the NEW structured fields. Byte-for-byte prompt_content parity is
covered separately by tests/test_context_prompt_parity.py.
"""

from __future__ import annotations

import csv

import pytest

from vuln_hunter_x.context.evidence import (
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

    return ContextProvider(out, repos)


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
