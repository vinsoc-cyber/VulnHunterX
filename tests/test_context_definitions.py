# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Definition lookups: struct CSV routing, multi-definition ambiguity, and the
CodeQL typedef/enum producers that back ``typedef:`` / ``enum:`` requests."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from vuln_hunter_x.codeql.context_extractor import QUERIES_BY_LANG, ContextExtractorDB
from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceRequest,
    EvidenceStatus,
    _kind_csv_name,
    struct_csv_name,
)
from vuln_hunter_x.context.provider import ContextProvider


def _write_csv(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _tree(tmp_path: Path, lang: str, files: dict[str, str]) -> tuple[ContextProvider, Path]:
    out = tmp_path / "output"
    repos = tmp_path / "repos"
    ctx = out / lang / "r" / "context"
    ctx.mkdir(parents=True)
    for rel, text in files.items():
        p = repos / lang / "r" / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text)
    return ContextProvider(out, repos), ctx


def _resolve(provider: ContextProvider, lang: str, kind: EvidenceKind, raw: str):
    req = EvidenceRequest(kind, raw.split(":", 1)[1], raw)
    return provider.resolve_evidence("r", lang, [req])[raw]


class TestStructCsvRouting:
    @pytest.mark.parametrize("lang", ["java", "go", "php", "python", "javascript", "csharp"])
    def test_non_c_languages_read_classes_csv(self, lang):
        assert struct_csv_name(lang) == "classes"
        assert _kind_csv_name(EvidenceKind.STRUCT, lang) == "classes"

    @pytest.mark.parametrize("lang", ["c", "cpp"])
    def test_c_family_reads_structs_csv(self, lang):
        assert struct_csv_name(lang) == "structs"

    @pytest.mark.parametrize("lang", ["java", "go", "php"])
    def test_struct_request_resolves_from_classes_csv(self, tmp_path, lang):
        provider, ctx = _tree(tmp_path, lang, {"m.src": "class Dto {\n  String name;\n}\n"})
        _write_csv(
            ctx / "classes.csv",
            [{"name": "Dto", "file": "m.src", "start_line": "1", "end_line": "3"}],
        )
        res = _resolve(provider, lang, EvidenceKind.STRUCT, "struct:Dto")
        assert res.status is EvidenceStatus.FOUND
        assert "String name;" in res.prompt_content


class TestMultipleDefinitions:
    def test_single_macro_definition_is_found(self, tmp_path):
        provider, ctx = _tree(tmp_path, "c", {})
        _write_csv(ctx / "macros.csv", [{"name": "N", "file": "a.h", "line": "3", "body": "16"}])
        res = _resolve(provider, "c", EvidenceKind.MACRO, "macro:N")
        assert res.status is EvidenceStatus.FOUND
        assert res.prompt_content == "// Macro: N\n// File: a.h:3\n#define N 16"

    def test_ifdef_macro_variants_are_all_shown_and_ambiguous(self, tmp_path):
        provider, ctx = _tree(tmp_path, "c", {})
        _write_csv(
            ctx / "macros.csv",
            [
                {"name": "BUFSZ", "file": "cfg.h", "line": "3", "body": "64"},
                {"name": "BUFSZ", "file": "cfg.h", "line": "5", "body": "4096"},
            ],
        )
        res = _resolve(provider, "c", EvidenceKind.MACRO, "macro:BUFSZ")
        assert res.status is EvidenceStatus.AMBIGUOUS
        assert "#define BUFSZ 64" in res.prompt_content
        assert "#define BUFSZ 4096" in res.prompt_content
        assert res.exhaustive is True

    def test_definitions_are_capped_and_marked_non_exhaustive(self, tmp_path):
        provider, ctx = _tree(tmp_path, "c", {})
        _write_csv(
            ctx / "typedefs.csv",
            [
                {"name": "len_t", "file": f"p{i}.h", "line": "1", "underlying_type": t}
                for i, t in enumerate(["int", "long", "short", "char", "unsigned"])
            ],
        )
        res = _resolve(provider, "c", EvidenceKind.TYPEDEF, "typedef:len_t")
        assert res.status is EvidenceStatus.AMBIGUOUS
        assert res.exhaustive is False
        assert "2 more definition(s) of len_t" in res.prompt_content

    def test_struct_member_rows_are_one_definition(self, tmp_path):
        # structs.csv has one row PER MEMBER; that is still a single definition.
        provider, ctx = _tree(tmp_path, "c", {"t.h": "struct P {\n  int x;\n  int y;\n};\n"})
        _write_csv(
            ctx / "structs.csv",
            [
                {"name": "P", "file": "t.h", "start_line": "1", "end_line": "4", "member_name": m}
                for m in ("x", "y")
            ],
        )
        res = _resolve(provider, "c", EvidenceKind.STRUCT, "struct:P")
        assert res.status is EvidenceStatus.FOUND
        assert res.prompt_content.count("// Struct/Class: P") == 1

    def test_same_class_name_in_two_files_is_ambiguous(self, tmp_path):
        provider, ctx = _tree(
            tmp_path,
            "python",
            {"a.py": "class Config:\n    debug = False\n", "b.py": "class Config:\n    debug = True\n"},
        )
        _write_csv(
            ctx / "classes.csv",
            [
                {"name": "Config", "file": f, "start_line": "1", "end_line": "2"}
                for f in ("a.py", "b.py")
            ],
        )
        res = _resolve(provider, "python", EvidenceKind.STRUCT, "struct:Config")
        assert res.status is EvidenceStatus.AMBIGUOUS
        assert "debug = False" in res.prompt_content and "debug = True" in res.prompt_content
        assert {p.file for p in res.provenance} == {"a.py", "b.py"}

    def test_global_redeclared_extern_is_ambiguous(self, tmp_path):
        provider, ctx = _tree(
            tmp_path, "c", {"g.h": "extern int limit;\n", "g.c": "int limit = 4;\n"}
        )
        _write_csv(
            ctx / "globals.csv",
            [
                {"name": "limit", "file": "g.h", "start_line": "1", "end_line": "1", "type": "extern int"},
                {"name": "limit", "file": "g.c", "start_line": "1", "end_line": "1", "type": "int"},
            ],
        )
        res = _resolve(provider, "c", EvidenceKind.GLOBAL, "global:limit")
        assert res.status is EvidenceStatus.AMBIGUOUS
        assert "int limit = 4;" in res.prompt_content


class TestSourceLineCache:
    def test_clear_cache_drops_cached_source(self, tmp_path):
        provider, _ = _tree(tmp_path, "c", {"a.c": "one\ntwo\n"})
        assert provider._read_lines("r", "c", "a.c", 1, 2) == "one\ntwo"
        (tmp_path / "repos" / "c" / "r" / "a.c").write_text("uno\ndos\n")
        assert provider._read_lines("r", "c", "a.c", 1, 2) == "one\ntwo"  # cached
        provider.clear_cache()
        assert provider._read_lines("r", "c", "a.c", 1, 2) == "uno\ndos"


class TestCodeqlTypedefEnumProducers:
    @pytest.mark.parametrize("lang", ["c", "cpp"])
    def test_typedefs_and_enums_are_extracted_for_c_family(self, lang):
        assert {"typedefs", "enums"} <= set(QUERIES_BY_LANG[lang])

    def test_query_files_exist_for_every_listed_query(self):
        queries_dir = Path(__file__).resolve().parents[1] / "config" / "queries" / "tools" / "cpp"
        for name in QUERIES_BY_LANG["cpp"]:
            assert (queries_dir / f"{name}.ql").is_file(), name

    def test_dry_run_lists_typedefs_and_enums(self, tmp_path):
        queries_dir = Path(__file__).resolve().parents[1] / "config" / "queries" / "tools"
        ext = ContextExtractorDB(queries_dir=queries_dir, output_dir=tmp_path)
        results = ext.extract_for_database(tmp_path / "db", "c", "r", dry_run=True)
        assert results["typedefs"][0] is True and results["enums"][0] is True
