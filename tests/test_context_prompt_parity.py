# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P2a characterization lock — byte-for-byte parity of context retrieval.

Captures the artifacts a verifier consumer actually sees, from the BASELINE
provider code, into goldens under tests/golden/context_parity/. Every later
P2a commit must keep these green: identical provider dicts AND identical
assembled prompts (the client.py prefetch filter + build_followup_prompt) are
the real verdict-neutral stop criterion.

Goldens are generated on first run (from unmodified provider code) and then
committed; after that they are a regression lock.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.context.snippet_provider import SnippetContextProvider
from vuln_hunter_x.llm.prompts import PromptBuilder

GOLDEN_DIR = Path(__file__).parent / "golden" / "context_parity"


def _write_csv(path: Path, rows: list[dict], fieldnames: list[str]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def _ser(d: dict[str, str]) -> str:
    """Serialize a request->string dict preserving order (order is observable)."""
    return json.dumps(list(d.items()), indent=2, ensure_ascii=False)


def _prefetch_block(d: dict[str, str]) -> str:
    """Replicate the client.py:476-485 prefetch filter (the [No / [Unknown gate)."""
    parts = []
    for req, code in d.items():
        if "[No " not in code and "[Unknown" not in code:
            parts.append(f"### {req}\n```\n{code}\n```")
    if parts:
        return "\n\n## Pre-fetched Additional Context\n\n" + "\n\n".join(parts)
    return ""


def _check_golden(name: str, content: str) -> None:
    GOLDEN_DIR.mkdir(parents=True, exist_ok=True)
    p = GOLDEN_DIR / name
    if not p.exists():
        p.write_text(content, encoding="utf-8")
    assert content == p.read_text(encoding="utf-8"), f"context parity drift in {name}"


_CPP_SOURCE = "\n".join(
    [
        "// app main",                        # 1
        "#define MAXLEN 128",                 # 2
        "typedef struct Node Node;",          # 3
        "struct Widget {",                    # 4
        "  int id;",                          # 5
        "  char* buf;",                       # 6
        "};",                                 # 7
        "int g_count = 0;",                   # 8
        "enum Color { RED, GREEN, BLUE };",   # 9
        "void helper(char* p) {",             # 10
        "  free(p);",                         # 11
        "}",                                  # 12
        "void process(char* in) {",           # 13
        "  helper(in);",                      # 14
        "  free(in);",                        # 15
        "}",                                  # 16
        "void process(int n) {",              # 17
        "  int x = n + 1;",                   # 18
        "}",                                  # 19
        "void orphan() {",                    # 20
        "  int unused = 0;",                  # 21
        "}",                                  # 22
        "Widget::~Widget() {",                # 23
        "  free(buf);",                       # 24
        "}",                                  # 25
    ]
)

_JS_SOURCE = "\n".join(
    [
        "import { ValidationPipe } from '@nestjs/common';",
        "export async function bootstrap(app) {",
        "  app.useGlobalPipes(new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true }));",
        "}",
    ]
)

_SNIPPET = "\n".join(
    [
        "struct Point { int x; int y; };",
        "#define SZ 8",
        "void run() {",
        "  char* p = malloc(SZ);",
        "  free(p);",
        "  helper(p);",
        "}",
    ]
)

_CPP_REQUESTS = [
    "caller:helper", "caller:orphan", "caller:ghost",
    "all_callers:free",
    "callees:process",
    "callee_bodies:process",
    "function:helper", "function:process", "function:badline", "function:ghost",
    "struct:Widget", "struct:Missing",
    "global:g_count", "global:missing",
    "macro:MAXLEN", "macro:MISSING",
    "typedef:Node", "typedef:Missing",
    "enum:Color", "enum:Missing",
    "free_sites:p", "free_sites:buf", "free_sites:zzz",
    "destructor:Widget", "destructor:Missing",
    "field_writes:Widget.buf", "field_writes:buf", "field_writes:Zzz.q",
    "bogus:x",
    "noColonHere",
    # aliases route to the same handlers:
    "method:helper", "classes:Widget", "func:process", "free_site:p",
]

_BARE_REQUESTS = [
    "free_sites:p", "destructor:Widget", "field_writes:Widget.buf",
    "function:foo", "caller:foo",
]

_JS_REQUESTS = ["framework_sanitizers:x", "framework_guards:x"]

_SNIPPET_REQUESTS = [
    "struct:Point", "macro:SZ", "free_sites:p", "callees:run",
    "caller:run", "global:g", "enum:E", "typedef:T",
    "destructor:X", "field_writes:X.y", "bogus:z", "noColonHere",
]


@pytest.fixture(scope="module")
def world(tmp_path_factory):
    base = tmp_path_factory.mktemp("parity")
    output_dir = base / "output"
    repos_dir = base / "repos"

    # cpp/app — full CSVs + source
    app_ctx = output_dir / "cpp" / "app" / "context"
    app_ctx.mkdir(parents=True)
    app_src = repos_dir / "cpp" / "app"
    app_src.mkdir(parents=True)
    (app_src / "main.cpp").write_text(_CPP_SOURCE, encoding="utf-8")

    _write_csv(
        app_ctx / "functions.csv",
        [
            {"name": "helper", "file": "main.cpp", "start_line": "10", "end_line": "12"},
            {"name": "process", "file": "main.cpp", "start_line": "13", "end_line": "16"},
            {"name": "process", "file": "main.cpp", "start_line": "17", "end_line": "19"},
            {"name": "orphan", "file": "main.cpp", "start_line": "20", "end_line": "22"},
            {"name": "badline", "file": "main.cpp", "start_line": "0", "end_line": "0"},
        ],
        ["name", "file", "start_line", "end_line"],
    )
    _write_csv(
        app_ctx / "callers.csv",
        [
            {"callee_name": "helper", "caller_name": "process", "caller_file": "main.cpp", "caller_start_line": "13", "caller_end_line": "16"},
            {"callee_name": "free", "caller_name": "process", "caller_file": "main.cpp", "caller_start_line": "13", "caller_end_line": "16"},
            {"callee_name": "free", "caller_name": "helper", "caller_file": "main.cpp", "caller_start_line": "10", "caller_end_line": "12"},
        ],
        ["callee_name", "caller_name", "caller_file", "caller_start_line", "caller_end_line"],
    )
    _write_csv(app_ctx / "structs.csv", [{"name": "Widget", "file": "main.cpp", "start_line": "4", "end_line": "7"}], ["name", "file", "start_line", "end_line"])
    _write_csv(app_ctx / "globals.csv", [{"name": "g_count", "file": "main.cpp", "start_line": "8", "end_line": "8", "type": "int"}], ["name", "file", "start_line", "end_line", "type"])
    _write_csv(app_ctx / "macros.csv", [{"name": "MAXLEN", "file": "main.cpp", "line": "2", "body": "128"}], ["name", "file", "line", "body"])
    _write_csv(app_ctx / "typedefs.csv", [{"name": "Node", "file": "main.cpp", "line": "3", "underlying_type": "struct Node"}], ["name", "file", "line", "underlying_type"])
    _write_csv(
        app_ctx / "enums.csv",
        [
            {"name": "Color", "file": "main.cpp", "member": "RED", "value": "0"},
            {"name": "Color", "file": "main.cpp", "member": "GREEN", "value": "1"},
            {"name": "Color", "file": "main.cpp", "member": "BLUE", "value": "2"},
        ],
        ["name", "file", "member", "value"],
    )
    _write_csv(
        app_ctx / "free_sites.csv",
        [
            {"pointer_name": "p", "free_kind": "free", "in_function": "helper", "file": "main.cpp", "line": "11"},
            {"pointer_name": "inbuf", "free_kind": "free", "in_function": "process", "file": "main.cpp", "line": "15"},
        ],
        ["pointer_name", "free_kind", "in_function", "file", "line"],
    )
    _write_csv(app_ctx / "destructors.csv", [{"type_name": "Widget", "method_name": "~Widget", "file": "main.cpp", "start_line": "23", "end_line": "25"}], ["type_name", "method_name", "file", "start_line", "end_line"])
    _write_csv(app_ctx / "field_writes.csv", [{"type_field": "Widget.buf", "in_function": "process", "file": "main.cpp", "line": "15"}], ["type_field", "in_function", "file", "line"])

    # cpp/bare — context dir exists but NO csvs
    (output_dir / "cpp" / "bare" / "context").mkdir(parents=True)
    (repos_dir / "cpp" / "bare").mkdir(parents=True)

    # javascript/web — grep source with sanitizer markers, no guard markers
    js_src = repos_dir / "javascript" / "web"
    js_src.mkdir(parents=True)
    (js_src / "app.ts").write_text(_JS_SOURCE, encoding="utf-8")
    (output_dir / "javascript" / "web" / "context").mkdir(parents=True)

    return ContextProvider(output_dir, repos_dir)


class TestCsvProviderParity:
    def test_app_dict(self, world):
        d = world.get_additional_context("app", "cpp", _CPP_REQUESTS)
        _check_golden("csv_app_dict.txt", _ser(d))

    def test_app_followup(self, world):
        d = world.get_additional_context("app", "cpp", _CPP_REQUESTS)
        _check_golden("csv_app_followup.txt", PromptBuilder().build_followup_prompt(d))

    def test_app_prefetch(self, world):
        d = world.get_additional_context("app", "cpp", _CPP_REQUESTS)
        _check_golden("csv_app_prefetch.txt", _prefetch_block(d))

    def test_bare_dict(self, world):
        d = world.get_additional_context("bare", "cpp", _BARE_REQUESTS)
        _check_golden("csv_bare_dict.txt", _ser(d))

    def test_js_framework_dict(self, world):
        d = world.get_additional_context("web", "javascript", _JS_REQUESTS)
        _check_golden("csv_js_framework_dict.txt", _ser(d))


class TestSnippetProviderParity:
    def _provider(self):
        return SnippetContextProvider(_SNIPPET, "run")

    def test_dict(self):
        d = self._provider().get_additional_context("app", "cpp", _SNIPPET_REQUESTS)
        _check_golden("snippet_dict.txt", _ser(d))

    def test_followup(self):
        d = self._provider().get_additional_context("app", "cpp", _SNIPPET_REQUESTS)
        _check_golden("snippet_followup.txt", PromptBuilder().build_followup_prompt(d))

    def test_prefetch(self):
        d = self._provider().get_additional_context("app", "cpp", _SNIPPET_REQUESTS)
        _check_golden("snippet_prefetch.txt", _prefetch_block(d))
