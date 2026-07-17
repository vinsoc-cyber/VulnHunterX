# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P5b provider surface: engine-derived reachability evidence over a synthetic
Go repo (functions.csv + callers.csv + real .go source). Deterministic, no LLM.

Three methods, each fail-closed:
  - resolve_repo_unique_enclosing_function: (file,line) -> a repo-wide-unique SymbolRef
  - resolve_all_recorded_callers: unbounded, P5a-qualified caller enumeration
  - scan_non_test_go_name_occurrences: conservative non-*_test.go reference veto
"""

from __future__ import annotations

import csv

from vuln_hunter_x.context.evidence import EvidenceStatus, SourceRef, SymbolRef
from vuln_hunter_x.context.provider import ContextProvider

_FUNC_COLS = ["name", "file", "start_line", "end_line", "param_count", "is_static"]
_CALLER_COLS = [
    "callee_name", "callee_file", "caller_name",
    "caller_file", "caller_start_line", "caller_end_line",
]


def _provider(tmp_path, *, functions, callers=(), sources=None, repo="svc", lang="go"):
    """Write output/<lang>/<repo>/context/{functions,callers}.csv + repos/<lang>/<repo>/<src>."""
    out = tmp_path / "output"
    repos = tmp_path / "repos"
    ctx = out / lang / repo / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    with open(ctx / "functions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_FUNC_COLS)
        w.writeheader()
        for r in functions:
            row = {"param_count": "0", "is_static": "false"}
            row.update(r)
            w.writerow(row)
    with open(ctx / "callers.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_CALLER_COLS)
        w.writeheader()
        for r in callers:
            w.writerow(r)
    src_root = repos / lang / repo
    src_root.mkdir(parents=True, exist_ok=True)
    for relpath, text in (sources or {}).items():
        p = src_root / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return ContextProvider(out, repos)


def _fn(name, file, start, end):
    return {"name": name, "file": file, "start_line": str(start), "end_line": str(end)}


def _caller(callee, callee_file, caller, caller_file, start, end):
    return {
        "callee_name": callee, "callee_file": callee_file, "caller_name": caller,
        "caller_file": caller_file, "caller_start_line": str(start), "caller_end_line": str(end),
    }


# minimal Go source so resolve_repo_file (existence + containment) succeeds
_SIG_SRC = "package crypto\n\nfunc verifySig(a, b string) bool {\n\treturn a == b\n}\n"


# ---- Task 1: resolve_repo_unique_enclosing_function ----

def test_resolve_unique_enclosing_returns_symbol(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", "internal/crypto/signature.go", 3, 5)],
        sources={"internal/crypto/signature.go": _SIG_SRC},
    )
    res = p.resolve_repo_unique_enclosing_function("svc", "go", "internal/crypto/signature.go", 4)
    assert res.status is EvidenceStatus.FOUND
    assert res.symbol is not None
    assert res.symbol.name == "verifySig"
    assert res.symbol.source_ref.file == "internal/crypto/signature.go"


def test_resolve_innermost_range(tmp_path):
    src = "package p\n\nfunc outer() {\n\tfunc() {\n\t\tx()\n\t}()\n}\n"
    p = _provider(
        tmp_path,
        functions=[_fn("outer", "a.go", 3, 7), _fn("inner", "a.go", 4, 6)],
        sources={"a.go": src},
    )
    res = p.resolve_repo_unique_enclosing_function("svc", "go", "a.go", 5)
    assert res.status is EvidenceStatus.FOUND
    assert res.symbol.name == "inner"


def test_resolve_non_unique_name_repo_wide_abstains(tmp_path):
    p = _provider(
        tmp_path,
        functions=[
            _fn("verifySig", "internal/crypto/signature.go", 3, 5),
            _fn("verifySig", "internal/legacy/old.go", 3, 5),
        ],
        sources={
            "internal/crypto/signature.go": _SIG_SRC,
            "internal/legacy/old.go": _SIG_SRC,
        },
    )
    res = p.resolve_repo_unique_enclosing_function("svc", "go", "internal/crypto/signature.go", 4)
    assert res.status is not EvidenceStatus.FOUND
    assert res.symbol is None


def test_resolve_line_outside_any_function(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", "internal/crypto/signature.go", 3, 5)],
        sources={"internal/crypto/signature.go": _SIG_SRC},
    )
    res = p.resolve_repo_unique_enclosing_function("svc", "go", "internal/crypto/signature.go", 99)
    assert res.status is EvidenceStatus.INCOMPLETE_INDEX
    assert res.symbol is None


def test_resolve_path_escape_abstains(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", "internal/crypto/signature.go", 3, 5)],
        sources={"internal/crypto/signature.go": _SIG_SRC},
    )
    res = p.resolve_repo_unique_enclosing_function("svc", "go", "../../../etc/passwd", 1)
    assert res.status is not EvidenceStatus.FOUND
    assert res.symbol is None
