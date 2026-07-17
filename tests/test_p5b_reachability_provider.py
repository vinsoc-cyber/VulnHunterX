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


# ---- Task 2: resolve_all_recorded_callers (unbounded, P5a-qualified) ----

_SIG_FILE = "internal/crypto/signature.go"


def _target(name="verifySig", file=_SIG_FILE, start=3, end=5, repo="svc", lang="go"):
    return SymbolRef(name, "function", SourceRef(repo, lang, file, start, end))


def test_enumerate_all_callers_no_cap(tmp_path):
    callers = [
        _caller("verifySig", _SIG_FILE, f"TestVerify{i}", f"internal/crypto/sig{i}_test.go", 10, 20)
        for i in range(10)
    ]
    callers.append(_caller("verifySig", _SIG_FILE, "Prod", "internal/crypto/crypto.go", 30, 40))
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", _SIG_FILE, 3, 5)],
        callers=callers,
    )
    res = p.resolve_all_recorded_callers("svc", "go", _target())
    assert res.status is EvidenceStatus.FOUND
    assert res.enumerated_all_rows is True
    assert len(res.callers) == 11  # NOT capped at 10


def test_all_test_callers_found(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", _SIG_FILE, 3, 5)],
        callers=[
            _caller("verifySig", _SIG_FILE, "TestA", "internal/crypto/a_test.go", 10, 20),
            _caller("verifySig", _SIG_FILE, "TestB", "internal/crypto/b_test.go", 30, 40),
        ],
    )
    res = p.resolve_all_recorded_callers("svc", "go", _target())
    assert res.status is EvidenceStatus.FOUND
    assert res.enumerated_all_rows is True
    assert {c.source_ref.file for c in res.callers} == {
        "internal/crypto/a_test.go", "internal/crypto/b_test.go"
    }


def test_empty_callers_is_incomplete_index_but_enumerated(tmp_path):
    p = _provider(tmp_path, functions=[_fn("verifySig", _SIG_FILE, 3, 5)], callers=[])
    res = p.resolve_all_recorded_callers("svc", "go", _target())
    assert res.status is EvidenceStatus.INCOMPLETE_INDEX
    assert res.enumerated_all_rows is True
    assert res.callers == ()


def test_homonym_callee_file_qualified(tmp_path):
    # verifySig defined in two files; callers split by callee_file. A target on
    # signature.go must return ONLY signature.go's callers (P5a binding), never
    # merge old.go's.
    p = _provider(
        tmp_path,
        functions=[
            _fn("verifySig", _SIG_FILE, 3, 5),
            _fn("verifySig", "internal/legacy/old.go", 3, 5),
        ],
        callers=[
            _caller("verifySig", _SIG_FILE, "TestNew", "internal/crypto/new_test.go", 10, 20),
            _caller("verifySig", "internal/legacy/old.go", "TestOld", "internal/legacy/old_test.go", 10, 20),
        ],
    )
    res = p.resolve_all_recorded_callers("svc", "go", _target())
    assert res.status is EvidenceStatus.FOUND
    assert {c.source_ref.file for c in res.callers} == {"internal/crypto/new_test.go"}


def test_malformed_caller_row_abstains(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", _SIG_FILE, 3, 5)],
        callers=[
            {
                "callee_name": "verifySig", "callee_file": _SIG_FILE, "caller_name": "X",
                "caller_file": "internal/crypto/x_test.go",
                "caller_start_line": "not-an-int", "caller_end_line": "20",
            }
        ],
    )
    res = p.resolve_all_recorded_callers("svc", "go", _target())
    assert res.enumerated_all_rows is False


def test_caller_path_escape_abstains(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", _SIG_FILE, 3, 5)],
        callers=[_caller("verifySig", _SIG_FILE, "X", "../../../etc/passwd", 10, 20)],
    )
    res = p.resolve_all_recorded_callers("svc", "go", _target())
    assert res.enumerated_all_rows is False


# ---- Task 3: scan_non_test_go_name_occurrences (declaration-token-excluded veto) ----

# verifySig declared on line 3 (aligns with _target(start=3)).
_DECL_ONLY = "package crypto\n\nfunc verifySig(a, b string) bool {\n\treturn a == b\n}\n"


def test_scan_zero_non_test_occurrences_complete(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", _SIG_FILE, 3, 5)],
        sources={
            _SIG_FILE: _DECL_ONLY,
            "internal/crypto/signature_test.go": "package crypto\n\nfunc TestV(t any){ verifySig(\"a\",\"b\") }\n",
        },
    )
    res = p.scan_non_test_go_name_occurrences("svc", _target())
    assert res.status is EvidenceStatus.NOT_FOUND_COMPLETE
    assert res.scan_complete is True


def test_scan_finds_production_reference(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", _SIG_FILE, 3, 5)],
        sources={
            _SIG_FILE: _DECL_ONLY,
            "internal/crypto/crypto.go": "package crypto\n\nfunc live(){ verifySig(\"a\",\"b\") }\n",
        },
    )
    res = p.scan_non_test_go_name_occurrences("svc", _target())
    assert res.status is EvidenceStatus.FOUND
    assert any(m.file == "internal/crypto/crypto.go" for m in res.matches)


def test_scan_decl_line_registration_still_found(tmp_path):
    # decl and a function-value registration on the SAME line: exclude the decl
    # TOKEN, keep the registration reference. (Under-suppression guard.)
    src = "package crypto\n\nfunc verifySig() { register(verifySig) }\n"
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", _SIG_FILE, 3, 3)],
        sources={_SIG_FILE: src},
    )
    res = p.scan_non_test_go_name_occurrences("svc", _target(start=3, end=3))
    assert res.status is EvidenceStatus.FOUND


def test_scan_vendor_tests_demo_are_scanned(tmp_path):
    for rel in ("vendor/x/foo.go", "internal/tests/foo.go", "cmd/demo.go"):
        p = _provider(
            tmp_path / rel.replace("/", "_"),
            functions=[_fn("verifySig", _SIG_FILE, 3, 5)],
            sources={
                _SIG_FILE: _DECL_ONLY,
                rel: "package x\n\nfunc f(){ verifySig(\"a\",\"b\") }\n",
            },
        )
        res = p.scan_non_test_go_name_occurrences("svc", _target())
        assert res.status is EvidenceStatus.FOUND, rel  # only *_test.go basenames are excluded


def test_scan_word_boundary(tmp_path):
    p = _provider(
        tmp_path,
        functions=[_fn("verifySig", _SIG_FILE, 3, 5)],
        sources={
            _SIG_FILE: _DECL_ONLY,
            "internal/crypto/other.go": "package crypto\n\nfunc f(){ verifySigExtra() }\n",
        },
    )
    res = p.scan_non_test_go_name_occurrences("svc", _target())
    assert res.status is EvidenceStatus.NOT_FOUND_COMPLETE


def test_scan_missing_root_incomplete(tmp_path):
    p = _provider(tmp_path, functions=[_fn("verifySig", _SIG_FILE, 3, 5)], sources={_SIG_FILE: _DECL_ONLY})
    res = p.scan_non_test_go_name_occurrences("ghost-repo", _target())
    assert res.status is EvidenceStatus.INCOMPLETE_INDEX


def test_scan_decl_token_not_located_incomplete(tmp_path):
    # start_line points nowhere near the func decl -> cannot safely exclude -> abstain.
    p = _provider(tmp_path, functions=[_fn("verifySig", _SIG_FILE, 3, 5)], sources={_SIG_FILE: _DECL_ONLY})
    res = p.scan_non_test_go_name_occurrences("svc", _target(start=1, end=1))
    assert res.status is EvidenceStatus.INCOMPLETE_INDEX
