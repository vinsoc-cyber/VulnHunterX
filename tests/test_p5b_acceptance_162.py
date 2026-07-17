# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P5b acceptance (#162): the reachability gate end-to-end through the REAL
ContextProvider (functions.csv + callers.csv + real .go source) — resolve ->
enumerate -> scan -> withhold. Deterministic, no LLM. Abstain-only: TP->NMD,
never ->FP; anything uncertain leaves the verdict unchanged.
"""

from __future__ import annotations

import csv

from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import _downgrade_test_only_reachability

_FUNC_COLS = ["name", "file", "start_line", "end_line", "param_count", "is_static"]
_CALLER_COLS = [
    "callee_name", "callee_file", "caller_name",
    "caller_file", "caller_start_line", "caller_end_line",
]
_SIG = "internal/crypto/signature.go"
# verifySig on line 3 (aligns with the sink at line 4 below).
_DECL = "package crypto\n\nfunc verifySig(a, b string) bool {\n\treturn a == b\n}\n"
_TEST_SRC = "package crypto\n\nfunc TestVerify(t any) { verifySig(\"a\", \"b\") }\n"


def _repo(tmp_path, *, functions, callers=(), sources=None, repo="svc", lang="go"):
    out, repos = tmp_path / "output", tmp_path / "repos"
    ctx = out / lang / repo / "context"
    ctx.mkdir(parents=True, exist_ok=True)
    with open(ctx / "functions.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_FUNC_COLS)
        w.writeheader()
        for r in functions:
            w.writerow({"param_count": "2", "is_static": "false", **r})
    with open(ctx / "callers.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=_CALLER_COLS)
        w.writeheader()
        for r in callers:
            w.writerow(r)
    src_root = repos / lang / repo
    src_root.mkdir(parents=True, exist_ok=True)
    for rel, text in (sources or {}).items():
        p = src_root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return ContextProvider(out, repos)


def _fn(name, file=_SIG, start=3, end=5):
    return {"name": name, "file": file, "start_line": str(start), "end_line": str(end)}


def _cr(caller, caller_file, callee="verifySig", callee_file=_SIG, s=10, e=20):
    return {
        "callee_name": callee, "callee_file": callee_file, "caller_name": caller,
        "caller_file": caller_file, "caller_start_line": str(s), "caller_end_line": str(e),
    }


def _finding(file=_SIG, lang="go", cwes=("CWE-208",)):
    return Finding(
        rule_id="go/timing-unsafe-comparison", message="timing", file=file,
        start_line=4, end_line=4, repo_name="svc", lang=lang, cwe_ids=list(cwes),
    )


def _gate(provider, finding, line=4):
    v = Verdict(
        finding=finding, verdict="True Positive", confidence="High",
        reasoning="secret compared with ==", answers=[], raw_response="{}", model="m",
        confidence_score=0.9,
    )
    return _downgrade_test_only_reachability(v, finding, provider, line)


# ---- the #162 core: dead function reached only from *_test.go ----

def test_eligible_test_only_downgrades_to_nmd(tmp_path):
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: _DECL, "internal/crypto/signature_test.go": _TEST_SRC},
    )
    v = _gate(p, _finding())
    assert v.verdict == "Needs More Data"
    assert v.decision_source == "reachability_gate"


def test_exported_target_downgrades(tmp_path):
    decl = "package crypto\n\nfunc VerifySig(a, b string) bool {\n\treturn a == b\n}\n"
    test = "package crypto\n\nfunc TestV(t any){ VerifySig(\"a\",\"b\") }\n"
    p = _repo(
        tmp_path,
        functions=[_fn("VerifySig")],
        callers=[_cr("TestV", "internal/crypto/sig_test.go", callee="VerifySig")],
        sources={_SIG: decl, "internal/crypto/sig_test.go": test},
    )
    assert _gate(p, _finding()).verdict == "Needs More Data"


# ---- unchanged (production reachability visible or unresolved) ----

def test_production_caller_row_11_unchanged(tmp_path):
    callers = [_cr(f"T{i}", f"internal/crypto/s{i}_test.go") for i in range(10)]
    callers.append(_cr("Prod", "internal/crypto/live.go"))  # 11th, non-test
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=callers,
        sources={_SIG: _DECL, "internal/crypto/live.go": "package crypto\n\nfunc L(){ verifySig(\"a\",\"b\") }\n"},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_handlefunc_registration_unchanged(tmp_path):
    reg = "package crypto\n\nfunc route(){ HandleFunc(\"/x\", verifySig) }\n"
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: _DECL, "internal/crypto/signature_test.go": _TEST_SRC, "internal/http/route.go": reg},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_same_line_decl_and_registration_unchanged(tmp_path):
    src = "package crypto\n\nfunc verifySig() { register(verifySig) }\n"
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig", start=3, end=3)],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: src, "internal/crypto/signature_test.go": _TEST_SRC},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_caller_in_tests_dir_not_test_basename_unchanged(tmp_path):
    # caller_file basename is foo.go (NOT *_test.go) -> not test-exclusive.
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=[_cr("Helper", "internal/tests/foo.go")],
        sources={_SIG: _DECL},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_zero_callers_unchanged(tmp_path):
    p = _repo(tmp_path, functions=[_fn("verifySig")], callers=[], sources={_SIG: _DECL})
    assert _gate(p, _finding()).verdict == "True Positive"


def test_repo_wide_homonym_unchanged(tmp_path):
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig"), _fn("verifySig", file="internal/legacy/old.go")],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: _DECL, "internal/legacy/old.go": _DECL},
    )
    assert _gate(p, _finding()).verdict == "True Positive"


def test_main_excluded_unchanged(tmp_path):
    decl = "package main\n\nfunc main() {\n\t_ = 1\n}\n"
    p = _repo(
        tmp_path,
        functions=[_fn("main", file="cmd/mockserver/main.go")],
        callers=[_cr("TestMain", "cmd/mockserver/main_test.go", callee="main", callee_file="cmd/mockserver/main.go")],
        sources={"cmd/mockserver/main.go": decl},
    )
    assert _gate(p, _finding(file="cmd/mockserver/main.go")).verdict == "True Positive"


# ---- neutrality: non-Go finding is never touched ----

def test_non_go_finding_unchanged(tmp_path):
    p = _repo(
        tmp_path,
        functions=[_fn("verifySig")],
        callers=[_cr("TestVerify", "internal/crypto/signature_test.go")],
        sources={_SIG: _DECL, "internal/crypto/signature_test.go": _TEST_SRC},
    )
    assert _gate(p, _finding(lang="php", cwes=("CWE-89",))).verdict == "True Positive"


# ---- projection soundness: abs/rel duplicate paths resolve to the same symbol ----

def test_path_normalization_is_stable(tmp_path):
    p = _repo(tmp_path, functions=[_fn("verifySig")], sources={_SIG: _DECL})
    a = p.resolve_repo_unique_enclosing_function("svc", "go", _SIG, 4)
    b = p.resolve_repo_unique_enclosing_function("svc", "go", "./" + _SIG, 4)
    assert a.symbol is not None and b.symbol is not None
    assert a.symbol.source_ref.file == b.symbol.source_ref.file == _SIG
