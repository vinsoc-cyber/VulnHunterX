# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P5a evidence binding envelope.

Retrieved evidence must carry the metadata it currently drops: the exact symbol
a request targets (so homonyms in different files are not merged), a
target-aware request key (so two qualified requests with the same ``raw_request``
do not collide), and — downstream — its full provenance and the obligation slots
it was requested for. This suite is verdict-neutral: every unqualified request
(``target=None``) behaves byte-for-byte as before; only new qualified requests
exercise the new branches.
"""

from __future__ import annotations

import csv as _csv

import pytest

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceRequest,
    EvidenceStatus,
    SourceRef,
    SymbolRef,
)
from vuln_hunter_x.context.provider import ContextProvider

# A self-contained repo modelled on insecure-coding's real homonym shape: the
# name `isSafe` is defined in two files (there it spans 8), each called by a
# local `main`; `dup` is defined twice in one file (a real same-file overload,
# like `operator+` in prefer_typesafe_literals.cpp) to exercise ambiguity.
_FUNCTIONS = [
    ("isSafe", "a.c", "5", "7", "1", "0"),
    ("isSafe", "b.c", "5", "7", "1", "0"),
    ("mainA", "a.c", "1", "3", "0", "0"),
    ("mainB", "b.c", "1", "3", "0", "0"),
    ("dup", "dup.c", "1", "2", "0", "0"),
    ("dup", "dup.c", "4", "5", "0", "0"),  # same (name,file) twice -> AMBIGUOUS
]
_CALLERS = [
    ("isSafe", "a.c", "mainA", "a.c", "1", "3"),
    ("isSafe", "b.c", "mainB", "b.c", "1", "3"),
    ("dup", "dup.c", "userDup", "dup.c", "1", "2"),
]


def _write_csv(path, header, rows):
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = _csv.writer(f)
        w.writerow(header)
        w.writerows(rows)


@pytest.fixture
def qual_provider(tmp_path):
    out = tmp_path / "out"
    repos = tmp_path / "repos"
    ctx = out / "cpp" / "testrepo" / "context"
    ctx.mkdir(parents=True)
    _write_csv(
        ctx / "functions.csv",
        ["name", "file", "start_line", "end_line", "param_count", "is_static"],
        _FUNCTIONS,
    )
    _write_csv(
        ctx / "callers.csv",
        ["callee_name", "callee_file", "caller_name", "caller_file",
         "caller_start_line", "caller_end_line"],
        _CALLERS,
    )
    src = repos / "cpp" / "testrepo"
    src.mkdir(parents=True)
    (src / "a.c").write_text("void mainA(){AAA}\n// l2\n// l3\nint isSafe(){}\n")
    (src / "b.c").write_text("void mainB(){BBB}\n// l2\n// l3\nint isSafe(){}\n")
    (src / "dup.c").write_text("void dup1(){}\n// l2\n// l3\nvoid dup2(){}\n")
    return ContextProvider(out, repos)


def _qualified(name, file):
    return EvidenceRequest(
        EvidenceKind.ALL_CALLERS, name, f"all_callers:{name}",
        target=SymbolRef(name, "function", SourceRef("testrepo", "cpp", file, 1, 2)),
    )


def _all_callers(target: SymbolRef | None = None) -> EvidenceRequest:
    return EvidenceRequest(
        EvidenceKind.ALL_CALLERS, "isSafe", "all_callers:isSafe", target=target
    )


def _sym(file: str) -> SymbolRef:
    return SymbolRef("isSafe", "function", SourceRef("r", "cpp", file, 1, 2))


def test_request_key_is_raw_request_when_unqualified():
    assert _all_callers().request_key == "all_callers:isSafe"


def test_request_key_discriminates_by_target_file():
    a = _all_callers(_sym("a.c"))
    b = _all_callers(_sym("b.c"))
    assert a.request_key != b.request_key
    assert a.request_key.startswith("all_callers:isSafe")


def test_request_key_tolerates_target_without_source_ref():
    r = _all_callers(SymbolRef("isSafe", "function", None))
    assert r.request_key.startswith("all_callers:isSafe")


def test_target_defaults_none_and_is_backward_compatible():
    r = EvidenceRequest(EvidenceKind.CALLER, "foo", "caller:foo")
    assert r.target is None
    assert r.request_key == "caller:foo"


# ---- Task 2: resolve_evidence keys on request_key (no collision) ----

def test_resolve_evidence_no_collision_between_targets(qual_provider):
    a = _qualified("isSafe", "a.c")
    b = _qualified("isSafe", "b.c")  # same raw_request "all_callers:isSafe"
    res = qual_provider.resolve_evidence("testrepo", "cpp", [a, b])
    assert set(res) == {a.request_key, b.request_key}
    assert a.request_key != b.request_key


def test_resolve_evidence_unqualified_key_is_raw_request(qual_provider):
    r = EvidenceRequest(EvidenceKind.ALL_CALLERS, "isSafe", "all_callers:isSafe")
    res = qual_provider.resolve_evidence("testrepo", "cpp", [r])
    assert set(res) == {"all_callers:isSafe"}


# ---- Task 3: file-qualified caller resolver (opt-in; ambiguity fails closed) ----

def test_qualified_callers_distinct_by_file(qual_provider):
    a = _qualified("isSafe", "a.c")
    b = _qualified("isSafe", "b.c")
    res = qual_provider.resolve_evidence("testrepo", "cpp", [a, b])
    ra, rb = res[a.request_key], res[b.request_key]
    assert ra.status is EvidenceStatus.FOUND and rb.status is EvidenceStatus.FOUND
    assert "AAA" in ra.prompt_content and "BBB" not in ra.prompt_content
    assert "BBB" in rb.prompt_content and "AAA" not in rb.prompt_content


def test_qualified_ambiguous_same_name_same_file(qual_provider):
    r = _qualified("dup", "dup.c")  # defined twice in dup.c
    out = qual_provider.resolve_evidence("testrepo", "cpp", [r])[r.request_key]
    assert out.status is EvidenceStatus.AMBIGUOUS


def test_qualified_miss_does_not_fall_back(qual_provider):
    r = _qualified("isSafe", "nonexistent.c")
    out = qual_provider.resolve_evidence("testrepo", "cpp", [r])[r.request_key]
    assert out.status is EvidenceStatus.INCOMPLETE_INDEX
    assert "AAA" not in out.prompt_content and "BBB" not in out.prompt_content


def test_name_only_still_merges_homonyms(qual_provider):
    r = EvidenceRequest(EvidenceKind.ALL_CALLERS, "isSafe", "all_callers:isSafe")
    out = qual_provider.resolve_evidence("testrepo", "cpp", [r])[r.request_key]
    assert out.status is EvidenceStatus.FOUND
    assert "AAA" in out.prompt_content and "BBB" in out.prompt_content  # merge unchanged


def test_qualified_single_caller_resolver(qual_provider):
    r = EvidenceRequest(
        EvidenceKind.CALLER, "isSafe", "caller:isSafe",
        target=SymbolRef("isSafe", "function", SourceRef("testrepo", "cpp", "b.c", 1, 2)),
    )
    out = qual_provider.resolve_evidence("testrepo", "cpp", [r])[r.request_key]
    assert out.status is EvidenceStatus.FOUND
    assert "BBB" in out.prompt_content and "AAA" not in out.prompt_content
