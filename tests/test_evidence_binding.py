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

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceRequest,
    SourceRef,
    SymbolRef,
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
