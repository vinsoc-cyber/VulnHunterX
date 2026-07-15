# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P2a — typed evidence contract: request parser, dataclasses, Protocol."""

from __future__ import annotations

from vuln_hunter_x.context.evidence import (
    ContextProviderProtocol,
    EvidenceKind,
    EvidenceRequest,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
    SymbolRef,
)
from vuln_hunter_x.context.snippet_provider import SnippetContextProvider


class TestEvidenceRequestParse:
    def test_basic(self):
        req = EvidenceRequest.parse("caller:foo")
        assert req is not None
        assert req.kind is EvidenceKind.CALLER
        assert req.subject == "foo"
        assert req.raw_request == "caller:foo"

    def test_aliases(self):
        assert EvidenceRequest.parse("method:x").kind is EvidenceKind.FUNCTION
        assert EvidenceRequest.parse("func:x").kind is EvidenceKind.FUNCTION
        assert EvidenceRequest.parse("classes:X").kind is EvidenceKind.STRUCT
        assert EvidenceRequest.parse("class:X").kind is EvidenceKind.STRUCT
        assert (
            EvidenceRequest.parse("framework_validation:*").kind
            is EvidenceKind.FRAMEWORK_SANITIZERS
        )
        assert (
            EvidenceRequest.parse("framework_auth:*").kind
            is EvidenceKind.FRAMEWORK_GUARDS
        )
        assert EvidenceRequest.parse("free_site:p").kind is EvidenceKind.FREE_SITES
        assert EvidenceRequest.parse("field_write:T.f").kind is EvidenceKind.FIELD_WRITES
        assert EvidenceRequest.parse("destructors:T").kind is EvidenceKind.DESTRUCTOR

    def test_unknown_type(self):
        req = EvidenceRequest.parse("bogus:z")
        assert req.kind is EvidenceKind.UNKNOWN
        assert req.subject == "z"
        assert req.raw_request == "bogus:z"

    def test_malformed_no_colon_returns_none(self):
        assert EvidenceRequest.parse("noColonHere") is None

    def test_whitespace_subject_trimmed_raw_preserved(self):
        req = EvidenceRequest.parse("function:  a.b  ")
        assert req.subject == "a.b"
        # raw_request is preserved verbatim (it is the output dict key downstream)
        assert req.raw_request == "function:  a.b  "

    def test_type_token_case_insensitive(self):
        assert EvidenceRequest.parse("CALLER:foo").kind is EvidenceKind.CALLER
        # raw_request keeps original casing
        assert EvidenceRequest.parse("CALLER:foo").raw_request == "CALLER:foo"

    def test_colon_in_subject_kept(self):
        req = EvidenceRequest.parse("global:ns::var")
        assert req.kind is EvidenceKind.GLOBAL
        assert req.subject == "ns::var"


class TestEvidenceResultDefaults:
    def test_defaults(self):
        req = EvidenceRequest.parse("function:x")
        res = EvidenceResult(
            request=req,
            status=EvidenceStatus.FOUND,
            prompt_content="code",
            scope=EvidenceScope.FILE,
        )
        assert res.exhaustive is True
        assert res.provenance == ()
        assert res.detail == ""

    def test_provenance_refs(self):
        sr = SourceRef(repo="r", lang="python", file="a.py", start=1, end=9)
        sym = SymbolRef(name="f", kind="function", source_ref=sr)
        req = EvidenceRequest.parse("function:f")
        res = EvidenceResult(
            request=req,
            status=EvidenceStatus.FOUND,
            prompt_content="code",
            scope=EvidenceScope.FILE,
            exhaustive=False,
            provenance=(sym,),
        )
        assert res.exhaustive is False
        assert res.provenance[0].source_ref.file == "a.py"


class TestProtocol:
    def test_runtime_checkable(self):
        # Snippet provider does NOT yet implement resolve_evidence (added in Task 6),
        # so it must NOT satisfy the Protocol at this phase.
        assert not isinstance(SnippetContextProvider("x"), ContextProviderProtocol)
