# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P2a — typed resolve_evidence + Protocol conformance for SnippetContextProvider."""

from __future__ import annotations

from vuln_hunter_x.context.evidence import (
    ContextProviderProtocol,
    EvidenceRequest,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
)
from vuln_hunter_x.context.snippet_provider import SnippetContextProvider

_SNIPPET = "\n".join(
    [
        "struct Point { int x; int y; };",
        "#define SZ 8",
        "void run() {",
        "  char* p = malloc(SZ);",
        "  free(p);",
        "}",
    ]
)


def _reqs(*raws: str):
    return [EvidenceRequest.parse(r) for r in raws]


class TestSnippetResolveEvidence:
    def test_in_snippet_found(self):
        p = SnippetContextProvider(_SNIPPET, "run")
        res = p.resolve_evidence("app", "cpp", _reqs("struct:Point"))["struct:Point"]
        assert res.status is EvidenceStatus.FOUND
        assert res.scope is EvidenceScope.SNIPPET

    def test_out_of_snippet_incomplete_not_repo_wide(self):
        p = SnippetContextProvider(_SNIPPET, "run")
        res = p.resolve_evidence("app", "cpp", _reqs("caller:run"))["caller:run"]
        # A snippet miss is incomplete at repository scope, never repo-wide absence.
        assert res.status is EvidenceStatus.INCOMPLETE_INDEX
        assert res.scope is EvidenceScope.SNIPPET

    def test_unknown_unsupported(self):
        p = SnippetContextProvider(_SNIPPET)
        assert p.resolve_evidence("app", "cpp", _reqs("bogus:z"))["bogus:z"].status is EvidenceStatus.UNSUPPORTED

    def test_source_ref_provenance(self):
        sr = SourceRef("app", "cpp", "a.cpp", 1, 6)
        p = SnippetContextProvider(_SNIPPET, "run", source_ref=sr)
        assert p.resolve_evidence("app", "cpp", _reqs("struct:Point"))["struct:Point"].provenance == (sr,)

    def test_prompt_content_matches_legacy_adapter(self):
        p = SnippetContextProvider(_SNIPPET, "run")
        raws = ["struct:Point", "macro:SZ", "free_sites:p", "caller:run", "bogus:z"]
        legacy = p.get_additional_context("app", "cpp", raws)
        typed = {k: r.prompt_content for k, r in p.resolve_evidence("app", "cpp", _reqs(*raws)).items()}
        assert typed == legacy


class TestProtocolConformance:
    def test_snippet_conforms(self):
        assert isinstance(SnippetContextProvider("x"), ContextProviderProtocol)
