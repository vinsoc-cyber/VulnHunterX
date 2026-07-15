# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Typed evidence contract for context retrieval (P2a).

Verdict-neutral in P2a: ``status``/``scope``/``exhaustive``/``provenance`` are
recorded but not consumed. ``prompt_content`` is the exact legacy string and is
the ONLY field that reaches the model; P2b consumes the structured fields,
never the prose.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol, runtime_checkable


class EvidenceStatus(Enum):
    FOUND = "found"
    NOT_FOUND_COMPLETE = "not_found_complete"
    AMBIGUOUS = "ambiguous"
    UNSUPPORTED = "unsupported"
    INCOMPLETE_INDEX = "incomplete_index"
    STALE_INDEX = "stale_index"  # no producer in P2a; reserved for P5


class EvidenceScope(Enum):
    SNIPPET = "snippet"
    FILE = "file"
    REPOSITORY_SOURCE = "repository_source"
    REPOSITORY_INDEX = "repository_index"


class EvidenceKind(Enum):
    CALLER = "caller"
    ALL_CALLERS = "all_callers"
    CALLEES = "callees"
    CALLEE_BODIES = "callee_bodies"
    FUNCTION = "function"
    STRUCT = "struct"
    GLOBAL = "global"
    MACRO = "macro"
    TYPEDEF = "typedef"
    ENUM = "enum"
    FREE_SITES = "free_sites"
    DESTRUCTOR = "destructor"
    FIELD_WRITES = "field_writes"
    FRAMEWORK_SANITIZERS = "framework_sanitizers"
    FRAMEWORK_GUARDS = "framework_guards"
    UNKNOWN = "unknown"


# Raw ctx_type token (lowercased/stripped) -> canonical kind. Mirrors the
# dispatch in ContextProvider.get_additional_context exactly.
_ALIASES: dict[str, EvidenceKind] = {
    "caller": EvidenceKind.CALLER,
    "all_callers": EvidenceKind.ALL_CALLERS,
    "callees": EvidenceKind.CALLEES,
    "callee_bodies": EvidenceKind.CALLEE_BODIES,
    "function": EvidenceKind.FUNCTION,
    "method": EvidenceKind.FUNCTION,
    "func": EvidenceKind.FUNCTION,
    "struct": EvidenceKind.STRUCT,
    "class": EvidenceKind.STRUCT,
    "classes": EvidenceKind.STRUCT,
    "global": EvidenceKind.GLOBAL,
    "macro": EvidenceKind.MACRO,
    "typedef": EvidenceKind.TYPEDEF,
    "enum": EvidenceKind.ENUM,
    "free_sites": EvidenceKind.FREE_SITES,
    "free_site": EvidenceKind.FREE_SITES,
    "destructor": EvidenceKind.DESTRUCTOR,
    "destructors": EvidenceKind.DESTRUCTOR,
    "field_writes": EvidenceKind.FIELD_WRITES,
    "field_write": EvidenceKind.FIELD_WRITES,
    "framework_sanitizers": EvidenceKind.FRAMEWORK_SANITIZERS,
    "framework_validation": EvidenceKind.FRAMEWORK_SANITIZERS,
    "framework_guards": EvidenceKind.FRAMEWORK_GUARDS,
    "framework_auth": EvidenceKind.FRAMEWORK_GUARDS,
}


@dataclass(frozen=True)
class SourceRef:
    repo: str
    lang: str
    file: str
    start: int
    end: int


@dataclass(frozen=True)
class SymbolRef:
    name: str
    kind: str
    source_ref: SourceRef | None = None


@dataclass(frozen=True)
class EvidenceRequest:
    kind: EvidenceKind
    subject: str
    raw_request: str

    @classmethod
    def parse(cls, raw: str) -> EvidenceRequest | None:
        """Parse a legacy ``"type:name"`` string.

        Returns ``None`` on a no-colon (malformed) request so each provider can
        preserve its own malformed policy (CSV drops; snippet emits an
        unavailable entry). ``subject`` is stripped; ``raw_request`` is kept
        verbatim because it is the downstream output-dict key.
        """
        if ":" not in raw:
            return None
        ctx_type, name = raw.split(":", 1)
        kind = _ALIASES.get(ctx_type.lower().strip(), EvidenceKind.UNKNOWN)
        return cls(kind=kind, subject=name.strip(), raw_request=raw)


@dataclass(frozen=True)
class EvidenceResult:
    request: EvidenceRequest
    status: EvidenceStatus
    prompt_content: str  # EXACT legacy string; opaque to P2b
    scope: EvidenceScope
    exhaustive: bool = True  # False when a result cap truncated the answer
    provenance: tuple[SourceRef | SymbolRef, ...] = ()
    detail: str = ""  # diagnostic only; never policy input


class ArtifactState(Enum):
    PRESENT = "present"
    MISSING = "missing"
    INVALID = "invalid"


@dataclass(frozen=True)
class Capability:
    kind: EvidenceKind
    lang: str
    supported: bool  # a producer exists for this kind + language
    artifact_state: ArtifactState  # for CSV-backed kinds (else PRESENT)
    scope: EvidenceScope
    authoritative_for_absence: bool  # may an exhaustive miss be NOT_FOUND_COMPLETE?


@runtime_checkable
class ContextProviderProtocol(Protocol):
    """Structural contract implemented by both context providers.

    ``resolve_evidence`` is the typed retrieval entrypoint; the legacy
    ``get_additional_context`` is the byte-for-byte string adapter over it.
    """

    def get_additional_context(
        self, repo_name: str, lang: str, context_requests: list[str]
    ) -> dict[str, str]: ...

    def resolve_evidence(
        self, repo_name: str, lang: str, requests: list[EvidenceRequest]
    ) -> dict[str, EvidenceResult]: ...

    def has_context_for_repo(self, repo_name: str, lang: str) -> bool: ...

    def clear_cache(self) -> None: ...
