# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Typed evidence contract for context retrieval (P2a).

Verdict-neutral in P2a: ``status``/``scope``/``exhaustive``/``provenance`` are
recorded but not consumed. ``prompt_content`` is the exact legacy string and is
the ONLY field that reaches the model; P2b consumes the structured fields,
never the prose.
"""

from __future__ import annotations

import csv
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
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
class SymbolResolution:
    """Result of resolving a (file, line) to its uniquely-named enclosing symbol.

    ``FOUND`` with a ``symbol`` only when the line lands in exactly one function
    whose name is unique repository-wide (the tree-sitter caller producer is
    homonym-fragile, so a repeated name cannot be bound to reliable caller
    evidence). Everything else fails closed with ``symbol=None`` (P5b).
    """

    status: EvidenceStatus
    symbol: SymbolRef | None = None
    detail: str = ""


@dataclass(frozen=True)
class CallerRef:
    """One recorded caller of a target symbol (name + where it calls from)."""

    name: str
    source_ref: SourceRef


@dataclass(frozen=True)
class RecordedCallersResult:
    """Unbounded, file-qualified enumeration of a target's recorded callers (P5b).

    ``enumerated_all_rows`` distinguishes 'complete over recorded rows' (the
    achievable completeness the reachability gate requires) from the capped
    prompt-facing ``_resolve_all_callers``. An empty-but-valid result is
    ``INCOMPLETE_INDEX`` with ``enumerated_all_rows=True`` (no recorded caller —
    could be an entrypoint or a missing index; the gate must not fire). Ambiguity
    or a malformed/escaping row → a non-FOUND status with
    ``enumerated_all_rows=False``.
    """

    status: EvidenceStatus
    target: SymbolRef
    callers: tuple[CallerRef, ...] = ()
    enumerated_all_rows: bool = False
    detail: str = ""


@dataclass(frozen=True)
class EvidenceRequest:
    kind: EvidenceKind
    subject: str
    raw_request: str
    # Optional exact symbol this request targets. ``None`` (the legacy default)
    # means name-only retrieval, byte-for-byte as before. When set for a caller
    # kind, retrieval is disambiguated to that symbol's file (see the provider).
    target: SymbolRef | None = None

    @property
    def request_key(self) -> str:
        """Retrieval identity. Equals ``raw_request`` for an unqualified request,
        so two qualified requests sharing a ``raw_request`` (e.g. callers of a
        homonym in different files) do not collide in the result mapping."""
        if self.target is None:
            return self.raw_request
        file = self.target.source_ref.file if self.target.source_ref else ""
        return f"{self.raw_request}\x00{file}#{self.target.name}"

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


# --- Capability matrix -----------------------------------------------------
# Kinds the toolchain extracts ONLY for the C family (c/cpp): CodeQL emits these
# queries under config/queries/tools/cpp, and tree-sitter's QUERIES_BY_LANG lists
# structs/globals/macros for c/cpp only. FUNCTION, STRUCT, and the call-graph
# kinds are extracted for every supported language.
_C_FAMILY_LANGS = frozenset({"c", "cpp"})
_C_ONLY_KINDS = frozenset(
    {
        EvidenceKind.GLOBAL,
        EvidenceKind.MACRO,
        EvidenceKind.TYPEDEF,
        EvidenceKind.ENUM,
        EvidenceKind.FREE_SITES,
        EvidenceKind.DESTRUCTOR,
        EvidenceKind.FIELD_WRITES,
    }
)
_FRAMEWORK_KINDS = frozenset(
    {EvidenceKind.FRAMEWORK_SANITIZERS, EvidenceKind.FRAMEWORK_GUARDS}
)

# Primary CSV basename backing each CSV-based kind. STRUCT is language-aware
# (see _kind_csv_name); framework/unknown kinds have no CSV.
_CSV_FOR_KIND: dict[EvidenceKind, str] = {
    EvidenceKind.CALLER: "callers",
    EvidenceKind.ALL_CALLERS: "callers",
    EvidenceKind.CALLEES: "callers",
    EvidenceKind.CALLEE_BODIES: "callers",
    EvidenceKind.FUNCTION: "functions",
    EvidenceKind.GLOBAL: "globals",
    EvidenceKind.MACRO: "macros",
    EvidenceKind.TYPEDEF: "typedefs",
    EvidenceKind.ENUM: "enums",
    EvidenceKind.FREE_SITES: "free_sites",
    EvidenceKind.DESTRUCTOR: "destructors",
    EvidenceKind.FIELD_WRITES: "field_writes",
}


def _kind_csv_name(kind: EvidenceKind, lang: str) -> str | None:
    """Primary CSV a handler reads for this kind+lang, or None if not CSV-backed."""
    if kind is EvidenceKind.STRUCT:
        # Mirrors ContextProvider._get_struct_context.
        return "classes" if lang in ("python", "javascript", "csharp") else "structs"
    return _CSV_FOR_KIND.get(kind)


def authoritative_for_absence(kind: EvidenceKind) -> bool:
    """Whether an exhaustive miss of this kind may be reported NOT_FOUND_COMPLETE.

    Framework markers are grep-based and complete under their bounds, so their
    absence is a real answer. Symbol and call-graph indexes are not authoritative:
    a lookup that misses there is INCOMPLETE_INDEX, never a proof of absence.

    Static — a property of the producers, not of any repo's artifact state. Both
    the runtime status mapping (``inspect_capability`` -> ``_absence_status``) and
    the policy layer's static emit space read this one rule, so the shapes the
    toolchain can emit and the shapes a policy may rely on cannot drift apart.
    """
    return kind in _FRAMEWORK_KINDS


def _supported(kind: EvidenceKind, lang: str) -> bool:
    """Whether the toolchain has any producer for this kind+language."""
    if kind in _FRAMEWORK_KINDS:
        return True  # grep-based; no index required
    if kind is EvidenceKind.UNKNOWN:
        return False
    if kind in _C_ONLY_KINDS:
        return lang in _C_FAMILY_LANGS
    return True  # FUNCTION, STRUCT, and the call-graph kinds are universal


def _artifact_state(context_dir: Path, csv_name: str) -> ArtifactState:
    path = context_dir / f"{csv_name}.csv"
    if not path.is_file():
        return ArtifactState.MISSING
    try:
        with open(path, newline="", encoding="utf-8") as f:
            next(csv.reader(f), None)  # touch header; catches unreadable/undecodable
        return ArtifactState.PRESENT
    except (OSError, UnicodeDecodeError, csv.Error):
        return ArtifactState.INVALID


def inspect_capability(context_dir: Path, lang: str, kind: EvidenceKind) -> Capability:
    """Describe what the toolchain can answer for (kind, lang) at this repo.

    Pure over ``context_dir`` (the repo's ``output/<lang>/<repo>/context`` dir).
    Distinguishes 'no producer for this kind+lang' (drives UNSUPPORTED) from
    'expected but the index is missing/invalid' (drives INCOMPLETE_INDEX).
    """
    csv_name = _kind_csv_name(kind, lang)
    artifact = (
        ArtifactState.PRESENT
        if csv_name is None
        else _artifact_state(context_dir, csv_name)
    )
    return Capability(
        kind=kind,
        lang=lang,
        supported=_supported(kind, lang),
        artifact_state=artifact,
        scope=(
            EvidenceScope.REPOSITORY_SOURCE
            if kind in _FRAMEWORK_KINDS
            else EvidenceScope.REPOSITORY_INDEX
        ),
        authoritative_for_absence=authoritative_for_absence(kind),
    )


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
