# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""The per-sample evidence ledger.

Holds every piece of evidence a sample may cite, under a stable ID: the primary
code slice (``L#``), the scanner dataflow (``D#``), and retrieved typed results
(``R#``). Retrieved entries carry the P2a ``EvidenceResult`` typed fields
(status/scope/exhaustive/kind) so the support layer can judge admissibility
without ever reading the prose ``prompt_content``.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
    SymbolRef,
)


class EvidenceOrigin(Enum):
    LOCAL_SLICE = "local_slice"
    SCANNER_DATAFLOW = "scanner_dataflow"
    RETRIEVED = "retrieved"


@dataclass(frozen=True)
class EvidenceEntry:
    """One citable item. Retrieved-only fields are ``None`` for seed entries."""

    id: str
    origin: EvidenceOrigin
    summary: str
    source_ref: SourceRef | None = None
    status: EvidenceStatus | None = None
    scope: EvidenceScope | None = None
    exhaustive: bool | None = None
    kind: EvidenceKind | None = None
    # P5a binding envelope (preserved, not yet enforced — a P5b consumer reads it):
    # the obligation slots this retrieval was requested for, the queried symbol,
    # and the full provenance of the returned evidence.
    requested_for_slots: frozenset[str] = frozenset()
    target: SymbolRef | None = None
    provenance: tuple[SourceRef | SymbolRef, ...] = ()


class EvidenceLedger:
    """Append-only ledger with per-origin stable IDs (L#, D#, R#)."""

    _PREFIX = {
        EvidenceOrigin.LOCAL_SLICE: "L",
        EvidenceOrigin.SCANNER_DATAFLOW: "D",
        EvidenceOrigin.RETRIEVED: "R",
    }

    def __init__(self) -> None:
        self._entries: list[EvidenceEntry] = []
        self._counts: dict[EvidenceOrigin, int] = {o: 0 for o in EvidenceOrigin}

    def _next_id(self, origin: EvidenceOrigin) -> str:
        self._counts[origin] += 1
        return f"{self._PREFIX[origin]}{self._counts[origin]}"

    def add_local_slice(self, source_ref: SourceRef, summary: str) -> EvidenceEntry:
        entry = EvidenceEntry(
            id=self._next_id(EvidenceOrigin.LOCAL_SLICE),
            origin=EvidenceOrigin.LOCAL_SLICE,
            summary=summary,
            source_ref=source_ref,
        )
        self._entries.append(entry)
        return entry

    def add_scanner_dataflow(self, summary: str) -> EvidenceEntry:
        entry = EvidenceEntry(
            id=self._next_id(EvidenceOrigin.SCANNER_DATAFLOW),
            origin=EvidenceOrigin.SCANNER_DATAFLOW,
            summary=summary,
        )
        self._entries.append(entry)
        return entry

    def add_retrieved(
        self, result: EvidenceResult, requested_for: frozenset[str] = frozenset()
    ) -> EvidenceEntry:
        entry = EvidenceEntry(
            id=self._next_id(EvidenceOrigin.RETRIEVED),
            origin=EvidenceOrigin.RETRIEVED,
            summary=result.request.raw_request,
            status=result.status,
            scope=result.scope,
            exhaustive=result.exhaustive,
            kind=result.request.kind,
            requested_for_slots=requested_for,
            target=result.request.target,
            provenance=result.provenance,
        )
        self._entries.append(entry)
        return entry

    @property
    def entries(self) -> list[EvidenceEntry]:
        return list(self._entries)

    def get(self, entry_id: str) -> EvidenceEntry | None:
        return next((e for e in self._entries if e.id == entry_id), None)

    def has(self, entry_id: str) -> bool:
        return self.get(entry_id) is not None
