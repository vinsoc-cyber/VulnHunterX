# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Per-slot-VALUE evidence admissibility — declarative, family-generic.

A claimed ``(slot, value)`` is admissible only when the cited ledger entries
carry evidence of the right *shape*. The shapes are a fixed named set of
**profiles** (encoded here); each family policy declares, per ``(slot, value)``,
which profile the citation must satisfy (``policy.admissibility``). Dispatch is
by profile, not by slot name, so a new family's slots become admissible by
declaring profiles — with no code branch here. A ``(slot, value)`` with no
declared profile fails closed (inadmissible).

Profiles (evidence-shape predicates over the cited ledger entries):

* ``LOCAL_POSITIVE`` — a property proven positively from the local slice.
* ``LOCAL_OR_DATAFLOW`` — local slice or the scanner dataflow (a concrete relation).
* ``LOCAL_OR_COMPLETE_ABSENCE`` — local proof, or a correctly-scoped complete absence.
* ``LOCAL_OR_FOUND`` — local slice or a positive retrieval.
* ``CONCRETE_PATH`` — a witnessed path: local slice, scanner dataflow, or a positive retrieval.
* ``EXHAUSTIVE_ENCODER`` — a retrieved, exhaustive, non-framework ``FOUND`` (coverage over all paths).
* ``COMPLETE_REPO_ABSENCE`` — a repository-scoped, non-framework ``NOT_FOUND_COMPLETE``.
* ``ANY_CITATION`` — any citation (informational slots only).

A non-exhaustive ``FOUND`` cannot establish full coverage; a framework-marker
result is never valid encoder evidence; a snippet-scoped / ``INCOMPLETE_INDEX`` /
``AMBIGUOUS`` absence never establishes complete absence. No prose is read here;
only the typed ledger fields.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence

from vuln_hunter_x.context.evidence import EvidenceKind, EvidenceScope, EvidenceStatus
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin
from vuln_hunter_x.verification.policy.models import FamilyPolicy

_FRAMEWORK_KINDS = frozenset(
    {EvidenceKind.FRAMEWORK_SANITIZERS, EvidenceKind.FRAMEWORK_GUARDS}
)
_REPO_SCOPES = frozenset(
    {EvidenceScope.FILE, EvidenceScope.REPOSITORY_SOURCE, EvidenceScope.REPOSITORY_INDEX}
)


def _is_local(e: EvidenceEntry) -> bool:
    return e.origin is EvidenceOrigin.LOCAL_SLICE


def _is_dataflow(e: EvidenceEntry) -> bool:
    return e.origin is EvidenceOrigin.SCANNER_DATAFLOW


def _is_retrieved(e: EvidenceEntry) -> bool:
    return e.origin is EvidenceOrigin.RETRIEVED


def _is_found(e: EvidenceEntry) -> bool:
    return _is_retrieved(e) and e.status is EvidenceStatus.FOUND


def _exhaustive_found_encoder(e: EvidenceEntry) -> bool:
    return (
        _is_retrieved(e)
        and e.status is EvidenceStatus.FOUND
        and e.exhaustive is True
        and e.kind not in _FRAMEWORK_KINDS
    )


def _complete_repo_absence(e: EvidenceEntry) -> bool:
    return (
        _is_retrieved(e)
        and e.status is EvidenceStatus.NOT_FOUND_COMPLETE
        and e.scope in _REPO_SCOPES
        and e.kind not in _FRAMEWORK_KINDS
    )


_PROFILES: dict[str, Callable[[Sequence[EvidenceEntry]], bool]] = {
    "LOCAL_POSITIVE": lambda cited: any(_is_local(e) for e in cited),
    "LOCAL_OR_DATAFLOW": lambda cited: any(_is_local(e) or _is_dataflow(e) for e in cited),
    "LOCAL_OR_COMPLETE_ABSENCE": lambda cited: any(
        _is_local(e) or _complete_repo_absence(e) for e in cited
    ),
    "LOCAL_OR_FOUND": lambda cited: any(_is_local(e) or _is_found(e) for e in cited),
    "CONCRETE_PATH": lambda cited: any(
        _is_local(e) or _is_dataflow(e) or _is_found(e) for e in cited
    ),
    "EXHAUSTIVE_ENCODER": lambda cited: any(_exhaustive_found_encoder(e) for e in cited),
    "COMPLETE_REPO_ABSENCE": lambda cited: any(_complete_repo_absence(e) for e in cited),
    "ANY_CITATION": lambda cited: bool(cited),
}

PROFILE_NAMES = frozenset(_PROFILES)


def is_admissible(
    policy: FamilyPolicy, slot: str, value: str, cited: Sequence[EvidenceEntry]
) -> bool:
    """Whether ``cited`` admissibly supports ``slot == value`` under ``policy``.

    Fails closed: no citations, or a ``(slot, value)`` with no declared profile,
    is never admissible.
    """
    if not cited:
        return False
    profile = policy.admissibility.get(slot, {}).get(value)
    predicate = _PROFILES.get(profile) if profile else None
    return predicate is not None and predicate(cited)
