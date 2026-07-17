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
* ``LOCAL_OR_EXHAUSTIVE`` — all-path coverage proven in the local slice (the full
  construction is visible) or by an exhaustive retrieval.
* ``COMPLETE_REPO_ABSENCE`` — a repository-scoped, non-framework ``NOT_FOUND_COMPLETE``.
* ``ANY_CITATION`` — any citation (informational slots only).

A non-exhaustive ``FOUND`` cannot establish full coverage; a framework-marker
result is never valid encoder evidence; a snippet-scoped / ``INCOMPLETE_INDEX`` /
``AMBIGUOUS`` absence never establishes complete absence. No prose is read here;
only the typed ledger fields.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from itertools import product

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceScope,
    EvidenceStatus,
    authoritative_for_absence,
)
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
    "LOCAL_OR_EXHAUSTIVE": lambda cited: any(
        _is_local(e) or _exhaustive_found_encoder(e) for e in cited
    ),
    "COMPLETE_REPO_ABSENCE": lambda cited: any(_complete_repo_absence(e) for e in cited),
    "ANY_CITATION": lambda cited: bool(cited),
}

PROFILE_NAMES = frozenset(_PROFILES)

# Profiles whose predicate is defensible but whose *semantics* are not trustworthy
# yet, and which are therefore never selectable from a policy — regardless of what
# the producers can emit. Satisfiability is not semantic correctness, so promotion
# must be a reviewed decision, not a side effect of some unrelated producer gaining
# authority for absence.
#
# COMPLETE_REPO_ABSENCE: counts FILE scope as repository scope and encodes no search
# domain, so a complete miss for `function:encodeForLog` would prove only that one
# symbol absent — not that no effective neutralizer exists anywhere.
DORMANT_PROFILES = frozenset({"COMPLETE_REPO_ABSENCE"})


def producible_witnesses() -> tuple[EvidenceEntry, ...]:
    """One witness per evidence shape the producers can ever emit.

    Static: a property of the producers, not of a repo's artifact state (whether a
    given index happens to be present is runtime readiness, and linting against it
    would let a policy load in one checkout and fail in another).

    Deliberately an OVER-approximation — any constraint not modelled here admits
    more shapes, never fewer. So a profile this proves unsatisfiable is *provably*
    dead, and a working family can never be rejected by mistake. The converse does
    not hold: a merely impractical profile still looks satisfiable here.
    """
    witnesses = [
        EvidenceEntry(id="L", origin=EvidenceOrigin.LOCAL_SLICE, summary=""),
        EvidenceEntry(id="D", origin=EvidenceOrigin.SCANNER_DATAFLOW, summary=""),
    ]
    for kind, status, scope, exhaustive in product(
        EvidenceKind, EvidenceStatus, EvidenceScope, (True, False)
    ):
        if status is EvidenceStatus.NOT_FOUND_COMPLETE and not authoritative_for_absence(kind):
            continue  # provider._absence_status can never report this pairing
        witnesses.append(
            EvidenceEntry(
                id="R",
                origin=EvidenceOrigin.RETRIEVED,
                summary="",
                status=status,
                scope=scope,
                exhaustive=exhaustive,
                kind=kind,
            )
        )
    return tuple(witnesses)


def is_profile_satisfiable(profile: str) -> bool:
    """Whether any evidence the toolchain can produce would admit ``profile``.

    Single-entry witnesses are enough because every profile is an ``any(...)`` over
    the cited entries. A future profile needing several entries at once would need a
    bundle here; it would read as unsatisfiable rather than pass unchecked.
    """
    predicate = _PROFILES.get(profile)
    return predicate is not None and any(predicate([w]) for w in producible_witnesses())


# The profiles a policy may declare: satisfiable by real evidence, and not dormant.
SELECTABLE_PROFILES = frozenset(
    name
    for name in _PROFILES
    if name not in DORMANT_PROFILES and is_profile_satisfiable(name)
)


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
