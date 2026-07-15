# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Per-slot-VALUE evidence admissibility for the log-injection family.

A claimed ``(slot, value)`` is admissible only when the cited ledger entries
carry evidence of the right *shape* for that specific value — encoded per value,
not per polarity. Key rules (from the converged design):

* ``neutralization_coverage``
  - ``ALL_REACHING_PATHS`` needs an exhaustive ``FOUND`` encoder result (a
    non-exhaustive ``FOUND`` cannot establish full coverage), and a
    framework-marker result is never valid encoder evidence.
  - ``NONE_FOUND_COMPLETE`` needs a repository-scoped ``NOT_FOUND_COMPLETE``
    (snippet-scoped / ``INCOMPLETE_INDEX`` / ``AMBIGUOUS`` leaves it unresolved).
  - ``BYPASS_PATH_FOUND`` needs a concrete path (local slice, scanner dataflow,
    or a positive ``FOUND`` retrieval) — never a mere absence result.
* Proven-safe negatives (``attacker_control=REFUTED``,
  ``record_boundary=PRESERVED``) are provable positively from the local slice.

No prose is read here; only the typed ledger fields.
"""

from __future__ import annotations

from collections.abc import Sequence

from vuln_hunter_x.context.evidence import EvidenceKind, EvidenceScope, EvidenceStatus
from vuln_hunter_x.verification.policy.ledger import EvidenceEntry, EvidenceOrigin

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


def _concrete_path(e: EvidenceEntry) -> bool:
    return (
        _is_local(e)
        or _is_dataflow(e)
        or (_is_retrieved(e) and e.status is EvidenceStatus.FOUND)
    )


def is_admissible(slot: str, value: str, cited: Sequence[EvidenceEntry]) -> bool:
    """Whether ``cited`` admissibly supports the claim ``slot == value``."""
    if not cited:
        return False

    if slot == "neutralization_coverage":
        if value == "ALL_REACHING_PATHS":
            return any(_exhaustive_found_encoder(e) for e in cited)
        if value == "NONE_FOUND_COMPLETE":
            return any(_complete_repo_absence(e) for e in cited)
        if value == "BYPASS_PATH_FOUND":
            return any(_concrete_path(e) for e in cited)
        return False

    if slot == "attacker_control":
        if value == "PROVEN":
            return any(_is_dataflow(e) or _is_local(e) for e in cited)
        if value == "REFUTED":
            return any(_is_local(e) for e in cited)
        return False

    if slot == "flow_to_sink":
        if value == "REACHES":
            return any(_is_dataflow(e) or _is_local(e) for e in cited)
        if value == "NO_PATH_COMPLETE":
            return any(_is_local(e) or _complete_repo_absence(e) for e in cited)
        return False

    if slot == "record_boundary":
        return any(
            _is_local(e) or (_is_retrieved(e) and e.status is EvidenceStatus.FOUND)
            for e in cited
        )

    if slot == "sink_binding":
        return any(_is_local(e) for e in cited)

    # production_scope is informational until P5 — any citation is accepted (never
    # decisive); any other slot is unknown to this family and not admissible.
    return slot == "production_scope"
