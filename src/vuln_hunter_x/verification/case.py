# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Pre-analysis case identity for duplicate scanner findings (#122).

Verifying every scanner observation independently lets one canonical sink receive
opposite verdicts under duplicate observations, and invites post-hoc "reconcilers"
that either force genuinely-different security questions to agree or make a mistaken
verdict contagious. This module instead groups observations into ``VerificationCase``
objects BEFORE analysis: two observations share a case iff every semantic input is
identical — the same canonical sink assessed against the same obligation. Everything
else (a different rule, a different flow, a different construct on the same line) is a
distinct case that may legitimately differ. Pure, no IO, deterministic.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from vuln_hunter_x.context.anchor import (
    EXACT,
    LOCATED_UNVERIFIED,
    STRUCTURAL_NMD_RESOLUTIONS,
    AnchorResolution,
    _norm,  # canonical snippet whitespace-normalizer; identity must match anchoring
)
from vuln_hunter_x.core.types import Finding

# Resolutions whose reported columns are still valid discriminators. After
# re-anchoring, the reported columns point at the old (misaligned) line — the
# resolver matches the first non-blank snippet line and ignores columns — so they
# are dropped from identity; the exact snippet + resolved line discriminate.
_COLUMN_TRUSTWORTHY = frozenset({EXACT, LOCATED_UNVERIFIED})


def case_key(finding: Finding, anchor: AnchorResolution, *, norm_path: str):
    """The exact-duplicate case key, or ``None`` when the finding must never merge.

    ``None`` (→ its own singleton case) when the scanner emitted no construct to
    confirm (``sink_snippet`` empty) or the anchor could not be uniquely placed
    (ambiguous/absent — owned by the structural gate). Otherwise a tuple keyed on
    the canonical sink (repo-relative path + resolved analysis line + exact snippet
    + span) and the obligation (exact rule id). ``norm_path`` is the repo-relative
    path, injected so this module stays IO-free.
    """
    snippet = _norm(finding.sink_snippet)
    if not snippet:
        return None
    if anchor.resolution in STRUCTURAL_NMD_RESOLUTIONS:
        return None
    span = (
        (finding.start_column, finding.end_column)
        if anchor.resolution in _COLUMN_TRUSTWORTHY
        else None
    )
    return (
        finding.repo_name,
        finding.lang,
        norm_path,
        anchor.analysis_line,
        snippet,
        finding.rule_id,
        tuple(finding.dataflow_path),
        span,
    )


@dataclass
class VerificationCase:
    """One canonical case: which observation is verified, which it stands for."""

    representative_index: int
    observation_indices: list[int] = field(default_factory=list)
    case_id: str = ""


def build_cases(keys: list) -> list[VerificationCase]:
    """Group observation indices into cases by identical non-``None`` key.

    Order-stable: case order follows first appearance; the representative is the
    lowest original index. Each ``None`` key is its own singleton. ``case_id`` is a
    stable digest of the key for multi-observation cases (shared provenance) and
    ``""`` for singletons. Deterministic — no clock, no randomness.
    """
    groups: dict = {}
    cases: list[VerificationCase] = []
    for idx, key in enumerate(keys):
        if key is None:
            cases.append(VerificationCase(idx, [idx], ""))
            continue
        case = groups.get(key)
        if case is None:
            case = VerificationCase(idx, [idx], "")
            groups[key] = case
            cases.append(case)
        else:
            case.observation_indices.append(idx)
    for key, case in groups.items():
        if len(case.observation_indices) > 1:
            case.case_id = hashlib.sha1(repr(key).encode()).hexdigest()[:12]
    return cases
