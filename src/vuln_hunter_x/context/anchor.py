# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic sink-anchor resolution (#118).

The scanner reports a finding at ``(file, start_line)`` and, when available, the
source text of the flagged construct (``Finding.sink_snippet``). If the verifier
reasons over a slice where that line means something else, it wrongly concludes
the construct "isn't there" and dismisses a real bug. This module confirms the
reported line, re-aligns to the construct's unique real location, or reports that
it cannot be uniquely placed — deterministically, with no IO and no model.
"""

from __future__ import annotations

from dataclasses import dataclass

from vuln_hunter_x.core.types import Finding

EXACT = "exact"
REANCHORED_UNIQUE = "reanchored_unique"
LOCATED_UNVERIFIED = "located_unverified"
AMBIGUOUS = "ambiguous"
ABSENT = "absent"

# Resolutions meaning "the reported construct could not be uniquely placed in the
# source": the finding must not be dismissed on a misaligned slice — it needs a
# correct anchor, i.e. a structural Needs-More-Data (never a False Positive).
STRUCTURAL_NMD_RESOLUTIONS = frozenset({AMBIGUOUS, ABSENT})


@dataclass(frozen=True)
class AnchorResolution:
    reported_line: int
    analysis_line: int
    resolution: str
    detail: str = ""


def _norm(text: str) -> str:
    return " ".join(text.split())


def _snippet_key(snippet: str) -> str:
    for line in snippet.splitlines():
        if line.strip():
            return _norm(line)
    return _norm(snippet)


def resolve_anchor(finding: Finding, file_text: str | None) -> AnchorResolution:
    """Resolve where the flagged construct actually lives in ``file_text``.

    ``file_text`` is the full source of ``finding.file`` at the scanned revision,
    or ``None`` if unreadable. Returns a resolution whose ``analysis_line`` is the
    line the verifier should extract context around (== reported unless
    re-anchored). Snippet-less or source-less findings resolve to
    ``located_unverified`` — the unchanged legacy behaviour.
    """
    reported = finding.start_line
    snippet = (finding.sink_snippet or "").strip()
    if not snippet or file_text is None:
        return AnchorResolution(reported, reported, LOCATED_UNVERIFIED)

    key = _snippet_key(snippet)
    if not key:
        return AnchorResolution(reported, reported, LOCATED_UNVERIFIED)

    lines = file_text.splitlines()

    def _matches(idx: int) -> bool:
        return 0 <= idx < len(lines) and key in _norm(lines[idx])

    if _matches(reported - 1):
        return AnchorResolution(reported, reported, EXACT)

    hits = [i + 1 for i in range(len(lines)) if _matches(i)]
    if len(hits) == 1:
        return AnchorResolution(
            reported, hits[0], REANCHORED_UNIQUE,
            detail=(
                f"scanner reported line {reported}, but the flagged construct "
                f"resolves uniquely to line {hits[0]}"
            ),
        )
    if not hits:
        return AnchorResolution(
            reported, reported, ABSENT,
            detail=f"flagged construct not found in {finding.file}",
        )
    return AnchorResolution(
        reported, reported, AMBIGUOUS,
        detail=f"flagged construct matches {len(hits)} lines in {finding.file}",
    )
