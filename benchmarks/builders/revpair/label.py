# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Automatic tier labelling of vulnerable-revision alerts.

Inputs per fix: the keyed alerts of the vulnerable (parent) and patched (fix)
revisions, the fix diff, and the CVE's CWE. Each vulnerable-side alert gets
exactly one tier (``metadata.label_tier``):

``silver-tp`` → label ``TP``
    The alert is absent after the patch (no match on the fix side), its
    flagged span overlaps a deleted/modified old-side hunk (or a pure
    insertion placed directly before/inside the span), and its CWE matches the
    CVE CWE (exact, or same family — see :func:`cwe_matches`).
``silver-tp-weak`` → label ``TP``
    Absent after the patch and touches the fix, but either the CWE does not
    match or the only overlap is function-level (the alert's enclosing
    function contains a changed line, the alert line itself does not).
``persistent`` → label ``FP``
    Matched unchanged on both revisions (primary key, CodeQL fingerprint or
    diff-mapped line) and located in a function — or, when the function is
    unknown, a file — that the fix did not touch. This means *persistent alert,
    not confirmed FP*: the alert survived a fix of a different bug; it may
    still be a real, unfixed vulnerability. Adjudication is pending.
``ambiguous`` → excluded from the manifest, counted in attrition:
    disappears without touching the fix; touches the fix but persists
    (including hunk-correspondence matches); unanchored alerts (no file/line).
    Fix-side alerts with no vulnerable-side partner are counted as
    ``new-on-fix-side`` ambiguous records.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from benchmarks.adapters.cwe_rule_map import cwe_to_rules, rule_to_cwe
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.builders.revpair.alert_key import (
    Alert,
    MatchResult,
    SourceCache,
    enclosing_function,
    key_str,
)
from benchmarks.builders.revpair.hunks import DiffIndex

TIER_SILVER_TP = "silver-tp"
TIER_SILVER_TP_WEAK = "silver-tp-weak"
TIER_PERSISTENT = "persistent"
TIER_AMBIGUOUS = "ambiguous"

SOURCE_DATASET = "revpair"
DEFAULT_SNIPPET_WINDOW = 15

# Small, explicit CWE families beyond what cwe_rule_map's shared rules imply.
# Members of one family are treated as the same weakness for labelling.
CWE_FAMILIES: tuple[frozenset[str], ...] = (
    frozenset({"CWE-119", "CWE-120", "CWE-121", "CWE-122", "CWE-125", "CWE-787", "CWE-788"}),
    frozenset({"CWE-190", "CWE-191", "CWE-189", "CWE-680", "CWE-197"}),
    frozenset({"CWE-77", "CWE-78", "CWE-88"}),
    frozenset({"CWE-22", "CWE-23", "CWE-36", "CWE-73", "CWE-59"}),
    frozenset({"CWE-79", "CWE-80", "CWE-83", "CWE-87"}),
    frozenset({"CWE-89", "CWE-564"}),
    frozenset({"CWE-94", "CWE-95", "CWE-1336", "CWE-917"}),
    frozenset({"CWE-416", "CWE-415", "CWE-825"}),
    frozenset({"CWE-400", "CWE-1333", "CWE-770", "CWE-674"}),
    frozenset({"CWE-611", "CWE-776", "CWE-827"}),
    frozenset({"CWE-502", "CWE-915", "CWE-1321"}),
)


def normalize_cwe(cwe: str) -> str:
    c = (cwe or "").strip().upper()
    if not c:
        return ""
    if c.isdigit():
        return f"CWE-{c}"
    if c.startswith("CWE") and not c.startswith("CWE-"):
        c = "CWE-" + c[3:].lstrip(":_ ")
    return c


def alert_cwes(alert: Alert) -> list[str]:
    """CWE ids the scanner attached to the alert, else the rule map's CWE."""
    cwes = [normalize_cwe(c) for c in alert.finding.cwe_ids if normalize_cwe(c)]
    if not cwes:
        mapped = rule_to_cwe(alert.rule_id)
        if mapped:
            cwes = [mapped]
    return cwes


def cwe_matches(target: str, alert: Alert) -> str:
    """Return ``"exact"``, ``"family"`` or ``""`` for the alert vs CVE CWE."""
    target = normalize_cwe(target)
    if not target:
        return ""
    cwes = alert_cwes(alert)
    if target in cwes:
        return "exact"
    target_rules = set(cwe_to_rules(target))
    if alert.rule_id in target_rules:
        return "family"
    for c in cwes:
        if target_rules & set(cwe_to_rules(c)):
            return "family"
        if any(target in fam and c in fam for fam in CWE_FAMILIES):
            return "family"
    return ""


def touched_functions(diff: DiffIndex, vuln_source: SourceCache, lang: str) -> set[tuple[str, str]]:
    """``(old path, function)`` pairs containing a changed or insertion line."""
    out: set[tuple[str, str]] = set()
    for fd in diff.files:
        if fd.old_path is None:
            continue
        lines = vuln_source.lines(fd.old_path)
        if not lines:
            continue
        probe: set[int] = set(fd.changed_old_lines())
        # A pure insertion sits *after* old line p, so it belongs to p's scope
        # (e.g. a check inserted right after a function's opening line).
        probe.update(p for p in fd.insertion_points if p > 0)
        for ln in probe:
            fn = enclosing_function(lines, ln, lang)
            if fn:
                out.add((fd.old_path, fn))
    return out


@dataclass
class TierDecision:
    alert: Alert
    tier: str
    reason: str
    touch: str  # "hunk" | "function" | ""
    cwe_match: str  # "exact" | "family" | ""
    match_kind: str | None


def classify(
    match: MatchResult,
    diff: DiffIndex,
    cve_cwe: str,
    fn_touched: set[tuple[str, str]],
) -> list[TierDecision]:
    """Assign a tier to every vulnerable-side alert (see module docstring)."""
    kinds: dict[int, str] = {id(v): how for v, _f, how in match.pairs}
    vuln_all = [v for v, _f, _h in match.pairs] + list(match.vuln_unmatched)
    decisions: list[TierDecision] = []
    for a in vuln_all:
        how = kinds.get(id(a))
        cwe_m = cwe_matches(cve_cwe, a)
        if not a.path or a.start_line < 1:
            decisions.append(TierDecision(a, TIER_AMBIGUOUS, "unanchored", "", cwe_m, how))
            continue
        fd = diff.for_old_path(a.path)
        hunk_touch = fd is not None and fd.overlaps_old(a.start_line, a.end_line)
        fn_touch = bool(a.function) and (a.path, a.function) in fn_touched
        touch = "hunk" if hunk_touch else ("function" if fn_touch else "")
        if how is None:
            if hunk_touch and cwe_m:
                tier, reason = TIER_SILVER_TP, "absent-after-fix:hunk:cwe-match"
            elif touch:
                why = "cwe-mismatch" if not cwe_m else "function-only"
                tier, reason = TIER_SILVER_TP_WEAK, f"absent-after-fix:{touch}:{why}"
            else:
                tier, reason = TIER_AMBIGUOUS, "disappears-without-touching-fix"
        else:
            if touch or how == "hunk":
                tier, reason = TIER_AMBIGUOUS, f"touches-fix-but-persists:{how}"
            else:
                # Function known → the function must be untouched; unknown →
                # conservatively require the whole file to be untouched.
                untouched_scope = (not fn_touch) if a.function else fd is None
                if untouched_scope:
                    tier, reason = TIER_PERSISTENT, f"persistent-untouched:{how}"
                else:
                    tier, reason = TIER_AMBIGUOUS, f"persists-in-touched-file:{how}"
        decisions.append(TierDecision(a, tier, reason, touch, cwe_m, how))
    return decisions


def snippet_window(lines: list[str] | None, line: int, window: int) -> str:
    if not lines:
        return ""
    lo = max(1, line - window)
    hi = min(len(lines), line + window)
    return "\n".join(lines[lo - 1 : hi])


@dataclass
class FixContext:
    """Per-fix metadata copied into every emitted entry."""

    cve_id: str
    cwe: str
    lang: str
    repo: str
    repo_url: str
    parent_sha: str
    fix_sha: str
    vuln_name: str
    fix_name: str
    cve_published: str | None = None


def entry_id(ctx: FixContext, decision: TierDecision, ordinal: int) -> str:
    a = decision.alert
    digest = key_str((ctx.parent_sha, *a.primary_key(), str(ordinal)))
    return f"{SOURCE_DATASET}:{ctx.cve_id}:{a.tool.lower()}:{digest[:12]}"


def build_entries(
    decisions: list[TierDecision],
    ctx: FixContext,
    vuln_source: SourceCache,
    *,
    window: int = DEFAULT_SNIPPET_WINDOW,
) -> list[GroundTruthEntry]:
    """Convert non-ambiguous decisions into :class:`GroundTruthEntry` objects.

    ``code_snippet`` is a ±``window``-line excerpt of the vulnerable revision.
    """
    entries: list[GroundTruthEntry] = []
    seen: dict[str, int] = {}
    for d in sorted(decisions, key=lambda d: (d.alert.path, d.alert.start_line, d.alert.rule_id)):
        if d.tier == TIER_AMBIGUOUS:
            continue
        a = d.alert
        base = key_str(a.primary_key())
        ordinal = seen.get(base, 0)
        seen[base] = ordinal + 1
        cwes = alert_cwes(a)
        label = TIER_TO_LABEL[d.tier]
        metadata: dict[str, Any] = {
            "label_source": "auto-diff",
            "adjudication": "pending",
            "label_tier": d.tier,
            "label_reason": d.reason,
            "label_note": (
                "persistent alert, not confirmed FP" if d.tier == TIER_PERSISTENT else ""
            ),
            "cve_id": ctx.cve_id,
            "cve_published": ctx.cve_published,
            "cve_cwe": normalize_cwe(ctx.cwe),
            "alert_cwes": cwes,
            "cwe_match": d.cwe_match,
            "touch": d.touch,
            "match_kind": d.match_kind,
            "repo": ctx.repo,
            "repo_url": ctx.repo_url,
            "parent_sha": ctx.parent_sha,
            "fix_sha": ctx.fix_sha,
            "repo_name": ctx.vuln_name,
            "fix_repo_name": ctx.fix_name,
            "tool": a.tool,
            "rule_id": a.rule_id,
            "primary_key": list(a.primary_key()),
            "primary_key_hash": base,
            "secondary_key": a.fingerprint,
            "finding": a.finding.to_dict(),
        }
        entries.append(
            GroundTruthEntry(
                id=entry_id(ctx, d, ordinal),
                source_dataset=SOURCE_DATASET,
                cwe_id=(cwes[0] if cwes else normalize_cwe(ctx.cwe)),
                rule_id=a.rule_id,
                file_path=a.path,
                function_name=a.function,
                start_line=a.start_line,
                lang=ctx.lang,
                label=label,
                code_snippet=snippet_window(vuln_source.lines(a.path), a.start_line, window),
                metadata=metadata,
                sink_line=a.start_line,
            )
        )
    return entries


TIER_TO_LABEL = {
    TIER_SILVER_TP: LABEL_TP,
    TIER_SILVER_TP_WEAK: LABEL_TP,
    TIER_PERSISTENT: LABEL_FP,
}
