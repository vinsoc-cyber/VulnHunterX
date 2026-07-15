# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Aggregate per-sample policy decisions.

Each self-consistency sample runs the closure controller independently (its own
ledger) and yields a :class:`PolicyDecision`. Aggregation is over the DECISIONS,
never a merge of fact slots across samples (that could manufacture a proof from
incompatible paths). A True/False-Positive disagreement resolves to honest NMD
``sample_disagreement`` — never a tie-broken binary.
"""

from __future__ import annotations

from collections.abc import Sequence

from vuln_hunter_x.verification.policy.models import FP, NMD, TP, PolicyDecision


def aggregate_policy_decisions(
    decisions: Sequence[PolicyDecision | None],
) -> PolicyDecision:
    resolved = [d for d in decisions if d is not None]
    if not resolved:
        return PolicyDecision(NMD, "unknown", {}, terminal_reason="no_samples")

    family = resolved[0].family
    verdicts = {d.verdict for d in resolved}
    has_tp = TP in verdicts
    has_fp = FP in verdicts

    if has_tp and has_fp:
        return PolicyDecision(NMD, family, {}, terminal_reason="sample_disagreement")

    if has_tp or has_fp:
        target = TP if has_tp else FP
        rep = next(d for d in resolved if d.verdict == target)
        return PolicyDecision(
            target, family, dict(rep.facts), rep.terminal_reason, rep.evidence_ids
        )

    # All NMD — combine the distinct terminal reasons.
    reasons = sorted({d.terminal_reason for d in resolved if d.terminal_reason})
    return PolicyDecision(
        NMD, family, {}, terminal_reason="; ".join(reasons) or "unresolved"
    )
