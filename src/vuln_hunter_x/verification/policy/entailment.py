# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Pure declarative entailment: resolved facts -> TP / FP / NMD.

No I/O, no model, no retrieval. Given a family policy and a mapping of already
resolved facts (slot -> value; unresolved slots absent), decide the verdict.

Precedence: a single sufficient false-positive condition dominates (a proven
safe fact resolves the finding negative even if other slots look positive).
Only when no FP condition holds and the full true-positive conjunction holds is
it TP. Otherwise — an unresolved decisive slot — it is honest NMD, and the
terminal reason names the unresolved slots.
"""

from __future__ import annotations

from collections.abc import Mapping

from vuln_hunter_x.verification.policy.models import (
    FP,
    NMD,
    TP,
    Condition,
    FamilyPolicy,
    PolicyDecision,
)


def _condition_holds(cond: Condition, facts: Mapping[str, str]) -> bool:
    """True iff every slot in the condition is resolved to an acceptable value."""
    for slot, allowed in cond.items():
        value = facts.get(slot)
        if value is None or value not in allowed:
            return False
    return True


def entail(
    policy: FamilyPolicy,
    facts: Mapping[str, str],
    *,
    evidence_ids: tuple[str, ...] = (),
) -> PolicyDecision:
    """Evaluate the policy's truth table over ``facts``."""
    resolved = {k: v for k, v in facts.items() if v is not None}

    for cond in policy.false_positive_if_any:
        if _condition_holds(cond, resolved):
            reason = "false_positive: " + ", ".join(
                f"{slot}={resolved[slot]}" for slot in cond
            )
            return PolicyDecision(FP, policy.family, resolved, reason, evidence_ids)

    if _condition_holds(policy.true_positive, resolved):
        return PolicyDecision(TP, policy.family, resolved, None, evidence_ids)

    unresolved = sorted(s for s in policy.decisive_slots if resolved.get(s) is None)
    reason = (
        "unresolved: " + ", ".join(unresolved) if unresolved else "no_entailment"
    )
    return PolicyDecision(NMD, policy.family, resolved, reason, evidence_ids)
