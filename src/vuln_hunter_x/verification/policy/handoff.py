# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Cross-family handoff control-flow types (P3c).

Internal to the engine's routing — NOT persisted on ``Verdict``. Attempting one
family (native or handoff) on a finding yields one of three outcomes:

- ``DECIDED``: the target family entailed a verdict (TP or FP).
- ``NOT_APPLICABLE``: the finding is not this family's sink. This is NEVER a
  dismissal — it hands the finding back to its base route.
- ``UNRESOLVED``: decisive facts (including the applicability slot) could not be
  resolved, so the family abstains (NMD).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from vuln_hunter_x.verification.policy.models import FamilyPolicy

if TYPE_CHECKING:
    from vuln_hunter_x.core.types import Verdict
    from vuln_hunter_x.verification.policy.models import PolicyDecision


class PolicyAttemptStatus(Enum):
    DECIDED = "decided"
    NOT_APPLICABLE = "family_not_applicable"
    UNRESOLVED = "unresolved"


@dataclass(frozen=True)
class PolicyAttempt:
    """Outcome of attempting one family on a finding (engine-internal)."""

    status: PolicyAttemptStatus
    verdict: Verdict | None = None
    decision: PolicyDecision | None = None


def classify_applicability(policy: FamilyPolicy, facts: Mapping[str, str]) -> str:
    """Classify a family's applicability to a finding from resolved facts.

    Returns ``"applicable"`` | ``"not_applicable"`` | ``"unresolved"``. A family
    with no ``applicability`` block is always applicable (existing families are
    unchanged — their ``NOT_*_SINK`` stays an entailment False Positive, never a
    not-applicable handoff outcome). Evaluated BEFORE entailment so a
    not-applicable finding can never become a False Positive.
    """
    appl = policy.applicability
    if appl is None:
        return "applicable"
    value = facts.get(appl.slot)
    if value is not None and value in appl.not_applicable_values:
        return "not_applicable"
    if value is not None and value in appl.applicable_values:
        return "applicable"
    return "unresolved"
