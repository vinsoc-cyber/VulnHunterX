# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Data model for the family-policy layer.

Kept dependency-free (no LLM / engine imports) so the policy core is a pure,
independently-testable unit. Verdict strings mirror
:class:`vuln_hunter_x.core.types.VerdictType` values but are re-declared here to
avoid importing the heavier types module into the pure core.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

# Verdict vocabulary — must equal core.types.VerdictType values.
TP = "True Positive"
FP = "False Positive"
NMD = "Needs More Data"

# A single entailment condition: slot -> tuple of acceptable values (a fact
# matches the condition when its resolved value is one of these).
Condition = Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class FamilyPolicy:
    """A declarative policy for one vulnerability family.

    ``true_positive`` is a conjunction (every slot must resolve to one of its
    acceptable values). ``false_positive_if_any`` is a disjunction of
    conjunctions (the finding is FP as soon as any one condition holds). A
    decisive slot left unresolved after retrieval forces NMD.
    """

    family: str
    cwes: frozenset[str]
    rule_aliases: tuple[str, ...]
    fact_slots: Mapping[str, tuple[str, ...]]  # slot -> declared allowed values
    decisive_slots: frozenset[str]
    true_positive: Condition
    false_positive_if_any: tuple[Condition, ...]
    # Optional language scoping: empty ⇒ language-agnostic (matches any lang, as
    # CWE-117 does); non-empty ⇒ the finding's lang must be a member. Lowercased.
    languages: frozenset[str] = frozenset()
    version: str = "1"


@dataclass(frozen=True)
class PolicyDecision:
    """The outcome of entailment over resolved facts for one sample."""

    verdict: str  # TP | FP | NMD
    family: str
    facts: Mapping[str, str]  # slot -> resolved value (only resolved slots)
    terminal_reason: str | None = None
    evidence_ids: tuple[str, ...] = ()
