# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Generic decision-strategy protocol for the verification loop.

The multi-turn loop in ``LLMClient.analyze`` can be handed an optional strategy
that, after each parsed model response, decides what to do next: fetch more
evidence and re-prompt, ask the model to repair a malformed response, finalize
a verdict, or abstain. This module is deliberately policy-agnostic — it imports
only the core ``Verdict`` type — so the loop never depends on the policy layer.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from vuln_hunter_x.core.types import Verdict


@dataclass(frozen=True)
class Retrieve:
    """Send ``followup_prompt`` as the next user turn (evidence already fetched)."""

    followup_prompt: str


@dataclass(frozen=True)
class Repair:
    """Send ``repair_prompt`` asking the model to fix a malformed response."""

    repair_prompt: str


@dataclass(frozen=True)
class Finalize:
    """Stop the loop and return this verdict."""

    verdict: Verdict


@dataclass(frozen=True)
class Abstain:
    """Stop the loop and return this (Needs-More-Data) verdict."""

    verdict: Verdict


Action = Retrieve | Repair | Finalize | Abstain


@runtime_checkable
class DecisionStrategy(Protocol):
    def evaluate(
        self, parsed: Mapping[str, object], raw_response: str = "", iteration: int = 1
    ) -> Action: ...
