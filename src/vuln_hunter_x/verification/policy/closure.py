# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Per-sample evidence-closure controller.

Implements the obligation-driven state machine for one model sample on the
policy path: parse the structured assessment, keep only admissibly-supported
fact values, and then either finalize (entailment resolves), retrieve more
evidence (an unresolved decisive slot with a usable request and budget left),
ask for one repair (malformed assessment), or abstain to honest NMD (budget
exhausted, no usable request, or a second malformed assessment).

It is a :class:`DecisionStrategy`: ``evaluate`` is called once per parsed model
turn. Retrieval is resolved here (via the typed provider) and rendered into the
follow-up prompt; the LLM turn execution stays in ``LLMClient``. This is NOT the
``min_iterations`` mechanism — closure is driven by evidence obligations, not a
fixed turn depth.
"""

from __future__ import annotations

from collections.abc import Mapping

from vuln_hunter_x.context.evidence import (
    ContextProviderProtocol,
    EvidenceKind,
    EvidenceRequest,
    EvidenceResult,
)
from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.llm.decision_strategy import Abstain, Finalize, Repair, Retrieve
from vuln_hunter_x.verification.policy.entailment import entail
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.models import NMD, FamilyPolicy, PolicyDecision
from vuln_hunter_x.verification.policy.schema import UNRESOLVED, SchemaError, parse_assessment
from vuln_hunter_x.verification.policy.support import is_admissible


def render_assessment_prompt(policy: FamilyPolicy, ledger: EvidenceLedger) -> str:
    """Render the covered-family assessment instructions + the seeded ledger.

    Appended to the first user turn so the model returns the structured
    ``fact_slots`` assessment (citing evidence by ledger id) instead of a
    free-text verdict.
    """
    lines = [
        "## Evidence-closure assessment (REQUIRED response format)",
        "",
        "Do NOT decide a free-text verdict. Assess each fact slot below using ONLY "
        "the cited evidence, and return strict JSON:",
        '{"fact_slots": {"<slot>": {"value": "<VALUE|UNRESOLVED>", "evidence": '
        '["<id>"]}}, "evidence_requests": [{"kind": "function", "subject": '
        '"<name>", "for_slot": "<slot>"}], "reasoning": "..."}',
        "",
        "Fact slots and allowed values (use UNRESOLVED if the evidence does not "
        "establish the value):",
    ]
    for slot, values in policy.fact_slots.items():
        lines.append(f"  - {slot}: {', '.join(values)} | UNRESOLVED")
    lines.append("")
    lines.append(
        "Available evidence (cite by id; if a decisive slot is UNRESOLVED, request "
        "more via evidence_requests):"
    )
    for entry in ledger.entries:
        lines.append(f"  [{entry.id}] {entry.origin.value}: {entry.summary}")
    return "\n".join(lines)


class PolicyClosureController:
    def __init__(
        self,
        *,
        policy: FamilyPolicy,
        provider: ContextProviderProtocol,
        finding: Finding,
        model: str,
        ledger: EvidenceLedger,
        max_retrieval_rounds: int = 3,
        max_unique_requests: int = 8,
        max_repairs: int = 1,
    ) -> None:
        self._policy = policy
        self._provider = provider
        self._finding = finding
        self._model = model
        self._ledger = ledger
        self._max_retrieval_rounds = max_retrieval_rounds
        self._max_unique_requests = max_unique_requests
        self._max_repairs = max_repairs
        self._retrieval_rounds = 0
        self._repairs = 0
        self._seen: set[tuple[EvidenceKind, str]] = set()
        self._pending: list[tuple[str, EvidenceResult]] = []  # (entry_id, result)
        self.last_decision: PolicyDecision | None = None

    def initial_instructions(self) -> str:
        """Fact-slot assessment instructions appended to the first user turn."""
        return render_assessment_prompt(self._policy, self._ledger)

    def evaluate(
        self, parsed: Mapping[str, object], raw_response: str = "", iteration: int = 1
    ):
        try:
            assessment = parse_assessment(parsed, self._policy, self._ledger)
        except SchemaError as exc:
            if self._repairs < self._max_repairs:
                self._repairs += 1
                return Repair(self._repair_prompt(exc))
            return self._abstain("model_failed_to_assess", raw_response)

        facts, evidence_ids = self._admissible_facts(assessment)
        decision = entail(self._policy, facts, evidence_ids=tuple(evidence_ids))

        if decision.verdict != NMD:
            self.last_decision = decision
            return Finalize(self._verdict_from(decision, assessment, raw_response))

        unresolved = {s for s in self._policy.decisive_slots if s not in facts}
        specs = [
            s
            for s in assessment.evidence_requests
            if s.for_slot in unresolved
            and s.kind is not EvidenceKind.UNKNOWN
            and (s.kind, s.subject) not in self._seen
        ]
        can_retrieve = (
            bool(specs)
            and self._retrieval_rounds < self._max_retrieval_rounds
            and len(self._seen) < self._max_unique_requests
        )
        if can_retrieve and self._retrieve(specs):
            self._retrieval_rounds += 1
            return Retrieve(self._retrieve_followup())

        if self._retrieval_rounds >= self._max_retrieval_rounds:
            reason = "retrieval_budget_exhausted"
        else:
            reason = decision.terminal_reason or "unresolved"
        return self._abstain(reason, raw_response, decision)

    # ---- internals ----

    def _admissible_facts(self, assessment) -> tuple[dict[str, str], list[str]]:
        facts: dict[str, str] = {}
        evidence_ids: list[str] = []
        for slot, claim in assessment.fact_claims.items():
            if claim.value == UNRESOLVED:
                continue
            cited = [self._ledger.get(eid) for eid in claim.evidence]
            cited = [c for c in cited if c is not None]
            if is_admissible(slot, claim.value, cited):
                facts[slot] = claim.value
                evidence_ids.extend(claim.evidence)
        return facts, evidence_ids

    def _retrieve(self, specs) -> bool:
        requests = []
        for s in specs:
            self._seen.add((s.kind, s.subject))
            requests.append(
                EvidenceRequest(
                    kind=s.kind, subject=s.subject, raw_request=f"{s.kind.value}:{s.subject}"
                )
            )
        results = self._provider.resolve_evidence(
            self._finding.repo_name, self._finding.lang, requests
        )
        self._pending = []
        added = False
        for req in requests:
            res = results.get(req.raw_request)
            if res is None:
                continue
            entry = self._ledger.add_retrieved(res)
            self._pending.append((entry.id, res))
            added = True
        return added

    def _retrieve_followup(self) -> str:
        blocks = [
            f"[{eid}] ({res.request.raw_request}, status={res.status.value}):\n{res.prompt_content}"
            for eid, res in self._pending
        ]
        self._pending = []
        return (
            "Additional evidence retrieved (cite by the bracketed id):\n\n"
            + "\n\n".join(blocks)
            + "\n\nRe-assess the fact slots using this evidence and return the JSON assessment."
        )

    def _repair_prompt(self, exc: SchemaError) -> str:
        return (
            "Your assessment was not valid: "
            + "; ".join(exc.errors)
            + ". Return a corrected JSON assessment with the same structure "
            "(fact_slots with declared enum values and evidence ids that exist)."
        )

    def _abstain(self, reason: str, raw_response: str = "", decision=None) -> Abstain:
        facts = dict(decision.facts) if decision else {}
        nmd = PolicyDecision(NMD, self._policy.family, facts, terminal_reason=reason)
        self.last_decision = nmd
        return Abstain(self._verdict_from(nmd, None, raw_response))

    def _verdict_from(self, decision: PolicyDecision, assessment, raw_response: str) -> Verdict:
        bits = []
        if assessment is not None and assessment.reasoning:
            bits.append(assessment.reasoning)
        bits.append(f"[policy:{decision.family} {decision.terminal_reason or 'entailed'}]")
        return Verdict(
            finding=self._finding,
            verdict=decision.verdict,
            confidence="High" if decision.verdict != NMD else "Low",
            reasoning=" ".join(bits),
            answers=[],
            raw_response=raw_response,
            model=self._model,
            data_flow="",
        )
