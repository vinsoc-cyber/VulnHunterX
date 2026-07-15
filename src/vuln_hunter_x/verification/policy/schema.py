# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Strict parser/validator for the covered-family assessment response.

The model, on the policy path, returns a structured assessment — typed
``fact_slots`` (each a value + cited evidence IDs) and optional typed
``evidence_requests`` — instead of a free-text verdict. Parsing existing prose
would recreate the structured-signals debt this design exists to remove, so the
schema is validated strictly here:

* every slot must be declared by the policy;
* every value must be a declared enum value or the explicit ``UNRESOLVED``;
* a *resolved* value must cite evidence IDs that exist in the sample's ledger;
* every evidence request must target a declared slot.

Structural / enum / dangling-reference problems raise :class:`SchemaError`, which
the closure controller answers with exactly one repair turn. A well-formed
``UNRESOLVED`` slot is NOT an error — it drives retrieval / NMD, not repair. The
model's own ``verdict`` field, if present, is ignored: the policy decides.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from vuln_hunter_x.context.evidence import EvidenceKind, EvidenceRequest
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.models import FamilyPolicy

UNRESOLVED = "UNRESOLVED"


@dataclass(frozen=True)
class FactClaim:
    slot: str
    value: str
    evidence: tuple[str, ...]


@dataclass(frozen=True)
class EvidenceRequestSpec:
    kind: EvidenceKind
    subject: str
    for_slot: str


@dataclass(frozen=True)
class Assessment:
    fact_claims: dict[str, FactClaim]
    evidence_requests: tuple[EvidenceRequestSpec, ...]
    reasoning: str

    def resolved_facts(self) -> dict[str, str]:
        """slot -> value for every claim that is not ``UNRESOLVED``."""
        return {
            slot: c.value
            for slot, c in self.fact_claims.items()
            if c.value != UNRESOLVED
        }


class SchemaError(ValueError):
    """The assessment is structurally invalid (triggers one repair turn)."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        super().__init__("; ".join(errors))


def parse_assessment(
    raw: Mapping[str, object], policy: FamilyPolicy, ledger: EvidenceLedger
) -> Assessment:
    errors: list[str] = []

    raw_slots = raw.get("fact_slots") if isinstance(raw, Mapping) else None
    if not isinstance(raw_slots, Mapping):
        raise SchemaError(["fact_slots is missing or not a mapping"])

    fact_claims: dict[str, FactClaim] = {}
    for slot, claim in raw_slots.items():
        if slot not in policy.fact_slots:
            errors.append(f"unknown slot {slot!r}")
            continue
        if not isinstance(claim, Mapping) or "value" not in claim:
            errors.append(f"slot {slot!r} claim must be a mapping with a 'value'")
            continue
        value = str(claim["value"])
        if value != UNRESOLVED and value not in policy.fact_slots[slot]:
            errors.append(f"value {value!r} is not declared for slot {slot!r}")
            continue
        raw_evidence = claim.get("evidence", []) or []
        if not isinstance(raw_evidence, (list, tuple)):
            errors.append(f"evidence for slot {slot!r} must be a list")
            continue
        evidence = tuple(str(e) for e in raw_evidence)
        if value != UNRESOLVED:
            missing = [eid for eid in evidence if not ledger.has(eid)]
            if missing:
                errors.append(f"slot {slot!r} cites unknown evidence {missing}")
                continue
        fact_claims[slot] = FactClaim(slot=slot, value=value, evidence=evidence)

    requests: list[EvidenceRequestSpec] = []
    raw_requests = raw.get("evidence_requests", []) or []
    if not isinstance(raw_requests, (list, tuple)):
        errors.append("evidence_requests must be a list")
        raw_requests = []
    for i, item in enumerate(raw_requests):
        if not isinstance(item, Mapping) or "kind" not in item or "subject" not in item:
            errors.append(f"evidence_requests[{i}] needs 'kind' and 'subject'")
            continue
        for_slot = str(item.get("for_slot", ""))
        if for_slot not in policy.fact_slots:
            errors.append(f"evidence_requests[{i}] targets unknown slot {for_slot!r}")
            continue
        parsed = EvidenceRequest.parse(f"{item['kind']}:{item['subject']}")
        kind = parsed.kind if parsed else EvidenceKind.UNKNOWN
        requests.append(
            EvidenceRequestSpec(kind=kind, subject=str(item["subject"]), for_slot=for_slot)
        )

    if errors:
        raise SchemaError(errors)

    reasoning = str(raw.get("reasoning", ""))
    return Assessment(
        fact_claims=fact_claims,
        evidence_requests=tuple(requests),
        reasoning=reasoning,
    )
