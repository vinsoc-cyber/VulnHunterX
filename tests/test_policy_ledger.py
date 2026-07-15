# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Evidence ledger: stable IDs over primary-slice, scanner-dataflow, retrieved."""

from __future__ import annotations

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceRequest,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
)
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger, EvidenceOrigin


def _retrieved(status=EvidenceStatus.FOUND, exhaustive=True, kind=EvidenceKind.FUNCTION):
    req = EvidenceRequest(kind=kind, subject="encodeForLog", raw_request="function:encodeForLog")
    return EvidenceResult(
        request=req,
        status=status,
        prompt_content="// body",
        scope=EvidenceScope.REPOSITORY_INDEX,
        exhaustive=exhaustive,
    )


def test_local_slice_gets_l_id():
    led = EvidenceLedger()
    ref = SourceRef("nodegoat", "javascript", "app/routes/session.js", 60, 70)
    e = led.add_local_slice(ref, "flagged log call + source")
    assert e.id == "L1"
    assert e.origin is EvidenceOrigin.LOCAL_SLICE
    assert e.source_ref == ref


def test_scanner_dataflow_gets_d_id():
    led = EvidenceLedger()
    e = led.add_scanner_dataflow("req.body.userName -> console.log")
    assert e.id == "D1"
    assert e.origin is EvidenceOrigin.SCANNER_DATAFLOW


def test_retrieved_gets_r_id_and_carries_typed_fields():
    led = EvidenceLedger()
    e = led.add_retrieved(_retrieved(status=EvidenceStatus.FOUND, exhaustive=False))
    assert e.id == "R1"
    assert e.origin is EvidenceOrigin.RETRIEVED
    assert e.status is EvidenceStatus.FOUND
    assert e.exhaustive is False
    assert e.kind is EvidenceKind.FUNCTION
    assert e.scope is EvidenceScope.REPOSITORY_INDEX


def test_ids_are_stable_and_incrementing_per_origin():
    led = EvidenceLedger()
    ref = SourceRef("r", "javascript", "f.js", 1, 2)
    led.add_local_slice(ref, "a")
    led.add_local_slice(ref, "b")
    led.add_scanner_dataflow("x")
    led.add_retrieved(_retrieved())
    led.add_retrieved(_retrieved())
    assert [e.id for e in led.entries] == ["L1", "L2", "D1", "R1", "R2"]


def test_get_and_has_by_id():
    led = EvidenceLedger()
    led.add_retrieved(_retrieved())
    assert led.has("R1")
    assert not led.has("R2")
    assert led.get("R1").id == "R1"
    assert led.get("nope") is None
