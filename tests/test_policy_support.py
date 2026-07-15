# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Per-slot-VALUE evidence admissibility for CWE-117.

The crux of the evidence-closure design: a claimed fact value is only accepted
when the CITED evidence is admissible for that specific value. This prevents
both over-confirmation (claiming a bypass with no path) and false-absence
(claiming complete neutralization from a non-exhaustive or framework-marker
result, or a snippet-scoped miss).
"""

from __future__ import annotations

from vuln_hunter_x.context.evidence import (
    EvidenceKind,
    EvidenceRequest,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    SourceRef,
)
from vuln_hunter_x.verification.policy.ledger import EvidenceLedger
from vuln_hunter_x.verification.policy.support import is_admissible

_REF = SourceRef("nodegoat", "javascript", "app/routes/session.js", 60, 70)


def _res(status, *, exhaustive=True, kind=EvidenceKind.FUNCTION, scope=EvidenceScope.REPOSITORY_INDEX):
    req = EvidenceRequest(kind=kind, subject="encodeForLog", raw_request="function:encodeForLog")
    return EvidenceResult(
        request=req, status=status, prompt_content="x", scope=scope, exhaustive=exhaustive
    )


# ---- no evidence is never admissible for a decisive fact ----

def test_empty_citations_not_admissible():
    assert not is_admissible("attacker_control", "PROVEN", [])


# ---- neutralization_coverage: the value-specific rules ----

def test_all_reaching_paths_needs_exhaustive_found():
    led = EvidenceLedger()
    ok = led.add_retrieved(_res(EvidenceStatus.FOUND, exhaustive=True))
    assert is_admissible("neutralization_coverage", "ALL_REACHING_PATHS", [ok])


def test_all_reaching_paths_rejects_non_exhaustive_found():
    led = EvidenceLedger()
    weak = led.add_retrieved(_res(EvidenceStatus.FOUND, exhaustive=False))
    assert not is_admissible("neutralization_coverage", "ALL_REACHING_PATHS", [weak])


def test_all_reaching_paths_rejects_framework_marker():
    led = EvidenceLedger()
    fw = led.add_retrieved(
        _res(EvidenceStatus.FOUND, exhaustive=True, kind=EvidenceKind.FRAMEWORK_SANITIZERS)
    )
    assert not is_admissible("neutralization_coverage", "ALL_REACHING_PATHS", [fw])


def test_none_found_complete_needs_not_found_complete():
    led = EvidenceLedger()
    complete = led.add_retrieved(_res(EvidenceStatus.NOT_FOUND_COMPLETE))
    assert is_admissible("neutralization_coverage", "NONE_FOUND_COMPLETE", [complete])


def test_none_found_complete_rejects_incomplete_index():
    led = EvidenceLedger()
    weak = led.add_retrieved(_res(EvidenceStatus.INCOMPLETE_INDEX))
    assert not is_admissible("neutralization_coverage", "NONE_FOUND_COMPLETE", [weak])


def test_none_found_complete_rejects_snippet_scope_miss():
    led = EvidenceLedger()
    snip = led.add_retrieved(
        _res(EvidenceStatus.NOT_FOUND_COMPLETE, scope=EvidenceScope.SNIPPET)
    )
    assert not is_admissible("neutralization_coverage", "NONE_FOUND_COMPLETE", [snip])


def test_bypass_path_found_needs_a_concrete_path():
    led = EvidenceLedger()
    slice_e = led.add_local_slice(_REF, "userName -> console.log, no encode")
    assert is_admissible("neutralization_coverage", "BYPASS_PATH_FOUND", [slice_e])


def test_bypass_path_found_rejects_only_an_absence_result():
    led = EvidenceLedger()
    absent = led.add_retrieved(_res(EvidenceStatus.NOT_FOUND_COMPLETE))
    assert not is_admissible("neutralization_coverage", "BYPASS_PATH_FOUND", [absent])


# ---- positive negatives: proven-safe facts from the local slice ----

def test_attacker_control_refuted_from_local_slice():
    led = EvidenceLedger()
    slice_e = led.add_local_slice(_REF, 'const msg = "static string"')
    assert is_admissible("attacker_control", "REFUTED", [slice_e])


def test_attacker_control_proven_from_scanner_dataflow():
    led = EvidenceLedger()
    df = led.add_scanner_dataflow("req.body.userName -> console.log")
    assert is_admissible("attacker_control", "PROVEN", [df])


def test_record_boundary_preserved_from_local_slice():
    led = EvidenceLedger()
    slice_e = led.add_local_slice(_REF, "logger.info({user}, 'msg')  // structured")
    assert is_admissible("record_boundary", "PRESERVED", [slice_e])


def test_sink_binding_from_local_slice():
    led = EvidenceLedger()
    slice_e = led.add_local_slice(_REF, "console.log(userName)")
    assert is_admissible("sink_binding", "QUALIFYING_LOG_SINK", [slice_e])
