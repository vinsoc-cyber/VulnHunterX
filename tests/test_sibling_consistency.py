# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Cross-line sibling-consistency re-verification (#122)."""

from __future__ import annotations

from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.verification.engine import (
    _select_sibling_consistency_candidates,
    apply_sibling_consistency,
)

_RULE = "php.lang.security.injection.tainted-filename.tainted-filename"
_F = "vulnerabilities/view_source.php"


def _mk(rule: str, file: str, line: int, verdict: str, conf: str = "High",
        cwe: list[str] | None = None, score: float = 0.9) -> Verdict:
    f = Finding(rule_id=rule, message="", file=file, start_line=line, end_line=line,
                repo_name="dvwa", lang="php", cwe_ids=cwe or ["CWE-918"])
    return Verdict(finding=f, verdict=verdict, confidence=conf, reasoning="r",
                   answers=[], raw_response="", model="m", confidence_score=score)


def _lines(cands):
    return sorted((fp.finding.start_line for fp, _ in cands))


def test_selects_low_and_med_fp_contradicting_tp_sibling() -> None:
    # dvwa view_source.php: TP@63/High, FP@67/Low, FP@68/Low — same rule, same file.
    cands = _select_sibling_consistency_candidates([
        _mk(_RULE, _F, 63, "True Positive", "High"),
        _mk(_RULE, _F, 67, "False Positive", "Low"),
        _mk(_RULE, _F, 68, "False Positive", "Low"),
    ])
    assert _lines(cands) == [67, 68]
    # every candidate carries the TP sibling at line 63
    for _fp, sibs in cands:
        assert [s.finding.start_line for s in sibs] == [63]


def test_high_confidence_fp_not_selected() -> None:
    cands = _select_sibling_consistency_candidates([
        _mk(_RULE, _F, 63, "True Positive", "High"),
        _mk(_RULE, _F, 67, "False Positive", "High"),
    ])
    assert cands == []


def test_consistent_cluster_selects_nothing() -> None:
    cands = _select_sibling_consistency_candidates([
        _mk(_RULE, _F, 63, "True Positive", "High"),
        _mk(_RULE, _F, 67, "True Positive", "Medium"),
    ])
    assert cands == []


def test_no_tp_sibling_selects_nothing() -> None:
    cands = _select_sibling_consistency_candidates([
        _mk(_RULE, _F, 67, "False Positive", "Low"),
        _mk(_RULE, _F, 68, "False Positive", "Low"),
    ])
    assert cands == []


def test_only_same_line_tp_is_not_a_cross_line_sibling() -> None:
    # TP and FP on the SAME line is reconciliation's job, not this pass.
    cands = _select_sibling_consistency_candidates([
        _mk(_RULE, _F, 63, "True Positive", "High"),
        _mk(_RULE, _F, 63, "False Positive", "Low"),
    ])
    assert cands == []


def test_cross_file_not_clustered() -> None:
    cands = _select_sibling_consistency_candidates([
        _mk(_RULE, "a/view_source.php", 63, "True Positive", "High"),
        _mk(_RULE, "b/view_source.php", 67, "False Positive", "Low"),
    ])
    assert cands == []


def test_different_rule_not_clustered() -> None:
    cands = _select_sibling_consistency_candidates([
        _mk("rule.x", _F, 63, "True Positive", "High"),
        _mk("rule.y", _F, 67, "False Positive", "Low"),
    ])
    assert cands == []


def test_vendored_and_nonproduction_skipped() -> None:
    cands = _select_sibling_consistency_candidates([
        _mk(_RULE, "app/vendor/lib.min.js", 63, "True Positive", "High"),
        _mk(_RULE, "app/vendor/lib.min.js", 67, "False Positive", "Low"),
        _mk(_RULE, "tests/test_x.php", 10, "True Positive", "High"),
        _mk(_RULE, "tests/test_x.php", 20, "False Positive", "Low"),
    ])
    assert cands == []


def test_oversized_cluster_skipped() -> None:
    verdicts = [_mk(_RULE, _F, 100, "True Positive", "High")]
    verdicts += [_mk(_RULE, _F, ln, "False Positive", "Low") for ln in range(1, 20)]
    cands = _select_sibling_consistency_candidates(verdicts)
    assert cands == []


def test_apply_flips_fp_to_tp_when_reverify_upgrades() -> None:
    verdicts = [
        _mk(_RULE, _F, 63, "True Positive", "High"),
        _mk(_RULE, _F, 68, "False Positive", "Low"),
    ]

    def reverify(fp, sibs):
        return _mk(fp.finding.rule_id, fp.finding.file, fp.finding.start_line,
                   "True Positive", "Medium")

    out = apply_sibling_consistency(verdicts, reverify)
    by_line = {v.finding.start_line: v.verdict for v in out}
    assert by_line == {63: "True Positive", 68: "True Positive"}


def test_apply_keeps_fp_when_reverify_declines() -> None:
    fp = _mk(_RULE, _F, 68, "False Positive", "Low")
    verdicts = [_mk(_RULE, _F, 63, "True Positive", "High"), fp]

    def reverify(fp_, sibs):
        return fp_  # unchanged — material difference found

    out = apply_sibling_consistency(verdicts, reverify)
    assert out[1] is fp
    assert out[1].verdict == "False Positive"


def test_apply_is_exception_safe() -> None:
    fp = _mk(_RULE, _F, 68, "False Positive", "Low")
    verdicts = [_mk(_RULE, _F, 63, "True Positive", "High"), fp]

    def reverify(fp_, sibs):
        raise RuntimeError("llm down")

    out = apply_sibling_consistency(verdicts, reverify)
    assert out[1] is fp
    assert out[1].verdict == "False Positive"


def test_apply_passes_fp_and_siblings_to_reverify() -> None:
    verdicts = [
        _mk(_RULE, _F, 63, "True Positive", "High"),
        _mk(_RULE, _F, 68, "False Positive", "Low"),
    ]
    seen = []

    def reverify(fp_, sibs):
        seen.append((fp_.finding.start_line, [s.finding.start_line for s in sibs]))
        return fp_

    apply_sibling_consistency(verdicts, reverify)
    assert seen == [(68, [63])]


def test_sibling_reverify_carries_evidence_and_prompt() -> None:
    from types import SimpleNamespace
    from unittest.mock import MagicMock

    from vuln_hunter_x.llm.client import LLMClient
    from vuln_hunter_x.verification.engine import VerificationEngine

    ctx = SimpleNamespace(code="@file_get_contents(...)", start_line=60,
                          function_name="<top>")
    returned = _mk(_RULE, _F, 68, "True Positive", "Medium")
    client = MagicMock()
    client.request_second_opinion.return_value = returned
    client._SIBLING_CONSISTENCY_CHALLENGE_PROMPT = (
        LLMClient._SIBLING_CONSISTENCY_CHALLENGE_PROMPT
    )
    engine = SimpleNamespace(
        questions_loader=MagicMock(get_questions=MagicMock(return_value="Q")),
        context_extractor=MagicMock(get_context=MagicMock(return_value=ctx)),
        llm_client=client,
        config=SimpleNamespace(output=SimpleNamespace(is_verbose=False, is_quiet=True)),
        _log_fh=None,
    )
    fp = _mk(_RULE, _F, 68, "False Positive", "Low")
    tp = _mk(_RULE, _F, 63, "True Positive", "High")

    out = VerificationEngine._sibling_reverify(engine, fp, [tp])

    assert out is returned
    _, kwargs = client.request_second_opinion.call_args
    assert kwargs["challenge_prompt"] is LLMClient._SIBLING_CONSISTENCY_CHALLENGE_PROMPT
    assert kwargs["previous_verdict"] is fp
    assert kwargs["context"] == ctx.code
    note = " ".join(kwargs["prefetched_context"].values())
    assert "63" in note  # sibling TP line is cited as evidence
