# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Regression tests for the rule_id aliases added to the Java and Python
question YAMLs (covering CWE-328, CWE-78, CWE-501) and for the
`pred_api_error_count` counter in the benchmark evaluator."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_hunter_x.core.rule_profiles import RuleProfileManager
from vuln_hunter_x.questions.loader import QuestionsLoader

_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def loader() -> QuestionsLoader:
    ql = QuestionsLoader(_ROOT / "config" / "prompts")
    rpm = RuleProfileManager(_ROOT / "config" / "rule_categories.yaml")
    ql.set_cwe_question_map(rpm.cwe_question_map)
    return ql


# ── Question-bank coverage regressions ────────────────────────────────────────

@pytest.mark.parametrize(
    "rule_id",
    [
        # Java: rule_ids that benchmarks/adapters/cwe_rule_map.py emits for
        # CWE-328, CWE-78, CWE-501. Pre-fix these fell to the default bucket
        # and dominated the FN cohort on owasp-java.
        "java/weak-cryptographic-hash",
        "java/weak-cryptographic-algorithm",
        "java/command-line-injection",
        "java/command-injection",
        "java/trust-boundary-violation",
        # Python: the symmetric set. owasp-python would hit the same trap
        # before this fix.
        "py/weak-sensitive-data-hashing",
        "py/weak-cryptographic-algorithm",
        "py/command-line-injection",
        "py/command-injection",
        "py/trust-boundary-violation",
    ],
)
def test_rule_id_resolves_to_exact_match(loader: QuestionsLoader, rule_id: str):
    """Each rule_id must hit the loader's exact-match path, not fall to default."""
    _, match_type = loader.get_questions_with_match_info(rule_id)
    assert match_type == "exact", f"{rule_id} fell to {match_type!r}"


def test_alias_shares_canonical_question_body(loader: QuestionsLoader):
    """YAML anchors mean the alias key returns the SAME GuidedQuestions object
    as the canonical key — no silent fork between the two."""
    canon, _ = loader.get_questions_with_match_info("java/weak-cryptographic-algorithm")
    alias, _ = loader.get_questions_with_match_info("java/weak-cryptographic-hash")
    assert canon.questions == alias.questions
    assert canon.additional_context == alias.additional_context
    assert canon.min_iterations == alias.min_iterations


def test_cwe_501_maps_to_trust_boundary(loader: QuestionsLoader):
    """CWE-501 was unmapped before; ensure the cwe_question_map fallback
    fires for a fictional rule_id when the CWE is supplied."""
    _, match_type = loader.get_questions_with_match_info(
        "java/some-future-trust-boundary-name",
        cwe_ids=["CWE-501"],
        lang="java",
    )
    assert match_type == "cwe"


# ── API-error counter regressions ─────────────────────────────────────────────

def test_pred_api_error_count_marks_litellm_failures():
    from benchmarks.adapters.ground_truth import LABEL_TP, GroundTruthEntry
    from benchmarks.approaches.base import PRED_ERROR, BenchmarkResult
    from benchmarks.metrics.evaluator import evaluate

    def _mk(reason: str) -> BenchmarkResult:
        return BenchmarkResult(
            entry=GroundTruthEntry(
                id="e", source_dataset="test", cwe_id="CWE-79", rule_id="java/xss",
                file_path="f.java", function_name="fn", start_line=1, lang="java",
                label=LABEL_TP, code_snippet="//",
            ),
            predicted_label=PRED_ERROR,
            confidence="",
            reasoning=reason,
            elapsed_seconds=0.0,
            iterations=0,
        )

    results = [
        _mk("LLM call failed: litellm.BadRequestError: OpenAIException - Insufficient Balance"),
        _mk("Rate limit hit"),
        _mk("Some unrelated parse failure with no API marker"),
    ]
    m = evaluate(results, approach_name="test", dataset_name="test", nmd_handling="exclude")
    assert m.pred_error == 3
    assert m.pred_api_error_count == 2  # only the two API-marked errors

    summary = m.summary_dict()
    assert summary["pred_error"] == 3
    assert summary["pred_api_error_count"] == 2
    assert summary["total_processed"] == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
