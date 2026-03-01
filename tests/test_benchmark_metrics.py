"""Unit tests for benchmark metrics evaluator."""

from __future__ import annotations

from benchmarks.adapters.ground_truth import (
    LABEL_BENIGN,
    LABEL_FP,
    LABEL_TP,
    GroundTruthEntry,
)
from benchmarks.approaches.base import (
    PRED_ERROR,
    PRED_FP,
    PRED_NMD,
    PRED_TP,
    BenchmarkResult,
)
from benchmarks.metrics.evaluator import evaluate


def _entry(label: str, cwe: str = "CWE-416", i: int = 0) -> GroundTruthEntry:
    return GroundTruthEntry(
        id=f"e{i}",
        source_dataset="test",
        cwe_id=cwe,
        rule_id="cpp/use-after-free",
        file_path="f.c",
        function_name="fn",
        start_line=1,
        lang="c",
        label=label,
        code_snippet="code",
    )


def _result(
    entry: GroundTruthEntry,
    predicted: str,
    confidence: str = "High",
    elapsed: float = 0.1,
    iterations: int = 1,
) -> BenchmarkResult:
    return BenchmarkResult(
        entry=entry,
        predicted_label=predicted,
        confidence=confidence,
        reasoning="test",
        elapsed_seconds=elapsed,
        iterations=iterations,
    )


class TestEvaluatorBasic:
    def test_perfect_precision_recall(self):
        """All TP entries predicted TP, all FP entries predicted FP."""
        tp1 = _entry(LABEL_TP, i=0)
        fp1 = _entry(LABEL_FP, i=1)
        results = [
            _result(tp1, PRED_TP),
            _result(fp1, PRED_FP),
        ]
        m = evaluate(results, "test", "dataset")
        assert m.precision == 1.0
        assert m.recall == 1.0
        assert m.f1 == 1.0

    def test_all_false_positive_predictions(self):
        """All TP entries predicted FP → recall=0, precision=None (no TP predictions)."""
        entries = [_entry(LABEL_TP, i=i) for i in range(3)]
        results = [_result(e, PRED_FP) for e in entries]
        m = evaluate(results, "test", "dataset")
        assert m.recall == 0.0
        assert m.precision is None  # no TP predictions → denominator = 0

    def test_all_false_negative_predictions(self):
        """All FP entries predicted TP → precision=0, recall=None."""
        entries = [_entry(LABEL_FP, i=i) for i in range(3)]
        results = [_result(e, PRED_TP) for e in entries]
        m = evaluate(results, "test", "dataset")
        assert m.fp_missed == 3
        assert m.tp_correct == 0
        # precision = tp_correct / (tp_correct + fp_missed) = 0/3 = 0
        assert m.precision == 0.0

    def test_f1_score(self):
        """F1 = 2 * P * R / (P + R)."""
        results = [
            _result(_entry(LABEL_TP, i=0), PRED_TP),  # tp_correct
            _result(_entry(LABEL_TP, i=1), PRED_FP),  # tp_missed (fn)
            _result(_entry(LABEL_FP, i=2), PRED_FP),  # fp_caught (tn)
            _result(_entry(LABEL_FP, i=3), PRED_TP),  # fp_missed (fp)
        ]
        m = evaluate(results, "test", "dataset")
        # precision = 1/(1+1) = 0.5
        # recall = 1/(1+1) = 0.5
        assert m.precision == pytest.approx(0.5)
        assert m.recall == pytest.approx(0.5)
        assert m.f1 == pytest.approx(0.5)

    def test_benign_excluded_from_accuracy(self):
        """BENIGN entries do not affect precision/recall."""
        results = [
            _result(_entry(LABEL_TP, i=0), PRED_TP),
            _result(_entry(LABEL_BENIGN, i=1), PRED_TP),  # should be ignored
        ]
        m = evaluate(results, "test", "dataset")
        assert m.total_evaluated == 1  # only the TP entry counts
        assert m.precision == 1.0
        assert m.recall == 1.0

    def test_empty_results(self):
        m = evaluate([], "test", "dataset")
        assert m.total_evaluated == 0
        assert m.precision is None
        assert m.recall is None
        assert m.f1 is None


class TestNMDHandling:
    def test_nmd_excluded_by_default(self):
        """NMD results are excluded from precision/recall with nmd_handling='exclude'."""
        tp = _entry(LABEL_TP, i=0)
        results = [
            _result(tp, PRED_TP),
            _result(_entry(LABEL_TP, i=1), PRED_NMD),
        ]
        m = evaluate(results, "test", "dataset", nmd_handling="exclude")
        assert m.total_evaluated == 1
        assert m.pred_nmd == 1
        assert m.nmd_rate == pytest.approx(0.5)

    def test_nmd_treated_as_fp(self):
        """With nmd_handling='fp', NMD is counted as FP prediction."""
        results = [
            _result(_entry(LABEL_TP, i=0), PRED_NMD),
        ]
        m = evaluate(results, "test", "dataset", nmd_handling="fp")
        assert m.pred_nmd == 0
        assert m.tp_missed == 1  # NMD→FP means tp_missed

    def test_error_excluded(self):
        """ERROR results are not counted in precision/recall."""
        results = [
            _result(_entry(LABEL_TP, i=0), PRED_TP),
            _result(_entry(LABEL_TP, i=1), PRED_ERROR),
        ]
        m = evaluate(results, "test", "dataset")
        assert m.total_evaluated == 1
        assert m.pred_error == 1


class TestPerCWEMetrics:
    def test_per_cwe_breakdown(self):
        """Per-CWE metrics are computed separately."""
        r1 = _result(_entry(LABEL_TP, cwe="CWE-416", i=0), PRED_TP)
        r2 = _result(_entry(LABEL_FP, cwe="CWE-416", i=1), PRED_FP)
        r3 = _result(_entry(LABEL_TP, cwe="CWE-89", i=2), PRED_FP)

        m = evaluate([r1, r2, r3], "test", "dataset")

        assert "CWE-416" in m.cwe_metrics
        assert "CWE-89" in m.cwe_metrics

        cwe416 = m.cwe_metrics["CWE-416"]
        assert cwe416.tp_correct == 1
        assert cwe416.fp_caught == 1

        cwe89 = m.cwe_metrics["CWE-89"]
        assert cwe89.tp_missed == 1


class TestCalibration:
    def test_calibration_high_confidence(self):
        """High-confidence correct predictions → calibration.High.accuracy = 1.0."""
        results = [
            _result(_entry(LABEL_TP, i=0), PRED_TP, confidence="High"),
            _result(_entry(LABEL_FP, i=1), PRED_FP, confidence="High"),
        ]
        m = evaluate(results, "test", "dataset")
        assert "High" in m.calibration
        cb = m.calibration["High"]
        assert cb.total == 2
        assert cb.correct == 2
        assert cb.accuracy == 1.0

    def test_calibration_low_confidence_wrong(self):
        """Low-confidence wrong predictions → calibration.Low.accuracy = 0.0."""
        results = [
            _result(_entry(LABEL_TP, i=0), PRED_FP, confidence="Low"),
        ]
        m = evaluate(results, "test", "dataset")
        assert "Low" in m.calibration
        assert m.calibration["Low"].accuracy == 0.0

    def test_calibration_mixed_buckets(self):
        results = [
            _result(_entry(LABEL_TP, i=0), PRED_TP, confidence="High"),
            _result(_entry(LABEL_TP, i=1), PRED_FP, confidence="Low"),
            _result(_entry(LABEL_FP, i=2), PRED_FP, confidence="Medium"),
        ]
        m = evaluate(results, "test", "dataset")
        assert m.calibration["High"].accuracy == 1.0
        assert m.calibration["Low"].accuracy == 0.0
        assert m.calibration["Medium"].accuracy == 1.0


class TestLatencyMetrics:
    def test_latency_stats(self):
        entries = [_entry(LABEL_TP, i=i) for i in range(5)]
        latencies = [0.1, 0.2, 0.3, 0.4, 1.0]
        results = [_result(e, PRED_TP, elapsed=t) for e, t in zip(entries, latencies)]
        m = evaluate(results, "test", "dataset")
        assert m.mean_latency == pytest.approx(sum(latencies) / len(latencies))
        assert m.median_latency == pytest.approx(0.3)
        assert m.p95_latency is not None

    def test_total_elapsed(self):
        entries = [_entry(LABEL_TP, i=i) for i in range(3)]
        results = [_result(e, PRED_TP, elapsed=1.0) for e in entries]
        m = evaluate(results, "test", "dataset")
        assert m.total_elapsed == pytest.approx(3.0)


class TestFPReductionRate:
    def test_fp_reduction(self):
        """FP reduction = (SAST_FPs - approach_FPs) / SAST_FPs."""
        # Raw SAST would predict all 4 FP entries as TP → 4 raw FPs
        # Approach catches 3 of 4 FPs → 1 remains (fp_missed=1)
        results = [
            _result(_entry(LABEL_FP, i=0), PRED_FP),  # caught
            _result(_entry(LABEL_FP, i=1), PRED_FP),  # caught
            _result(_entry(LABEL_FP, i=2), PRED_FP),  # caught
            _result(_entry(LABEL_FP, i=3), PRED_TP),  # missed (fp)
        ]
        m = evaluate(results, "test", "dataset")
        # fp_missed = 1, raw_sast_fp = 4
        rate = m.fp_reduction_rate(raw_sast_fp_count=4)
        assert rate == pytest.approx(0.75)  # (4-1)/4

    def test_fp_reduction_none_when_zero_raw(self):
        m = evaluate([], "test", "dataset")
        assert m.fp_reduction_rate(0) is None


class TestSummaryDict:
    def test_summary_dict_has_required_keys(self):
        results = [
            _result(_entry(LABEL_TP, i=0), PRED_TP),
            _result(_entry(LABEL_FP, i=1), PRED_FP),
        ]
        m = evaluate(results, "approach_name", "dataset_name")
        d = m.summary_dict()
        for key in (
            "approach", "dataset", "precision", "recall", "f1",
            "nmd_rate", "total_evaluated", "calibration", "per_cwe",
        ):
            assert key in d, f"Missing key: {key}"

    def test_summary_dict_with_fp_reduction(self):
        results = [_result(_entry(LABEL_FP, i=0), PRED_FP)]
        m = evaluate(results, "test", "dataset")
        d = m.summary_dict(raw_sast_tp=5, raw_sast_fp=4)
        assert "fp_reduction_rate" in d
        assert "tp_preservation_rate" in d


class TestRawSastApproach:
    def test_raw_sast_always_predicts_tp(self):
        from benchmarks.approaches.raw_sast import RawSastApproach

        approach = RawSastApproach()
        entry = _entry(LABEL_FP)
        result = approach.evaluate(entry)
        assert result.predicted_label == PRED_TP
        assert result.tokens_used == 0
        assert result.cost_usd == 0.0
        assert result.elapsed_seconds >= 0.0

    def test_raw_sast_name(self):
        from benchmarks.approaches.raw_sast import RawSastApproach
        assert RawSastApproach.name == "raw-sast"


class TestApproachBase:
    def test_entry_to_finding_basic(self):
        from benchmarks.approaches.base import entry_to_finding

        entry = _entry(LABEL_TP)
        finding = entry_to_finding(entry)
        assert finding.rule_id == "cpp/use-after-free"
        assert finding.lang == "c"
        assert finding.repo_name == "test"

    def test_entry_to_finding_no_rule_id(self):
        from benchmarks.approaches.base import entry_to_finding

        entry = GroundTruthEntry(
            id="x",
            source_dataset="test",
            cwe_id="CWE-416",
            rule_id="",   # empty
            file_path="f.c",
            function_name="fn",
            start_line=1,
            lang="c",
            label=LABEL_TP,
            code_snippet="",
        )
        finding = entry_to_finding(entry)
        # Falls back to CWE-based rule ID
        assert "cwe416" in finding.rule_id.lower() or "416" in finding.rule_id

    def test_verdict_to_pred_mapping(self):
        from benchmarks.approaches.base import verdict_to_pred

        assert verdict_to_pred("True Positive") == PRED_TP
        assert verdict_to_pred("False Positive") == PRED_FP
        assert verdict_to_pred("Needs More Data") == PRED_NMD
        assert verdict_to_pred("Error") == PRED_ERROR
        assert verdict_to_pred("unknown") == PRED_ERROR


import pytest
