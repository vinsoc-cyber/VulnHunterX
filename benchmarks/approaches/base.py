"""Abstract base class and shared utilities for benchmark approaches."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from vuln_hunter_x.context.extractor import ContextExtractor
from vuln_hunter_x.core.types import CodeContext, Finding

from benchmarks.adapters.ground_truth import GroundTruthEntry

# Predicted label values produced by approaches
PRED_TP = "TP"       # Approach predicted: vulnerable
PRED_FP = "FP"       # Approach predicted: safe / false positive
PRED_NMD = "NMD"     # Approach returned: Needs More Data (inconclusive)
PRED_ERROR = "ERROR" # Approach returned an error

# Map VulnHunterX verdict strings → benchmark prediction labels
_VERDICT_MAP: dict[str, str] = {
    "True Positive": PRED_TP,
    "False Positive": PRED_FP,
    "Needs More Data": PRED_NMD,
    "Error": PRED_ERROR,
}


@dataclass
class BenchmarkResult:
    """The result of one approach evaluating one GroundTruthEntry."""

    entry: GroundTruthEntry
    predicted_label: str   # PRED_TP | PRED_FP | PRED_NMD | PRED_ERROR
    confidence: str        # "High" | "Medium" | "Low" | ""
    reasoning: str
    elapsed_seconds: float
    tokens_used: int = 0
    cost_usd: float = 0.0
    iterations: int = 0
    raw_response: str = ""

    def to_dict(self) -> dict:
        return {
            "entry_id": self.entry.id,
            "source_dataset": self.entry.source_dataset,
            "ground_truth_label": self.entry.label,
            "predicted_label": self.predicted_label,
            "confidence": self.confidence,
            "reasoning": self.reasoning,
            "elapsed_seconds": self.elapsed_seconds,
            "tokens_used": self.tokens_used,
            "cost_usd": self.cost_usd,
            "iterations": self.iterations,
        }


class BenchmarkApproach(ABC):
    """Abstract base for all benchmark approaches."""

    name: str = "unnamed"

    @abstractmethod
    def evaluate(self, entry: GroundTruthEntry) -> BenchmarkResult:
        """Evaluate a single ground truth entry."""
        ...


def entry_to_finding(entry: GroundTruthEntry) -> Finding:
    """Convert a GroundTruthEntry to a VulnHunterX Finding for use with VerificationEngine."""
    return Finding(
        rule_id=entry.rule_id or f"benchmark/{entry.cwe_id.lower().replace('-', '')}",
        message=entry.metadata.get("message", f"{entry.cwe_id or 'vulnerability'} detected"),
        file=entry.file_path or "benchmark_snippet.c",
        start_line=entry.start_line or 1,
        end_line=entry.start_line or 1,
        repo_name=entry.source_dataset,
        lang=entry.lang,
        tool="benchmark",
    )


def verdict_to_pred(verdict_str: str) -> str:
    """Map a VulnHunterX verdict string to a benchmark prediction label."""
    return _VERDICT_MAP.get(verdict_str, PRED_ERROR)


class _SnippetContextExtractor(ContextExtractor):
    """A ContextExtractor that returns an in-memory code snippet.

    Used by benchmark approaches so code from GroundTruthEntry.code_snippet
    is passed directly to the LLM without needing files on disk.
    """

    def __init__(self, code_snippet: str, function_name: str) -> None:
        # Do not call super().__init__ — we bypass disk I/O entirely
        self._snippet = code_snippet
        self._func_name = function_name

    def get_context(self, file_path: str, line: int, lang: str) -> CodeContext:  # type: ignore[override]
        return CodeContext(
            code=self._snippet,
            function_name=self._func_name or "<benchmark>",
            start_line=1,
            end_line=len(self._snippet.splitlines()),
            file_path=file_path,
        )
