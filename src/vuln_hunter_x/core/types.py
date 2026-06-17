# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Core data types for the SAST + LLM verification framework."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class VerdictType(Enum):
    """Possible verdict outcomes from LLM analysis."""

    TRUE_POSITIVE = "True Positive"
    FALSE_POSITIVE = "False Positive"
    NEEDS_MORE_DATA = "Needs More Data"
    ERROR = "Error"


class ConfidenceLevel(Enum):
    """Confidence level of the verdict."""

    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"


@dataclass
class Finding:
    """A static analysis finding from SARIF output (CodeQL, Semgrep, etc.)."""

    rule_id: str
    message: str
    file: str
    start_line: int
    end_line: int
    repo_name: str
    lang: str
    sarif_path: str = ""
    tool: str = ""
    dataflow_path: list[str] = field(default_factory=list)
    severity: str = ""
    precision: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    related_locations: list[str] = field(default_factory=list)

    @property
    def location(self) -> str:
        """Return a formatted location string."""
        return f"{self.file}:{self.start_line}"

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "rule_id": self.rule_id,
            "message": self.message,
            "file": self.file,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "repo_name": self.repo_name,
            "lang": self.lang,
            "sarif_path": self.sarif_path,
            "tool": self.tool,
            "dataflow_path": self.dataflow_path,
            "severity": self.severity,
            "precision": self.precision,
            "cwe_ids": self.cwe_ids,
            "tags": self.tags,
            "related_locations": self.related_locations,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Finding:
        """Create Finding from dictionary."""
        return cls(
            rule_id=data.get("rule_id", ""),
            message=data.get("message", ""),
            file=data.get("file", ""),
            start_line=data.get("start_line", 0),
            end_line=data.get("end_line", 0),
            repo_name=data.get("repo_name", ""),
            lang=data.get("lang", ""),
            sarif_path=data.get("sarif_path", ""),
            tool=data.get("tool", ""),
            dataflow_path=data.get("dataflow_path", []),
            severity=data.get("severity", ""),
            precision=data.get("precision", ""),
            cwe_ids=data.get("cwe_ids", []),
            tags=data.get("tags", []),
            related_locations=data.get("related_locations", []),
        )


@dataclass
class GuidedQuestions:
    """Guided questions for a specific static analysis rule."""

    rule_id: str
    short_description: str
    questions: list[str]
    context_hint: str = ""
    additional_context: list[str] = field(default_factory=list)
    min_iterations: int = 1
    snippet_window_lines: int | None = None

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "rule_id": self.rule_id,
            "short_description": self.short_description,
            "questions": self.questions,
            "context_hint": self.context_hint,
            "additional_context": self.additional_context,
            "min_iterations": self.min_iterations,
            "snippet_window_lines": self.snippet_window_lines,
        }


@dataclass
class CodeContext:
    """Code context extracted for a finding."""

    code: str
    function_name: str
    start_line: int
    end_line: int
    file_path: str = ""

    @property
    def line_count(self) -> int:
        """Return the number of lines in the context."""
        return len(self.code.splitlines())


@dataclass
class Verdict:
    """LLM verdict for a finding.

    Attributes:
        confidence_score: Numeric confidence (0.0-1.0). Extracted from LLM response
            if available; otherwise mapped from categorical confidence
            (High=0.85, Medium=0.6, Low=0.3).
    """

    finding: Finding
    verdict: str
    confidence: str
    reasoning: str
    answers: list[str]
    raw_response: str
    model: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    elapsed_seconds: float = 0.0
    context_needed: list[str] = field(default_factory=list)
    iterations: int = 1
    tokens_used: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    # Subset of input_tokens that hit the provider's prompt cache, as
    # reported by the provider (e.g. DeepSeek / OpenAI cached_tokens).
    cached_input_tokens: int = 0
    cost_usd: float = 0.0
    confidence_score: float = 0.0
    data_flow: str = ""

    @property
    def is_true_positive(self) -> bool:
        """Check if verdict is True Positive."""
        return self.verdict == VerdictType.TRUE_POSITIVE.value

    @property
    def is_false_positive(self) -> bool:
        """Check if verdict is False Positive."""
        return self.verdict == VerdictType.FALSE_POSITIVE.value

    @property
    def needs_more_data(self) -> bool:
        """Check if verdict needs more data."""
        return self.verdict == VerdictType.NEEDS_MORE_DATA.value

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "finding": self.finding.to_dict(),
            "verdict": self.verdict,
            "confidence": self.confidence,
            "confidence_score": self.confidence_score,
            "reasoning": self.reasoning,
            "answers": self.answers,
            "context_needed": self.context_needed,
            "iterations": self.iterations,
            "model": self.model,
            "timestamp": self.timestamp,
            "elapsed_seconds": self.elapsed_seconds,
            "tokens_used": self.tokens_used,
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "cached_input_tokens": self.cached_input_tokens,
            "cost_usd": self.cost_usd,
            "data_flow": self.data_flow,
        }

    @classmethod
    def from_dict(cls, data: dict) -> Verdict:
        """Create Verdict from dictionary."""
        return cls(
            finding=Finding.from_dict(data.get("finding", {})),
            verdict=data.get("verdict", ""),
            confidence=data.get("confidence", ""),
            reasoning=data.get("reasoning", ""),
            answers=data.get("answers", []),
            raw_response=data.get("raw_response", ""),
            model=data.get("model", ""),
            timestamp=data.get("timestamp", ""),
            elapsed_seconds=data.get("elapsed_seconds", 0.0),
            context_needed=data.get("context_needed", []),
            iterations=data.get("iterations", 1),
            tokens_used=data.get("tokens_used", 0),
            input_tokens=data.get("input_tokens", 0),
            output_tokens=data.get("output_tokens", 0),
            cached_input_tokens=data.get("cached_input_tokens", 0),
            cost_usd=data.get("cost_usd", 0.0),
            confidence_score=data.get("confidence_score", 0.0),
            data_flow=data.get("data_flow", ""),
        )


@dataclass
class VerificationResult:
    """Complete result of a verification run."""

    verdicts: list[Verdict]
    stats: dict[str, int]
    model: str
    provider: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    total_time_seconds: float = 0.0

    @property
    def total_findings(self) -> int:
        """Return total number of findings analyzed."""
        return len(self.verdicts)

    @property
    def true_positive_count(self) -> int:
        """Return count of True Positive verdicts."""
        return self.stats.get("True Positive", 0)

    @property
    def false_positive_count(self) -> int:
        """Return count of False Positive verdicts."""
        return self.stats.get("False Positive", 0)

    @property
    def false_positive_rate(self) -> float:
        """Return false positive rate as percentage."""
        if self.total_findings == 0:
            return 0.0
        return (self.false_positive_count / self.total_findings) * 100

    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "timestamp": self.timestamp,
            "provider": self.provider,
            "model": self.model,
            "total_findings": self.total_findings,
            "total_time_seconds": self.total_time_seconds,
            "stats": self.stats,
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


@dataclass
class RepositoryInfo:
    """Information about a repository for analysis."""

    name: str
    url: str
    lang: str
    build_command: str | None = None
    local_path: str | None = None
    database_path: str | None = None
