"""Core data types for the CodeQL + LLM verification framework."""

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
    """A CodeQL finding from SARIF analysis."""
    rule_id: str
    message: str
    file: str
    start_line: int
    end_line: int
    repo_name: str
    lang: str
    sarif_path: str = ""
    
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
        }


@dataclass
class GuidedQuestions:
    """Guided questions for a specific CodeQL rule."""
    rule_id: str
    short_description: str
    questions: list[str]
    context_hint: str = ""
    additional_context: list[str] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary for serialization."""
        return {
            "rule_id": self.rule_id,
            "short_description": self.short_description,
            "questions": self.questions,
            "context_hint": self.context_hint,
            "additional_context": self.additional_context,
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
    """LLM verdict for a finding."""
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
            "reasoning": self.reasoning,
            "answers": self.answers,
            "context_needed": self.context_needed,
            "iterations": self.iterations,
            "model": self.model,
            "timestamp": self.timestamp,
            "elapsed_seconds": self.elapsed_seconds,
        }


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
