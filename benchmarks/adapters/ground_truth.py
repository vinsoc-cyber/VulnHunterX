# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Ground truth data types and loading utilities for benchmark datasets."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

# Valid label values
LABEL_TP = "TP"       # Code IS vulnerable (ground truth)
LABEL_FP = "FP"       # Code is SAFE but SAST incorrectly flags it
LABEL_BENIGN = "BENIGN"  # Clean code SAST correctly ignores (excluded from precision/recall)


@dataclass
class GroundTruthEntry:
    """A single ground-truth labeled finding from a benchmark dataset.

    Labels:
        TP      — code IS vulnerable (ground truth); SAST correctly flags it
        FP      — code is SAFE but SAST incorrectly flags it (e.g. Juliet good() functions)
        BENIGN  — clean code that SAST correctly ignores; excluded from precision/recall
    """

    id: str
    source_dataset: str    # "secllmholmes" | "juliet" | "diversevul"
    cwe_id: str            # e.g., "CWE-416"
    rule_id: str           # mapped CodeQL/Semgrep rule ID; empty if no mapping
    file_path: str
    function_name: str
    start_line: int
    lang: str              # "c" | "cpp" | "python" | "javascript" | "php"
    label: str             # LABEL_TP | LABEL_FP | LABEL_BENIGN
    code_snippet: str
    metadata: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.label not in (LABEL_TP, LABEL_FP, LABEL_BENIGN):
            raise ValueError(
                f"Invalid label {self.label!r}; must be 'TP', 'FP', or 'BENIGN'"
            )

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "source_dataset": self.source_dataset,
            "cwe_id": self.cwe_id,
            "rule_id": self.rule_id,
            "file_path": self.file_path,
            "function_name": self.function_name,
            "start_line": self.start_line,
            "lang": self.lang,
            "label": self.label,
            "code_snippet": self.code_snippet,
            "metadata": self.metadata,
        }

    @classmethod
    def from_dict(cls, data: dict) -> GroundTruthEntry:
        return cls(
            id=data["id"],
            source_dataset=data["source_dataset"],
            cwe_id=data.get("cwe_id", ""),
            rule_id=data.get("rule_id", ""),
            file_path=data.get("file_path", ""),
            function_name=data.get("function_name", ""),
            start_line=data.get("start_line", 1),
            lang=data.get("lang", "c"),
            label=data["label"],
            code_snippet=data.get("code_snippet", ""),
            metadata=data.get("metadata", {}),
        )


def load_entries(path: Path) -> list[GroundTruthEntry]:
    """Load ground truth entries from a JSON file (list or single object)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return [GroundTruthEntry.from_dict(d) for d in data]
    return [GroundTruthEntry.from_dict(data)]


def save_entries(entries: list[GroundTruthEntry], path: Path) -> None:
    """Save ground truth entries to a JSON file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump([e.to_dict() for e in entries], f, indent=2)
