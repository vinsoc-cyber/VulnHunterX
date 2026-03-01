"""Adapter for the SecLLMHolmes benchmark dataset.

SecLLMHolmes: LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?)
  Paper: https://arxiv.org/abs/2312.12575
  Code:  https://github.com/ai4cloudops/SecLLMHolmes

Dataset structure (after cloning):
    SecLLMHolmes/
    └── datasets/
        └── <CWE-ID>/
            └── <complexity>/
                ├── good/     # safe code (label=FP relative to SAST)
                └── bad/      # vulnerable code (label=TP)

Usage:
    from benchmarks.adapters.secllmholmes_adapter import SecLLMHolmesAdapter
    adapter = SecLLMHolmesAdapter(Path("benchmarks/datasets/secllmholmes"))
    entries = adapter.load()
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from benchmarks.adapters.cwe_rule_map import primary_rule
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry

logger = logging.getLogger(__name__)

# SecLLMHolmes covers 8 CWE classes (from the paper)
_SECLLMHOLMES_CWES = {
    "CWE-416", "CWE-476", "CWE-119", "CWE-190", "CWE-78",
    "CWE-89", "CWE-134", "CWE-401",
}

# Language detection from file extension
_LANG_MAP: dict[str, str] = {
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".php": "php",
}


class SecLLMHolmesAdapter:
    """Parse SecLLMHolmes scenarios into GroundTruthEntry objects.

    Expects the repo to be cloned at `dataset_path` (the repo root or
    the `datasets/` directory inside it).
    """

    def __init__(self, dataset_path: Path) -> None:
        self.dataset_path = Path(dataset_path)

    def _find_datasets_dir(self) -> Path:
        """Locate the datasets/ directory (handle cloned repo vs. inner dir)."""
        # If path itself contains CWE dirs, use as-is
        cwe_dirs = [d for d in self.dataset_path.iterdir() if d.is_dir() and d.name.startswith("CWE-")]
        if cwe_dirs:
            return self.dataset_path
        # Look one level deeper
        inner = self.dataset_path / "datasets"
        if inner.is_dir():
            return inner
        raise FileNotFoundError(
            f"Cannot find datasets directory under {self.dataset_path}. "
            "Expected CWE-* subdirectories or a 'datasets/' folder."
        )

    def load(self, limit: int = 0) -> list[GroundTruthEntry]:
        """Load all scenarios from the SecLLMHolmes dataset.

        Args:
            limit: Maximum number of entries to load (0 = all).

        Returns:
            List of GroundTruthEntry with label TP (bad/) or FP (good/).
        """
        datasets_dir = self._find_datasets_dir()
        entries: list[GroundTruthEntry] = []

        for cwe_dir in sorted(datasets_dir.iterdir()):
            if not cwe_dir.is_dir() or not cwe_dir.name.startswith("CWE-"):
                continue
            cwe_id = cwe_dir.name  # e.g., "CWE-416"
            rule_id = primary_rule(cwe_id)

            for complexity_dir in sorted(cwe_dir.iterdir()):
                if not complexity_dir.is_dir():
                    continue

                for label_dir, label in (("bad", LABEL_TP), ("good", LABEL_FP)):
                    code_dir = complexity_dir / label_dir
                    if not code_dir.is_dir():
                        continue

                    for code_file in sorted(code_dir.glob("*")):
                        if not code_file.is_file():
                            continue
                        lang = _LANG_MAP.get(code_file.suffix.lower(), "c")
                        try:
                            snippet = code_file.read_text(encoding="utf-8", errors="replace")
                        except OSError:
                            logger.warning("Cannot read %s; skipping", code_file)
                            continue

                        entry_id = hashlib.md5(  # noqa: S324
                            str(code_file).encode()
                        ).hexdigest()[:12]

                        entries.append(
                            GroundTruthEntry(
                                id=f"slh_{entry_id}",
                                source_dataset="secllmholmes",
                                cwe_id=cwe_id,
                                rule_id=rule_id,
                                file_path=str(code_file.relative_to(self.dataset_path)),
                                function_name="",
                                start_line=1,
                                lang=lang,
                                label=label,
                                code_snippet=snippet,
                                metadata={
                                    "complexity": complexity_dir.name,
                                    "filename": code_file.name,
                                },
                            )
                        )

                        if limit and len(entries) >= limit:
                            return entries

        logger.info("SecLLMHolmes: loaded %d entries from %s", len(entries), datasets_dir)
        return entries
