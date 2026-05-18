# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the SecLLMHolmes benchmark dataset.

SecLLMHolmes: LLMs Cannot Reliably Identify and Reason About Security Vulnerabilities (Yet?)
  Paper: https://arxiv.org/abs/2312.12575
  Code:  https://github.com/ai4cloudops/SecLLMHolmes

Dataset structure (after cloning):
    SecLLMHolmes/
    └── datasets/
        ├── hand-crafted/dataset/CWE-416/{1.c, p_1.c, ...}
        ├── augmented/trivial/A*/dataset/CWE-416/{1.c, p_1.c, ...}
        ├── augmented/non-trivial/A*/dataset/CWE-416/{1.c, p_1.c, ...}
        └── real-world/<project>/...

    Naming convention:
        p_*.c / p_*.py  → patched (safe) code  → label=FP
        *.c / *.py      → vulnerable code       → label=TP

Usage:
    from benchmarks.adapters.secllmholmes_adapter import SecLLMHolmesAdapter
    adapter = SecLLMHolmesAdapter(Path("benchmarks/datasets/secllmholmes"))
    entries = adapter.load()
"""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path

from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import DatasetAdapter, register_adapter

logger = logging.getLogger(__name__)

# SecLLMHolmes covers 8 CWE classes (from the actual dataset)
_SECLLMHOLMES_CWES = {
    "CWE-22", "CWE-77", "CWE-79", "CWE-89",
    "CWE-190", "CWE-416", "CWE-476", "CWE-787",
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


@register_adapter
class SecLLMHolmesAdapter(DatasetAdapter):
    """Parse SecLLMHolmes scenarios into GroundTruthEntry objects.

    Expects the repo to be cloned at `dataset_path` (the repo root or
    the `datasets/` directory inside it).
    """

    name = "secllmholmes"
    langs = ("c", "cpp", "python", "javascript", "php")
    family = "academic"
    option_schema: dict = {}
    install_url = "https://github.com/Ahmed-Ucsd/SecLLMHolmes.git"
    expected_files = ("datasets",)

    def __init__(self, dataset_path: Path) -> None:
        self.dataset_path = Path(dataset_path)

    def _find_dataset_dirs(self) -> list[Path]:
        """Find all ``dataset/`` directories containing CWE-* subdirs."""
        root = self.dataset_path
        # Look for a top-level ``datasets/`` container first
        inner = root / "datasets"
        if inner.is_dir():
            root = inner

        dataset_dirs: list[Path] = []
        for candidate in root.rglob("dataset"):
            if not candidate.is_dir():
                continue
            has_cwe = any(
                d.is_dir() and d.name.startswith("CWE-")
                for d in candidate.iterdir()
            )
            if has_cwe:
                dataset_dirs.append(candidate)

        if not dataset_dirs:
            raise FileNotFoundError(
                f"Cannot find any dataset/ directories with CWE-* entries "
                f"under {self.dataset_path}."
            )
        return sorted(dataset_dirs)

    def load(self, limit: int = 0) -> list[GroundTruthEntry]:
        """Load all scenarios from the SecLLMHolmes dataset.

        Args:
            limit: Maximum number of entries to load (0 = all).

        Returns:
            List of GroundTruthEntry with label TP (vulnerable) or FP (patched).
        """
        dataset_dirs = self._find_dataset_dirs()
        entries: list[GroundTruthEntry] = []

        for ds_dir in dataset_dirs:
            # Derive variant name from path, e.g. "hand-crafted" or "augmented/trivial/A6"
            try:
                variant = str(ds_dir.parent.relative_to(
                    self.dataset_path / "datasets"
                ))
            except ValueError:
                variant = str(ds_dir.parent.relative_to(self.dataset_path))

            for cwe_dir in sorted(ds_dir.iterdir()):
                if not cwe_dir.is_dir() or not cwe_dir.name.startswith("CWE-"):
                    continue
                cwe_id = cwe_dir.name  # e.g., "CWE-416"

                for code_file in sorted(cwe_dir.iterdir()):
                    if not code_file.is_file():
                        continue
                    if code_file.suffix.lower() not in _LANG_MAP:
                        continue

                    lang = _LANG_MAP[code_file.suffix.lower()]
                    # Pick the rule whose prefix matches this file's language
                    # so per-rule and per-language metrics line up.
                    rule_id = primary_rule_for_lang(cwe_id, lang)
                    # p_ prefix = patched (safe), otherwise vulnerable
                    label = LABEL_FP if code_file.name.startswith("p_") else LABEL_TP

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
                                "variant": variant,
                                "filename": code_file.name,
                            },
                        )
                    )

                    if limit and len(entries) >= limit:
                        return entries

        logger.info("SecLLMHolmes: loaded %d entries from %s", len(entries), self.dataset_path)
        return entries
