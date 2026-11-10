# SPDX-License-Identifier: LGPL-2.1-only
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
from benchmarks.adapters.perturbation import KINDS, perturb_entry
from benchmarks.adapters.registry import (
    DatasetAdapter,
    OptionSpec,
    _to_bool,
    _to_csv_list,
    register_adapter,
)

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
    option_schema = {
        "perturb": OptionSpec(
            _to_csv_list,
            default=None,
            help="Comma list of perturbation kinds ("
            + ",".join(KINDS)
            + "); emits extra copies with ids '<id>__<kind>' "
            "(metadata.perturbation) for verdict-flip-rate analysis.",
        ),
        "perturb_seed": OptionSpec(int, default=0, help="Seed for perturbations."),
        "aug_as_perturbation": OptionSpec(
            _to_bool,
            default=False,
            help="Tag the dataset's own augmented/ variants as perturbations "
            "(metadata.perturbation.kind='secllmholmes-aug', original_id = the "
            "hand-crafted entry with the same CWE and filename, if any).",
        ),
    }
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

    def load(
        self,
        limit: int = 0,
        perturb: list[str] | None = None,
        perturb_seed: int = 0,
        aug_as_perturbation: bool = False,
    ) -> list[GroundTruthEntry]:
        """Load scenarios, optionally with perturbed copies / tagged aug variants.

        ``limit`` caps base entries; perturbed copies are appended after it.
        Defaults leave behaviour unchanged.
        """
        entries = self._load_base(limit)
        if aug_as_perturbation:
            originals = {
                (e.cwe_id, e.metadata["filename"]): e.id
                for e in entries
                if e.metadata["variant"] == "hand-crafted"
            }
            for e in entries:
                if str(e.metadata["variant"]).startswith("augmented"):
                    e.metadata["perturbation"] = {
                        "kind": "secllmholmes-aug",
                        "seed": None,
                        "original_id": originals.get((e.cwe_id, e.metadata["filename"])),
                        "variant": e.metadata["variant"],
                        "applied": True,
                    }
        if perturb:
            bad = [k for k in perturb if k not in KINDS]
            if bad:
                raise ValueError(f"unknown perturbation kinds {bad}; valid: {list(KINDS)}")
            base = [e for e in entries if "perturbation" not in e.metadata]
            for kind in perturb:
                entries.extend(perturb_entry(e, kind, perturb_seed) for e in base)
        return entries

    def _load_base(self, limit: int = 0) -> list[GroundTruthEntry]:
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
