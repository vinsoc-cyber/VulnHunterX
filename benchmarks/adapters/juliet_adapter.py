# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the Juliet C/C++ Test Suite (NIST SARD).

Juliet C/C++ 1.3.1: https://samate.nist.gov/SARD/test-suites
  - 64,099 test cases across ~180 CWEs
  - Each test case has bad() (vulnerable) and good() (safe) functions
  - Naming convention: *_bad.c / *_good.c or inline bad()/good() functions

Two operational modes:
  OFFLINE: synthesize Finding objects from filename convention without running CodeQL.
  FULL:    run CodeQL on Juliet source and cross-reference SARIF with bad/good functions.

Usage:
    from benchmarks.adapters.juliet_adapter import JulietAdapter
    adapter = JulietAdapter(Path("benchmarks/datasets/juliet"))
    entries = adapter.load(mode="offline")
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

from benchmarks.adapters.cwe_rule_map import CWE_TO_RULES, primary_rule, primary_rule_for_lang
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry

logger = logging.getLogger(__name__)

# Juliet CWEs with CodeQL rules — full target set
TARGET_CWES = {
    "CWE416", "CWE476", "CWE190", "CWE119", "CWE787",
    "CWE78", "CWE22", "CWE125", "CWE134", "CWE401",
    "CWE415", "CWE457", "CWE193", "CWE170", "CWE197",
}

# 8 CWEs with cross-benchmark overlap (SecLLMHolmes + LLM4FPM) — default for cost-effective runs
BENCHMARK_CWES = {
    "CWE416",  # Use After Free        — SecLLMHolmes + LLM4FPM
    "CWE476",  # NULL Pointer Deref    — SecLLMHolmes + LLM4FPM
    "CWE190",  # Integer Overflow      — SecLLMHolmes
    "CWE787",  # Out-of-Bounds Write   — SecLLMHolmes
    "CWE125",  # Out-of-Bounds Read    — SecLLMHolmes
    "CWE401",  # Memory Leak           — LLM4FPM
    "CWE457",  # Uninitialized Var     — LLM4FPM
    "CWE134",  # Uncontrolled Fmt Str  — SecLLMHolmes
}

# Extract CWE from directory name, e.g., "CWE416_Use_After_Free" → "CWE-416"
_CWE_DIR_RE = re.compile(r"^(CWE\d+)", re.IGNORECASE)


def _dir_to_cwe_id(dirname: str) -> str | None:
    """Extract CWE-NNN from a Juliet directory name."""
    m = _CWE_DIR_RE.match(dirname)
    if not m:
        return None
    raw = m.group(1).upper()  # e.g., "CWE416"
    num = raw[3:]              # e.g., "416"
    return f"CWE-{num}"


def _is_bad_file(path: Path) -> bool:
    name = path.stem.lower()
    return name.endswith("_bad") or name.endswith("bad")


def _is_good_file(path: Path) -> bool:
    name = path.stem.lower()
    return name.endswith("_good") or name.endswith("good") or "_good" in name


def _contains_bad_function(code: str) -> bool:
    """Detect bad() function definition in a file."""
    return bool(re.search(r"\bvoid\s+bad\s*\(", code))


def _contains_good_function(code: str) -> bool:
    """Detect good() function definitions in a file."""
    return bool(re.search(r"\bvoid\s+good\d*\s*\(", code))


class JulietAdapter:
    """Parse Juliet C/C++ test cases into GroundTruthEntry objects.

    Mode "offline": synthesize entries from filename/function conventions.
                    Does not require CodeQL to be installed.
    """

    def __init__(self, dataset_path: Path) -> None:
        self.dataset_path = Path(dataset_path)

    def _find_testcases_dir(self) -> Path:
        """Locate the C test cases directory."""
        # Common layouts: dataset_path/C/testcases/ or dataset_path/testcases/
        for candidate in [
            self.dataset_path / "C" / "testcases",
            self.dataset_path / "testcases",
            self.dataset_path,
        ]:
            if candidate.is_dir():
                # Check it has CWE dirs
                has_cwe = any(
                    d.is_dir() and d.name.upper().startswith("CWE")
                    for d in candidate.iterdir()
                )
                if has_cwe:
                    return candidate
        raise FileNotFoundError(
            f"Cannot find Juliet test cases directory under {self.dataset_path}. "
            "Expected CWE* subdirectories or C/testcases/ layout."
        )

    def load(
        self,
        mode: str = "offline",
        limit: int = 0,
        per_cwe_limit: int = 0,
        benchmark_cwes_only: bool = True,
    ) -> list[GroundTruthEntry]:
        """Load Juliet test cases.

        Args:
            mode: "offline" (from file/function naming) or "full" (requires CodeQL).
            limit: Overall cap on entries returned (0 = no cap). Applied after per-CWE
                   sampling, so the actual count may be less than this value.
            per_cwe_limit: Max entries per CWE, balanced TP/FP (max(1, per_cwe_limit // 2) each).
                           0 = load all entries for each CWE.
                           Default 0 (unlimited). Recommended: 20 for standard runs.
            benchmark_cwes_only: When True (default), restrict to the 8-CWE BENCHMARK_CWES
                                 set (SecLLMHolmes + LLM4FPM overlap) for cost-effective runs.
                                 Set False to use the full 15-CWE TARGET_CWES set.

        Returns:
            List of GroundTruthEntry with TP (bad) or FP (good) labels.
        """
        if mode == "full":
            logger.warning(
                "Juliet 'full' mode requires CodeQL; falling back to 'offline'."
            )
        return self._load_offline(limit, per_cwe_limit, benchmark_cwes_only)

    def _load_offline(
        self,
        limit: int,
        per_cwe_limit: int = 0,
        benchmark_cwes_only: bool = True,
    ) -> list[GroundTruthEntry]:
        """Synthesize entries from filename conventions (no CodeQL required)."""
        testcases_dir = self._find_testcases_dir()
        entries: list[GroundTruthEntry] = []
        active_cwes = BENCHMARK_CWES if benchmark_cwes_only else TARGET_CWES

        for cwe_dir in sorted(testcases_dir.iterdir()):
            if not cwe_dir.is_dir():
                continue
            raw_name = cwe_dir.name
            if not raw_name.upper().startswith("CWE"):
                continue

            cwe_id = _dir_to_cwe_id(raw_name)
            if cwe_id is None:
                continue

            # Skip CWEs not in our active set
            cwe_no_dash = cwe_id.replace("-", "")  # "CWE416"
            if cwe_no_dash not in active_cwes:
                continue

            cwe_entries: list[GroundTruthEntry] = []

            for c_file in sorted(cwe_dir.rglob("*.c")) + sorted(cwe_dir.rglob("*.cpp")):
                lang = "cpp" if c_file.suffix == ".cpp" else "c"
                rule_id = primary_rule_for_lang(cwe_id, lang)
                try:
                    code = c_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue

                rel_path = str(c_file.relative_to(self.dataset_path))

                # Determine labels from filename convention
                candidates: list[tuple[str, str]] = []

                if _is_bad_file(c_file):
                    candidates.append((LABEL_TP, "bad()"))
                elif _is_good_file(c_file):
                    candidates.append((LABEL_FP, "good()"))
                else:
                    # Mixed file: may have both bad() and good()
                    if _contains_bad_function(code):
                        candidates.append((LABEL_TP, "bad()"))
                    if _contains_good_function(code):
                        candidates.append((LABEL_FP, "good()"))

                for label, func_name in candidates:
                    entry_id = hashlib.md5(  # noqa: S324
                        f"{rel_path}:{label}".encode()
                    ).hexdigest()[:12]

                    cwe_entries.append(
                        GroundTruthEntry(
                            id=f"juliet_{entry_id}",
                            source_dataset="juliet",
                            cwe_id=cwe_id,
                            rule_id=rule_id,
                            file_path=rel_path,
                            function_name=func_name,
                            start_line=1,
                            lang=lang,
                            label=label,
                            code_snippet=code[:8000],  # cap for LLM context
                            metadata={
                                "cwe_dir": raw_name,
                                "filename": c_file.name,
                            },
                        )
                    )

            # Apply per-CWE balanced sampling
            if per_cwe_limit and cwe_entries:
                half = max(1, per_cwe_limit // 2)
                tp_entries = [e for e in cwe_entries if e.label == LABEL_TP][:half]
                fp_entries = [e for e in cwe_entries if e.label == LABEL_FP][:half]
                cwe_entries = tp_entries + fp_entries
                logger.debug(
                    "Juliet %s: sampled %d TP + %d FP (from %d total)",
                    cwe_id, len(tp_entries), len(fp_entries), len(cwe_entries),
                )

            entries.extend(cwe_entries)

        # Apply overall cap after per-CWE sampling
        if limit:
            entries = entries[:limit]

        logger.info(
            "Juliet: loaded %d entries (per_cwe_limit=%d, benchmark_cwes_only=%s)",
            len(entries), per_cwe_limit, benchmark_cwes_only,
        )
        return entries
