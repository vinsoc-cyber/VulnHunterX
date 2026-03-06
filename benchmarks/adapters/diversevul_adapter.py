"""Adapter for the DiverseVul dataset (RAID 2023).

Source: https://github.com/wagner-group/diversevul
Format: JSON lines — {func, target, cwe, project, commit_id}

DiverseVul contains 18,945 vulnerable + 330,492 non-vulnerable C/C++ functions
across 150 CWEs, with real CVE-backed labels.

Usage:
    from benchmarks.adapters.diversevul_adapter import DiverseVulAdapter
    adapter = DiverseVulAdapter(Path("benchmarks/datasets/diversevul"))
    entries = adapter.load(limit=100)
"""

from __future__ import annotations

import hashlib
import json
import logging
from pathlib import Path

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry

logger = logging.getLogger(__name__)

# Max code snippet length (same as JulietAdapter)
_MAX_SNIPPET_CHARS = 8000


class DiverseVulAdapter:
    """Adapter for the DiverseVul dataset."""

    def __init__(self, dataset_path: Path) -> None:
        self.dataset_path = Path(dataset_path)

    def _find_data_file(self) -> Path | None:
        """Find the DiverseVul JSON data file."""
        # Try common filenames
        for name in [
            "diversevul_20230702.json",
            "diversevul.json",
            "data.json",
        ]:
            candidate = self.dataset_path / name
            if candidate.is_file():
                return candidate
        # Try any .json file
        json_files = list(self.dataset_path.glob("*.json"))
        if json_files:
            return json_files[0]
        # Try JSON lines file
        jsonl_files = list(self.dataset_path.glob("*.jsonl"))
        if jsonl_files:
            return jsonl_files[0]
        return None

    def load(
        self,
        limit: int = 0,
        cwes: list[str] | None = None,
    ) -> list[GroundTruthEntry]:
        """Load entries from DiverseVul dataset.

        Args:
            limit: Maximum entries to load (0 = all).
            cwes: Optional list of CWE IDs to filter (e.g. ["CWE-787", "CWE-416"]).

        Returns:
            List of GroundTruthEntry objects.
        """
        data_file = self._find_data_file()
        if data_file is None:
            raise FileNotFoundError(
                f"DiverseVul data file not found in {self.dataset_path}. "
                "Download from: https://github.com/wagner-group/diversevul"
            )

        logger.info("Loading DiverseVul from %s", data_file)
        entries: list[GroundTruthEntry] = []
        seen_hashes: set[str] = set()

        cwe_filter = set(cwes) if cwes else None

        with open(data_file, encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    # Try loading as a full JSON array on the first line
                    if line_no == 1 and line.startswith("["):
                        f.seek(0)
                        records = json.load(f)
                        for rec in records:
                            entry = self._record_to_entry(rec, seen_hashes, cwe_filter)
                            if entry is not None:
                                entries.append(entry)
                                if limit and len(entries) >= limit:
                                    break
                        break
                    continue

                entry = self._record_to_entry(record, seen_hashes, cwe_filter)
                if entry is not None:
                    entries.append(entry)
                    if limit and len(entries) >= limit:
                        break

        logger.info(
            "Loaded %d entries from DiverseVul (%d TP, %d FP)",
            len(entries),
            sum(1 for e in entries if e.label == LABEL_TP),
            sum(1 for e in entries if e.label == LABEL_FP),
        )
        return entries

    def _record_to_entry(
        self,
        record: dict,
        seen_hashes: set[str],
        cwe_filter: set[str] | None,
    ) -> GroundTruthEntry | None:
        """Convert a single DiverseVul record to a GroundTruthEntry."""
        func = record.get("func", "")
        if not func:
            return None

        # Normalize CWE
        cwe_raw = str(record.get("cwe", "")).strip()
        if cwe_raw and not cwe_raw.upper().startswith("CWE-"):
            cwe_id = f"CWE-{cwe_raw}"
        else:
            cwe_id = cwe_raw.upper() if cwe_raw else "Unknown"

        # Apply CWE filter
        if cwe_filter and cwe_id not in cwe_filter:
            return None

        # Deduplicate by function hash
        func_hash = hashlib.md5(func.encode(), usedforsecurity=False).hexdigest()[:12]
        if func_hash in seen_hashes:
            return None
        seen_hashes.add(func_hash)

        # Map target to label
        target = record.get("target", 0)
        label = LABEL_TP if target == 1 else LABEL_FP

        # Cap snippet length
        code_snippet = func[:_MAX_SNIPPET_CHARS]

        return GroundTruthEntry(
            id=f"dvul_{func_hash}",
            source_dataset="diversevul",
            cwe_id=cwe_id,
            rule_id="",
            file_path=record.get("file", ""),
            function_name=record.get("func_name", ""),
            start_line=1,
            lang="c",
            label=label,
            code_snippet=code_snippet,
            metadata={
                "project": record.get("project", ""),
                "commit_id": record.get("commit_id", ""),
            },
        )
