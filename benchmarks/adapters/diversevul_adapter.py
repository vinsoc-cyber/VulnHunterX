# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

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

from benchmarks.adapters.cwe_rule_map import primary_rule_for_langs
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import (
    DatasetAdapter,
    OptionSpec,
    _to_bool,
    _to_csv_list,
    register_adapter,
)

logger = logging.getLogger(__name__)

# Max code snippet length (same as JulietAdapter)
_MAX_SNIPPET_CHARS = 8000


@register_adapter
class DiverseVulAdapter(DatasetAdapter):
    """Adapter for the DiverseVul dataset."""

    name = "diversevul"
    langs = ("c", "cpp")
    family = "cve"
    option_schema = {
        "cwes": OptionSpec(
            _to_csv_list,
            default=None,
            help="Comma-separated CWE IDs to filter (e.g. CWE-787,CWE-416).",
        ),
        "include_unknown_cwe": OptionSpec(
            _to_bool,
            default=False,
            help="Keep records whose CVE has no CWE mapping (dropped by default).",
        ),
        "negative_fraction": OptionSpec(
            float,
            default=None,
            help="Rebalance to this fraction of target=0 records (e.g. 0.5).",
        ),
    }
    install_url = "https://drive.google.com/uc?id=1-1Lhr-Fp1jB7CRf3lEpoFvz3UPDDfQOj"
    expected_files = ("diversevul_20230702.json",)

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
        include_unknown_cwe: bool = False,
        negative_fraction: float | None = None,
    ) -> list[GroundTruthEntry]:
        """Load entries from DiverseVul dataset.

        Args:
            limit: Maximum entries to load (0 = all).
            cwes: Optional list of CWE IDs to filter (e.g. ["CWE-787", "CWE-416"]).
            include_unknown_cwe: If False (default), drop records whose CVE has
                no CWE mapping. These pollute per-CWE stratification and force
                VulnHunterX's guided-question routing into a generic fallback,
                biasing the rule-specific ablation comparison. Pass True to
                keep the full corpus for binary-classification-only use.
            negative_fraction: If set (0.0–1.0), enforce this fraction of
                target=0 (non-vulnerable / FP-label) records in the returned
                set. Without negatives the FP-Reduction metric is unmeasurable
                because raw-sast achieves 100% precision by construction.
                Defaults to None (no rebalancing — preserves the dataset's
                natural ~5% positive ratio after filtering by CWE).

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
        dropped_unknown_cwe = [0]

        cwe_filter = set(cwes) if cwes else None

        # When negative_fraction is requested, we cannot honour `limit`
        # streaming-fast — we have to load both pools (positive/negative)
        # past `limit` and then rebalance. So in that mode we ignore the
        # streaming early-stop and rebalance at the end.
        rebalance = negative_fraction is not None
        load_limit = 0 if rebalance else limit

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
                            entry = self._record_to_entry(
                                rec, seen_hashes, cwe_filter,
                                include_unknown_cwe, dropped_unknown_cwe,
                            )
                            if entry is not None:
                                entries.append(entry)
                                if load_limit and len(entries) >= load_limit:
                                    break
                        break
                    continue

                entry = self._record_to_entry(
                    record, seen_hashes, cwe_filter,
                    include_unknown_cwe, dropped_unknown_cwe,
                )
                if entry is not None:
                    entries.append(entry)
                    if load_limit and len(entries) >= load_limit:
                        break

        if rebalance:
            entries = self._rebalance(entries, negative_fraction, limit)

        logger.info(
            "Loaded %d entries from DiverseVul (%d TP, %d FP)",
            len(entries),
            sum(1 for e in entries if e.label == LABEL_TP),
            sum(1 for e in entries if e.label == LABEL_FP),
        )
        if dropped_unknown_cwe[0]:
            logger.info(
                "Dropped %d entries with no CWE (pass include_unknown_cwe=True to keep)",
                dropped_unknown_cwe[0],
            )
        return entries

    @staticmethod
    def _rebalance(
        entries: list[GroundTruthEntry],
        negative_fraction: float,
        limit: int,
    ) -> list[GroundTruthEntry]:
        """Return a subset of ``entries`` with the requested negative ratio,
        stratified per CWE.

        Stratification matters because the raw diversevul positive ratio
        varies hugely across CWEs — CWE-264 is ~9% positive, CWE-787 is
        100% positive. A naive global rebalance over-weights whichever CWE
        appears first in the file. Per-CWE stratification gives each CWE a
        fair share of the cap, so per-CWE F1 numbers reflect real signal
        rather than file ordering.

        Deterministic — no random sampling. Within each CWE, the first
        ``n_pos`` positives and first ``n_neg`` negatives are kept (by
        original file order). When ``limit`` is set, the cap is divided
        evenly across CWEs (with any remainder going to CWEs that have
        spare capacity).
        """
        if not 0.0 <= negative_fraction <= 1.0:
            raise ValueError(
                f"negative_fraction must be in [0.0, 1.0], got {negative_fraction!r}"
            )

        # Group by CWE, preserving file order within each group.
        by_cwe: dict[str, dict[str, list[GroundTruthEntry]]] = {}
        for e in entries:
            cwe = e.cwe_id or "Unknown"
            slot = by_cwe.setdefault(cwe, {"pos": [], "neg": []})
            if e.label == LABEL_TP:
                slot["pos"].append(e)
            else:
                slot["neg"].append(e)

        n_cwes = max(len(by_cwe), 1)

        # Per-CWE caps.
        if limit <= 0:
            # No global cap: take all positives in every CWE, then take
            # enough negatives in each CWE to hit the requested ratio
            # (capped by availability).
            out: list[GroundTruthEntry] = []
            for slot in by_cwe.values():
                n_pos = len(slot["pos"])
                n_neg_wanted = int(
                    n_pos * negative_fraction / max(1 - negative_fraction, 1e-6)
                )
                n_neg = min(len(slot["neg"]), n_neg_wanted)
                out.extend(slot["pos"][:n_pos])
                out.extend(slot["neg"][:n_neg])
            return out

        # Global cap: distribute roughly evenly across CWEs. Track shortfalls
        # so a CWE with fewer positives/negatives than its share doesn't
        # waste capacity — redistribute to CWEs that still have slack.
        per_cwe_quota = max(1, limit // n_cwes)
        remainder = limit - per_cwe_quota * n_cwes  # may be negative if n_cwes > limit

        # First pass: take fair share from each CWE.
        out = []
        shortfall_pool: list[GroundTruthEntry] = []
        for slot in by_cwe.values():
            n_neg = int(round(per_cwe_quota * negative_fraction))
            n_pos = per_cwe_quota - n_neg
            n_pos = min(n_pos, len(slot["pos"]))
            n_neg = min(n_neg, len(slot["neg"]))
            out.extend(slot["pos"][:n_pos])
            out.extend(slot["neg"][:n_neg])
            shortfall_pool.extend(slot["pos"][n_pos:])
            shortfall_pool.extend(slot["neg"][n_neg:])

        # Second pass: top up from the shortfall pool to hit `limit`,
        # preserving the requested negative_fraction approximately.
        needed = limit - len(out)
        if needed > 0:
            # Sort the shortfall by label so we can pull positives and
            # negatives in the right ratio.
            pool_pos = [e for e in shortfall_pool if e.label == LABEL_TP]
            pool_neg = [e for e in shortfall_pool if e.label == LABEL_FP]
            n_neg_extra = int(round(needed * negative_fraction))
            n_pos_extra = needed - n_neg_extra
            n_pos_extra = min(n_pos_extra, len(pool_pos))
            n_neg_extra = min(n_neg_extra, len(pool_neg))
            out.extend(pool_pos[:n_pos_extra])
            out.extend(pool_neg[:n_neg_extra])
            # Final greedy top-up if still short (one side exhausted).
            still_needed = limit - len(out)
            if still_needed > 0:
                remaining = pool_pos[n_pos_extra:] + pool_neg[n_neg_extra:]
                out.extend(remaining[:still_needed])
        return out

    def _record_to_entry(
        self,
        record: dict,
        seen_hashes: set[str],
        cwe_filter: set[str] | None,
        include_unknown_cwe: bool,
        dropped_unknown_cwe: list[int],
    ) -> GroundTruthEntry | None:
        """Convert a single DiverseVul record to a GroundTruthEntry."""
        func = record.get("func", "")
        if not func:
            return None

        # Normalize CWE: source field is a list (sometimes empty) per the
        # DiverseVul schema; older variants may also serialise it as a bare
        # string. Pick the primary CWE as the canonical id; keep the full
        # list under metadata.all_cwes so nothing is silently dropped.
        raw_cwe = record.get("cwe", []) or []
        if isinstance(raw_cwe, str):
            cwe_list = [raw_cwe] if raw_cwe.strip() else []
        else:
            cwe_list = [str(c).strip() for c in raw_cwe if str(c).strip()]
        normalised: list[str] = []
        for c in cwe_list:
            c_upper = c.upper()
            normalised.append(c_upper if c_upper.startswith("CWE-") else f"CWE-{c_upper}")
        cwe_id = normalised[0] if normalised else "Unknown"

        # Drop Unknown-CWE entries by default — they pollute per-CWE stratification
        # and break rule-specific guided-question routing. Checked before the
        # dedup hash insert so dropped records do not poison dedup state.
        if cwe_id == "Unknown" and not include_unknown_cwe:
            dropped_unknown_cwe[0] += 1
            return None

        # Apply CWE filter
        if cwe_filter and cwe_id not in cwe_filter:
            return None

        # Synthesise a rule_id from the CWE so the questions loader can
        # exact-match instead of falling to the default-question bucket.
        # The language-preference logic lives in cwe_rule_map.primary_rule_for_langs,
        # so adding a new dataset with different language coverage is a
        # one-line change (just pass the adapter's `langs` tuple).
        rule_id = ""
        if cwe_id != "Unknown":
            rule_id = primary_rule_for_langs(cwe_id, self.langs) or ""

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
            rule_id=rule_id,
            file_path=record.get("file", ""),
            function_name=record.get("func_name", ""),
            start_line=1,
            lang="c",
            label=label,
            code_snippet=code_snippet,
            metadata={
                "project": record.get("project", ""),
                "commit_id": record.get("commit_id", ""),
                "all_cwes": normalised,
            },
        )
