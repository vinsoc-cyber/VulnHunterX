# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the CASTLE benchmark (250 C programs, 25 CWEs).

Paper: https://arxiv.org/abs/2503.09433
Repo:  https://github.com/CASTLE-Benchmark/CASTLE-Benchmark (MIT)

Verified layout (v1.2 of the dataset file):
    CASTLE-Benchmark/
    └── datasets/
        ├── CASTLE-C250.json        # {"tests": [...]} labelled dataset
        ├── CASTLE-C250.min.json    # minified copy of the same
        └── CASTLE-C250/CASTLE-<cwe>-<n>.c   # raw sources (no label markers)

Each ``tests[i]`` has: ``name`` ("CASTLE-22-1.c"), ``id`` ("22-1"),
``vulnerable`` (bool), ``cwe`` (int), ``lines`` (1-indexed vulnerable lines,
empty for clean programs), ``description`` and ``code``. The ``.c`` files
carry no label markers; labels and line numbers come from the JSON only.

Label rule: vulnerable -> TP with ``sink_line = lines[0]``; clean -> FP.

Redaction: this adapter does NOT redact. ``metadata['description']`` is
label-bearing; ``benchmarks.adapters.redaction`` may opt in to the dataset
name ``"castle"``.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import (
    DatasetAdapter,
    OptionSpec,
    _to_csv_list,
    register_adapter,
)

logger = logging.getLogger(__name__)

_JSON_CANDIDATES = (
    "datasets/CASTLE-C250.json",
    "datasets/CASTLE-C250.min.json",
    "CASTLE-C250.json",
    "CASTLE-C250.min.json",
)


def _normalize_cwe(raw: Any) -> str:
    s = str(raw).strip()
    if not s:
        return ""
    return s.upper() if s.upper().startswith("CWE-") else f"CWE-{s}"


@register_adapter
class CastleAdapter(DatasetAdapter):
    name = "castle"
    langs = ("c",)
    family = "synthetic"
    option_schema = {
        "cwes": OptionSpec(
            _to_csv_list,
            default=None,
            help="Comma list of CWEs to keep (e.g. 'CWE-22,CWE-787'). Default: all.",
        ),
        "per_cwe_limit": OptionSpec(
            int,
            default=0,
            help="Max entries per CWE, balanced TP/FP (N//2 each). 0 = no cap.",
        ),
    }
    install_url = "https://github.com/CASTLE-Benchmark/CASTLE-Benchmark"
    expected_files = ("datasets",)

    def __init__(self, dataset_path: Path) -> None:
        self.dataset_path = Path(dataset_path)

    def _json_path(self) -> Path:
        for rel in _JSON_CANDIDATES:
            p = self.dataset_path / rel
            if p.is_file():
                return p
        raise FileNotFoundError(
            f"Cannot find CASTLE-C250.json under {self.dataset_path}; "
            "is this a CASTLE-Benchmark checkout?"
        )

    def _source_for(self, test: dict) -> str:
        code = test.get("code")
        if isinstance(code, str) and code:
            return code
        name = str(test.get("name") or "")
        if name and "/" not in name and "\\" not in name:
            for base in (
                self.dataset_path / "datasets" / "CASTLE-C250",
                self.dataset_path / "CASTLE-C250",
            ):
                p = base / name
                if p.is_file():
                    return p.read_text(encoding="utf-8", errors="replace")
        return ""

    def load(
        self,
        limit: int = 0,
        cwes: list[str] | None = None,
        per_cwe_limit: int = 0,
    ) -> list[GroundTruthEntry]:
        data = json.loads(self._json_path().read_text(encoding="utf-8"))
        tests = data.get("tests", []) if isinstance(data, dict) else data
        wanted = {_normalize_cwe(c) for c in cwes} if cwes else None

        by_cwe: dict[str, list[GroundTruthEntry]] = {}
        for t in tests:
            cwe_id = _normalize_cwe(t.get("cwe", ""))
            if not cwe_id or (wanted and cwe_id not in wanted):
                continue
            vulnerable = bool(t.get("vulnerable"))
            lines = [x for x in (t.get("lines") or []) if isinstance(x, int)]
            code = self._source_for(t)
            if not code:
                logger.warning("CASTLE: no source for %s; skipping", t.get("name"))
                continue
            sink = lines[0] if (vulnerable and lines) else None
            tid = str(t.get("id") or t.get("name"))
            by_cwe.setdefault(cwe_id, []).append(
                GroundTruthEntry(
                    id=f"castle_{tid}",
                    source_dataset="castle",
                    cwe_id=cwe_id,
                    rule_id=primary_rule_for_lang(cwe_id, "c"),
                    file_path=str(t.get("name") or f"CASTLE-{tid}.c"),
                    function_name="",
                    start_line=sink or 1,
                    sink_line=sink,
                    lang="c",
                    label=LABEL_TP if vulnerable else LABEL_FP,
                    code_snippet=code,
                    metadata={
                        "cwe": cwe_id,
                        "original_filename": str(t.get("name") or ""),
                        "vulnerable_lines": lines,
                        # Label-bearing; redaction may strip it.
                        "description": str(t.get("description") or ""),
                    },
                )
            )

        entries: list[GroundTruthEntry] = []
        for cwe_id in sorted(by_cwe, key=lambda c: (len(c), c)):
            group = by_cwe[cwe_id]
            if per_cwe_limit:
                half = max(1, per_cwe_limit // 2)
                group = [e for e in group if e.label == LABEL_TP][:half] + [
                    e for e in group if e.label == LABEL_FP
                ][:half]
            entries.extend(group)
        if limit:
            entries = entries[:limit]
        logger.info("CASTLE: loaded %d entries", len(entries))
        return entries
