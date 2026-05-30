# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the OpenVuln dataset (from the ZeroFalse project).

Source: https://github.com/mhsniranmanesh/ZeroFalse  (MIT)
Paper:  https://arxiv.org/abs/2510.02534

OpenVuln is the highest-fidelity *real* SAST-FP-reduction set found: 58 real
CodeQL SARIF alerts across 7 Java projects, each labeled TP/FP by comparing the
vulnerable vs. patched version. This is exactly the shape VulnHunterX consumes
(a CodeQL alert + a ground-truth verdict), so it is a Track-1 (FP-reduction)
dataset — unlike function-level detection sets (DiverseVul/CVEfixes).

Layout (after `git clone`):
    ZeroFalse/OpenVuln/
    ├── ground_truth.csv     # project_slug, alert_number, cve_id, filename, is_vulnerable
    ├── Projects_info.csv     # project_slug, cve_id, cwe_id, cwe_name, ...
    ├── sarif-files/<project_slug>.sarif
    └── code-context/{baseline,optimized,method-finder}/.../<filename>

Labels:
    is_vulnerable == True  → LABEL_TP   (real vulnerability the CodeQL alert caught)
    is_vulnerable == False → LABEL_FP   (CodeQL alert that is a false positive)

Snippet extraction is best-effort: the per-alert code-context file named in
``ground_truth.csv`` is searched under ``code-context/`` and read if found;
otherwise the entry is tagged ``metadata.snippet_kind = "missing"`` (still
scores for raw-sast comparison).
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path
from typing import ClassVar

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import DatasetAdapter, register_adapter

logger = logging.getLogger(__name__)

_MAX_SNIPPET_CHARS = 8000
# vulnerability_java_path-injection_9.txt -> lang=java, slug=path-injection
_FILENAME_RE = re.compile(r"_(?P<lang>[a-z]+)_(?P<slug>[a-z0-9-]+)_(?P<num>\d+)\.txt$")


def _normalize_cwe(raw: str) -> str:
    """``CWE-022`` -> ``CWE-22`` (strip zero-padding so the CWE map matches)."""
    raw = (raw or "").strip().upper()
    m = re.match(r"CWE-0*(\d+)$", raw)
    return f"CWE-{m.group(1)}" if m else raw


def _rule_id_from_filename(filename: str) -> tuple[str, str]:
    """Return (rule_id, lang) derived from the code-context filename.

    ``vulnerability_java_path-injection_9.txt`` -> ("java/path-injection", "java").
    Falls back to ("", "java") when the pattern doesn't match.
    """
    m = _FILENAME_RE.search(filename)
    if not m:
        return "", "java"
    lang = m.group("lang")
    return f"{lang}/{m.group('slug')}", lang


@register_adapter
class OpenVulnAdapter(DatasetAdapter):
    """Load OpenVuln (ZeroFalse) CodeQL alerts as TP/FP GroundTruthEntry objects."""

    name = "openvuln"
    langs: ClassVar[tuple[str, ...]] = ("java",)
    family = "cve"
    option_schema: ClassVar[dict] = {}
    install_url = "https://github.com/mhsniranmanesh/ZeroFalse.git"
    expected_files = ("OpenVuln/ground_truth.csv",)

    def __init__(self, dataset_path: Path) -> None:
        p = Path(dataset_path)
        # Accept either a ZeroFalse clone root or the OpenVuln dir directly.
        self.base = p / "OpenVuln" if (p / "OpenVuln").is_dir() else p

    def _cwe_by_project(self) -> dict[str, str]:
        info = self.base / "Projects_info.csv"
        if not info.is_file():
            return {}
        out: dict[str, str] = {}
        with info.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                slug = (row.get("project_slug") or "").strip()
                if slug:
                    out[slug] = _normalize_cwe(row.get("cwe_id", ""))
        return out

    def _find_snippet(self, filename: str) -> str:
        """Best-effort: locate the named code-context file anywhere under
        code-context/ and return its contents (capped)."""
        ctx = self.base / "code-context"
        if not ctx.is_dir() or not filename:
            return ""
        matches = list(ctx.rglob(filename))
        if not matches:
            return ""
        try:
            return matches[0].read_text(encoding="utf-8", errors="replace")[:_MAX_SNIPPET_CHARS]
        except OSError:
            return ""

    def load(self, limit: int = 0) -> list[GroundTruthEntry]:
        gt = self.base / "ground_truth.csv"
        if not gt.is_file():
            raise FileNotFoundError(
                f"OpenVuln ground_truth.csv not found under {self.base}. "
                "Clone https://github.com/mhsniranmanesh/ZeroFalse."
            )
        cwe_by_project = self._cwe_by_project()

        entries: list[GroundTruthEntry] = []
        missing_snippets = 0
        with gt.open(encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                slug = (row.get("project_slug") or "").strip()
                alert = (row.get("alert_number") or "").strip()
                filename = (row.get("filename") or "").strip()
                is_vuln = (row.get("is_vulnerable") or "").strip().lower() == "true"
                if not slug or not filename:
                    continue

                rule_id, lang = _rule_id_from_filename(filename)
                cwe_id = cwe_by_project.get(slug, "")
                snippet = self._find_snippet(filename)
                snippet_kind = "code-context" if snippet else "missing"
                if not snippet:
                    missing_snippets += 1

                entries.append(
                    GroundTruthEntry(
                        id=f"openvuln-{slug}-{alert}",
                        source_dataset="openvuln",
                        cwe_id=cwe_id,
                        rule_id=rule_id,
                        file_path=filename,
                        function_name="",
                        start_line=1,
                        lang=lang,
                        label=LABEL_TP if is_vuln else LABEL_FP,
                        code_snippet=snippet,
                        metadata={
                            "project_slug": slug,
                            "alert_number": alert,
                            "cve_id": (row.get("cve_id") or "").strip(),
                            "snippet_kind": snippet_kind,
                        },
                    )
                )
                if limit and len(entries) >= limit:
                    break

        logger.info(
            "openvuln: loaded %d entries (%d TP, %d FP); %d missing snippets",
            len(entries),
            sum(1 for e in entries if e.label == LABEL_TP),
            sum(1 for e in entries if e.label == LABEL_FP),
            missing_snippets,
        )
        return entries
