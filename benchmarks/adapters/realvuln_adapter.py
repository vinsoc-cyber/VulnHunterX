# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the RealVuln Benchmark dataset.

Repo: https://github.com/kolega-ai/Real-Vuln-Benchmark (MIT)

This is the substitute we adopted in lieu of SastBench, whose public
repository URL was not findable at integration time. RealVuln has the
same shape (real CVEs as TPs + FP traps) and a documented JSON schema.

Dataset layout:
    Real-Vuln-Benchmark/
    ├── ground-truth/<repo_id>/ground-truth.json
    └── (optionally) per-repo working trees the user has checked out

Each ground-truth.json contains:
    {
        "schema_version": ...,
        "repo_id": ..., "repo_url": ..., "commit_sha": ...,
        "language": "python", ...
        "findings": [
            {
                "id": "...", "is_vulnerable": true|false,
                "primary_cwe": "CWE-89" | "89",
                "file": "path/to/file.py",
                "location": {"start_line": ..., "end_line": ..., "function": ...},
                "evidence": {"source": "cve|semgrep", "cve_id": "...", ...}
            },
            ...
        ]
    }

Label rule:
    is_vulnerable == True  → LABEL_TP
    is_vulnerable == False → LABEL_FP   (FP "trap" sample)

Code snippet extraction is best-effort. If a working tree exists at
``<repos_cache>/<repo_id>`` (the user is responsible for checking out
the correct commit), the adapter reads the function lines from disk.
Otherwise it leaves ``code_snippet=""`` and tags the entry; downstream
approaches that need source must skip these. A test caller can pass
an in-memory snippet via ``code_resolver``.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from pathlib import Path

from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import DatasetAdapter, register_adapter

logger = logging.getLogger(__name__)


# (repo_id, finding) -> snippet  (used in tests; production reads from disk)
CodeResolver = Callable[[str, dict], str]


def _normalize_cwe(raw: str | int | None) -> str:
    if raw is None:
        return ""
    s = str(raw).strip()
    if not s:
        return ""
    if s.upper().startswith("CWE-"):
        return s.upper()
    return f"CWE-{s}"


def _read_lines(path: Path, start: int, end: int, pad: int = 0) -> str:
    """Read lines [start, end] inclusive (1-indexed) with optional padding."""
    if not path.is_file():
        return ""
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""
    lines = text.splitlines()
    s = max(0, start - 1 - pad)
    e = min(len(lines), end + pad)
    return "\n".join(lines[s:e])


@register_adapter
class RealVulnAdapter(DatasetAdapter):
    """Parse RealVuln Benchmark ground-truth JSON files into GroundTruthEntry.

    Args:
        dataset_path: Root of the cloned Real-Vuln-Benchmark repository.
        repos_cache: Optional directory containing checked-out source trees
            keyed by repo_id. If absent, snippets are left empty.
            Programmatic-only — not exposed via the registry CLI.
        code_resolver: Optional callable for tests to inject snippets.
            Programmatic-only — not exposed via the registry CLI.
    """

    name = "realvuln"
    langs = ("python",)
    family = "cve"
    option_schema: dict = {}
    install_url = "https://github.com/kolega-ai/Real-Vuln-Benchmark.git"
    expected_files = ("ground-truth",)

    def __init__(
        self,
        dataset_path: Path,
        repos_cache: Path | None = None,
        code_resolver: CodeResolver | None = None,
    ) -> None:
        self.dataset_path = Path(dataset_path)
        self.repos_cache = (
            Path(repos_cache) if repos_cache else self.dataset_path / "_repos"
        )
        self.code_resolver = code_resolver

    def _ground_truth_files(self) -> list[Path]:
        gt_root = self.dataset_path / "ground-truth"
        if not gt_root.is_dir():
            raise FileNotFoundError(
                f"No ground-truth/ under {self.dataset_path}; "
                "is this a RealVuln Benchmark checkout?"
            )
        return sorted(gt_root.rglob("ground-truth.json"))

    def _resolve_snippet(
        self, repo_id: str, finding: dict, file_rel: str, start: int, end: int
    ) -> tuple[str, str]:
        """Return (snippet, source_kind) for the finding."""
        if self.code_resolver is not None:
            return self.code_resolver(repo_id, finding) or "", "resolver"
        if start <= 0 or end < start:
            return "", "missing"
        repo_root = self.repos_cache / repo_id
        candidate = repo_root / file_rel
        snippet = _read_lines(candidate, start, end, pad=2)
        if snippet:
            return snippet, "checkout"
        # Fallback: ±50 line window on the same file (still empty if no checkout)
        snippet = _read_lines(candidate, start, end, pad=50)
        return snippet, "window" if snippet else "missing"

    def load(self, limit: int = 0) -> list[GroundTruthEntry]:
        entries: list[GroundTruthEntry] = []
        for gt_path in self._ground_truth_files():
            try:
                manifest = json.loads(gt_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Skipping %s: %s", gt_path, exc)
                continue

            repo_id = str(manifest.get("repo_id") or gt_path.parent.name)
            commit = str(manifest.get("commit_sha") or "")
            lang = str(manifest.get("language") or "").lower() or "python"

            for f in manifest.get("findings", []):
                is_vuln = bool(f.get("is_vulnerable"))
                label = LABEL_TP if is_vuln else LABEL_FP

                cwe_id = _normalize_cwe(f.get("primary_cwe"))
                if not cwe_id:
                    continue

                location = f.get("location") or {}
                start_line = int(location.get("start_line") or 0)
                end_line = int(location.get("end_line") or start_line)
                func_name = str(location.get("function") or "")
                file_rel = str(f.get("file") or "")

                snippet, snippet_kind = self._resolve_snippet(
                    repo_id, f, file_rel, start_line, end_line
                )

                evidence = f.get("evidence") or {}
                finding_id = str(f.get("id") or f"{repo_id}-{len(entries)}")

                entries.append(
                    GroundTruthEntry(
                        id=f"realvuln-{repo_id}-{finding_id}",
                        source_dataset="realvuln",
                        cwe_id=cwe_id,
                        rule_id=primary_rule_for_lang(cwe_id, lang),
                        file_path=file_rel,
                        function_name=func_name,
                        start_line=start_line or 1,
                        lang=lang,
                        label=label,
                        code_snippet=snippet,
                        metadata={
                            "repo_id": repo_id,
                            "commit_sha": commit,
                            "end_line": end_line,
                            "evidence_source": str(evidence.get("source") or ""),
                            "cve_id": str(evidence.get("cve_id") or ""),
                            "snippet_kind": snippet_kind,
                            "vulnerability_class": str(
                                f.get("vulnerability_class") or ""
                            ),
                        },
                    )
                )

                if limit and len(entries) >= limit:
                    return entries

        logger.info(
            "RealVuln: loaded %d entries from %s",
            len(entries), self.dataset_path,
        )
        return entries
