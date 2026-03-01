"""Adapter for the CVEfixes dataset.

CVEfixes: Automatically Collected Vulnerabilities and Their Fixes from Open-Source Software
  Paper: https://arxiv.org/abs/2107.08760
  Data:  https://zenodo.org/records/7029359

The dataset is a SQLite database (CVEfixes.db) with vulnerability-fixing commits.
Each row maps: CVE → repo → commit → file → function → CWE

Usage:
    from benchmarks.adapters.cvefixes_adapter import CVEfixesAdapter
    adapter = CVEfixesAdapter(Path("benchmarks/datasets/cvefixes/CVEfixes.db"))
    entries = adapter.load(langs=["c", "python"], limit=100)
"""

from __future__ import annotations

import hashlib
import logging
import sqlite3
from pathlib import Path

from benchmarks.adapters.cwe_rule_map import CWE_TO_RULES, primary_rule
from benchmarks.adapters.ground_truth import LABEL_TP, GroundTruthEntry

logger = logging.getLogger(__name__)

# Languages supported by VulnHunterX → CVEfixes extension mapping
_LANG_MAP: dict[str, str] = {
    "c": "c",
    "cpp": "cpp",
    "c++": "cpp",
    "python": "python",
    "javascript": "javascript",
    "js": "javascript",
    "php": "php",
}

# CWE IDs that have CodeQL rule mappings (we only import these)
_MAPPED_CWES = set(CWE_TO_RULES.keys())


class CVEfixesAdapter:
    """Load CVEfixes database entries as GroundTruthEntry objects.

    Note: CVEfixes records vulnerable code snippets; all loaded entries are TP
    (code IS vulnerable at the vulnerable commit). The database does not include
    SAST-FP cases. Use in combination with a raw SAST baseline to generate FP
    labels for code that SAST incorrectly flags.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        if not self.db_path.is_file():
            raise FileNotFoundError(f"CVEfixes DB not found: {self.db_path}")

    def load(
        self,
        langs: list[str] | None = None,
        limit: int = 0,
        cwe_filter: list[str] | None = None,
    ) -> list[GroundTruthEntry]:
        """Load vulnerability entries from CVEfixes.

        Args:
            langs: Language filter, e.g. ["c", "python"]. None = all supported.
            limit: Maximum entries to load (0 = all).
            cwe_filter: Only load entries for these CWE IDs (e.g. ["CWE-416"]).

        Returns:
            List of GroundTruthEntry with label=TP (all CVEfixes entries are vulnerable).
        """
        target_langs = set(langs or list(_LANG_MAP.keys()))
        target_cwes = set(cwe_filter) if cwe_filter else _MAPPED_CWES

        entries: list[GroundTruthEntry] = []

        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cur = conn.cursor()

            # CVEfixes schema: cve_fixes table links CVE → file_change → method_change
            # Try to query available tables first
            tables = {
                r[0]
                for r in cur.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            logger.debug("CVEfixes tables: %s", tables)

            rows = self._query_vulnerabilities(cur, tables)

        for row in rows:
            lang_raw = (row.get("programming_language") or "").lower().strip()
            lang = _LANG_MAP.get(lang_raw, "")
            if lang not in target_langs:
                continue

            cwe_raw = row.get("cwe_id") or ""
            # Normalize: "CWE-416", "416" → "CWE-416"
            cwe_id = cwe_raw if cwe_raw.startswith("CWE-") else f"CWE-{cwe_raw}"
            if cwe_id not in target_cwes:
                continue

            rule_id = primary_rule(cwe_id)
            code = (row.get("before_change") or row.get("code") or "").strip()
            if not code:
                continue

            cve_id = row.get("cve_id") or "unknown"
            file_path = row.get("filename") or ""
            func_name = row.get("name") or row.get("func_name") or ""

            entry_id = hashlib.md5(  # noqa: S324
                f"{cve_id}:{file_path}:{func_name}".encode()
            ).hexdigest()[:12]

            entries.append(
                GroundTruthEntry(
                    id=f"cvef_{entry_id}",
                    source_dataset="cvefixes",
                    cwe_id=cwe_id,
                    rule_id=rule_id,
                    file_path=file_path,
                    function_name=func_name,
                    start_line=1,
                    lang=lang,
                    label=LABEL_TP,
                    code_snippet=code[:8000],
                    metadata={
                        "cve_id": cve_id,
                        "repo": row.get("repo_url") or "",
                        "commit": row.get("hash") or "",
                    },
                )
            )

            if limit and len(entries) >= limit:
                break

        logger.info("CVEfixes: loaded %d entries", len(entries))
        return entries

    def _query_vulnerabilities(
        self,
        cur: sqlite3.Cursor,
        tables: set[str],
    ) -> list[dict]:
        """Query vulnerability data, adapting to different CVEfixes schema versions."""
        # CVEfixes v1.0 schema: cve_fixes + file_change + method_change + cve
        if "method_change" in tables and "file_change" in tables and "cve" in tables:
            cur.execute(
                """
                SELECT
                    cv.cve_id,
                    cv.cwe_id,
                    fc.filename,
                    fc.programming_language,
                    mc.name,
                    mc.before_change,
                    fc.repo_url,
                    fc.hash
                FROM method_change mc
                JOIN file_change fc ON mc.file_change_id = fc.file_change_id
                JOIN cve_fixes cf ON fc.hash = cf.hash AND fc.repo_url = cf.repo_url
                JOIN cve cv ON cf.cve_id = cv.cve_id
                WHERE mc.before_change IS NOT NULL
                  AND length(mc.before_change) > 10
                """
            )
        elif "commits" in tables:
            # Alternative schema
            cur.execute(
                """
                SELECT
                    cve_id, cwe_id, filename, programming_language,
                    func_name, before_change, repo_url, hash
                FROM commits
                WHERE before_change IS NOT NULL
                """
            )
        else:
            logger.warning(
                "Unrecognised CVEfixes schema; available tables: %s", tables
            )
            return []

        columns = [d[0] for d in cur.description]
        return [dict(zip(columns, row)) for row in cur.fetchall()]
