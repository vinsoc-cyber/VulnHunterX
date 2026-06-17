# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the OWASP Benchmark Project (Java + Python).

Project: https://owasp.org/www-project-benchmark/
Repos:
    https://github.com/OWASP-Benchmark/BenchmarkJava   (GPL-2.0)
    https://github.com/OWASP-Benchmark/BenchmarkPython (GPL-3.0)

Dataset structure (after cloning):
    BenchmarkJava/
    ├── expectedresults-1.2.csv         # ground truth manifest
    └── src/main/java/.../BenchmarkTest00001.java
        ...

    BenchmarkPython/
    ├── expectedresults-0.1.csv
    └── testcode/BenchmarkTest00001.py
        ...

Note: the two upstream repos use different source-dir conventions. The
adapter selects the dir per-language (``src`` for Java, ``testcode`` for
Python).

Manifest columns:
    "# test name", "category", "real vulnerability", "cwe",
    "Benchmark version", "time"

Label rules:
    real vulnerability == "true"  → LABEL_TP
    real vulnerability == "false" → LABEL_FP

OWASP entries are exclusively TP-or-FP (never BENIGN); they are designed to
be triaged by SAST tools.
"""

from __future__ import annotations

import csv
import logging
import re
from pathlib import Path

from benchmarks.adapters.cwe_rule_map import cwe_to_rules, primary_rule
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.registry import DatasetAdapter, register_adapter

logger = logging.getLogger(__name__)


_TEST_NAME_RE = re.compile(r"BenchmarkTest\d{5}")
_JAVA_METHOD_RE = re.compile(
    r"public\s+void\s+do\w+\s*\(",  # doPost / doGet / doPut etc.
)
_PYTHON_DEF_RE = re.compile(r"^\s*def\s+(\w+)\s*\(", re.MULTILINE)


class OwaspBenchmarkAdapter:
    """Parse OWASP BenchmarkJava / BenchmarkPython into GroundTruthEntry objects."""

    def __init__(self, dataset_path: Path, lang: str) -> None:
        if lang not in ("java", "python"):
            raise ValueError(f"OWASP adapter supports java|python, got {lang!r}")
        self.dataset_path = Path(dataset_path)
        self.lang = lang
        self._suffix = ".java" if lang == "java" else ".py"
        self._rule_prefix = "java/" if lang == "java" else "py/"
        # BenchmarkJava ships test files under src/main/java/...; BenchmarkPython
        # ships them flat under testcode/.
        self._source_dirname = "src" if lang == "java" else "testcode"

    def _rule_for(self, cwe_id: str) -> str:
        """Pick the rule ID matching this adapter's language; fall back to primary."""
        for rule in cwe_to_rules(cwe_id):
            if rule.startswith(self._rule_prefix):
                return rule
        return primary_rule(cwe_id)

    def _find_manifest(self) -> Path:
        candidates = sorted(self.dataset_path.glob("expectedresults-*.csv"))
        if not candidates:
            raise FileNotFoundError(
                f"No expectedresults-*.csv under {self.dataset_path}; "
                "is this an OWASP Benchmark checkout?"
            )
        # Prefer highest version (lexicographic sort works for v0.1 < v1.2 here)
        return candidates[-1]

    def _index_test_files(self) -> dict[str, Path]:
        """Map BenchmarkTest##### → file path under the language-specific source dir."""
        src = self.dataset_path / self._source_dirname
        if not src.is_dir():
            raise FileNotFoundError(
                f"Expected {self._source_dirname}/ under {self.dataset_path}"
            )
        index: dict[str, Path] = {}
        for path in src.rglob(f"BenchmarkTest*{self._suffix}"):
            stem = path.stem  # BenchmarkTest00001
            if _TEST_NAME_RE.fullmatch(stem):
                index[stem] = path
        return index

    @staticmethod
    def _extract_function_name(snippet: str, lang: str) -> str:
        if lang == "java":
            m = _JAVA_METHOD_RE.search(snippet)
            return m.group(0).split()[2].split("(")[0] if m else ""
        # python: first top-level def after "class"
        m = _PYTHON_DEF_RE.search(snippet)
        return m.group(1) if m else ""

    def load(self, limit: int = 0) -> list[GroundTruthEntry]:
        manifest = self._find_manifest()
        version = manifest.stem.removeprefix("expectedresults-")
        files_by_name = self._index_test_files()

        entries: list[GroundTruthEntry] = []
        with manifest.open(encoding="utf-8") as fh:
            reader = csv.DictReader(fh)
            # Normalize header keys (strip leading "#" and whitespace)
            reader.fieldnames = [
                (f or "").lstrip("#").strip().lower() for f in (reader.fieldnames or [])
            ]
            for row in reader:
                test_name = (row.get("test name") or "").strip()
                if not test_name or not _TEST_NAME_RE.fullmatch(test_name):
                    continue
                code_file = files_by_name.get(test_name)
                if code_file is None:
                    logger.debug("OWASP: missing source file for %s", test_name)
                    continue

                cwe_raw = (row.get("cwe") or "").strip()
                if not cwe_raw.isdigit():
                    continue
                cwe_id = f"CWE-{cwe_raw}"
                real_vuln = (row.get("real vulnerability") or "").strip().lower() == "true"
                label = LABEL_TP if real_vuln else LABEL_FP
                category = (row.get("category") or "").strip()

                try:
                    snippet = code_file.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    logger.warning("Cannot read %s; skipping", code_file)
                    continue

                entries.append(
                    GroundTruthEntry(
                        id=f"owasp-{self.lang}-{test_name}",
                        source_dataset=f"owasp-{self.lang}",
                        cwe_id=cwe_id,
                        rule_id=self._rule_for(cwe_id),
                        file_path=str(code_file.relative_to(self.dataset_path)),
                        function_name=self._extract_function_name(snippet, self.lang),
                        start_line=1,
                        lang=self.lang,
                        label=label,
                        code_snippet=snippet,
                        metadata={
                            "category": category,
                            "version": version,
                            "test_name": test_name,
                        },
                    )
                )
                if limit and len(entries) >= limit:
                    break

        logger.info(
            "OWASP-%s: loaded %d entries from %s (manifest=%s)",
            self.lang, len(entries), self.dataset_path, manifest.name,
        )
        return entries


# ── Registry-facing thin subclasses ──────────────────────────────────
# The base ``OwaspBenchmarkAdapter`` takes ``lang`` at __init__ time,
# which doesn't fit the DatasetAdapter contract (``Adapter(dataset_path)``).
# These subclasses pin ``lang`` at the class level so the registry can
# instantiate them generically. Behaviour is otherwise identical.


@register_adapter
class OwaspJavaAdapter(OwaspBenchmarkAdapter, DatasetAdapter):
    """OWASP BenchmarkJava — registry-facing wrapper."""

    name = "owasp-java"
    langs = ("java",)
    family = "owasp"
    option_schema: dict = {}
    install_url = "https://github.com/OWASP-Benchmark/BenchmarkJava.git"
    expected_files = ("expectedresults-",)

    def __init__(self, dataset_path: Path) -> None:
        super().__init__(dataset_path, lang="java")


@register_adapter
class OwaspPythonAdapter(OwaspBenchmarkAdapter, DatasetAdapter):
    """OWASP BenchmarkPython — registry-facing wrapper."""

    name = "owasp-python"
    langs = ("python",)
    family = "owasp"
    option_schema: dict = {}
    install_url = "https://github.com/OWASP-Benchmark/BenchmarkPython.git"
    expected_files = ("expectedresults-",)

    def __init__(self, dataset_path: Path) -> None:
        super().__init__(dataset_path, lang="python")
