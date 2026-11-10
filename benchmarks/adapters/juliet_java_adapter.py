# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Adapter for the Juliet Java 1.3 Test Suite (NIST SARD).

Download: https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-java-v1-3.zip
(HTTP 200, ~77 MB, verified).

Layout:
    src/testcases/CWE<nnn>_<Name>/[s01/...]/CWE<nnn>_<Name>__<variant>_<flow>.java
    src/testcasesupport/...   (helpers, ignored)

Each test case defines ``bad()`` (vulnerable) and ``good*()`` (safe) methods,
either in one file or split across ``*_bad.java`` / ``*_good*.java``. As in
the C adapter's offline mode, one file can yield a TP and an FP entry that
share the whole-file snippet; ``function_name`` and ``start_line`` identify
the method. Entries are function-granularity (``sink_line`` None).

Redaction: not done here. File paths, class names, ``bad``/``good`` names
and ``FLAW``/``FIX`` comments are label-bearing; ``benchmarks.adapters.
redaction`` may opt in to the dataset name ``"juliet-java"``. Raw info is
kept in ``metadata`` (``cwe_dir``, ``filename``).
"""

from __future__ import annotations

import hashlib
import logging
import re
from pathlib import Path

from benchmarks.adapters.cwe_rule_map import primary_rule_for_lang
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, GroundTruthEntry
from benchmarks.adapters.juliet_adapter import (
    _dir_to_cwe_id,
    _is_bad_file,
    _is_good_file,
)
from benchmarks.adapters.registry import (
    DatasetAdapter,
    OptionSpec,
    _to_csv_list,
    register_adapter,
)

logger = logging.getLogger(__name__)

# Default Java CWE set (CodeQL-mappable, common SAST targets).
DEFAULT_JAVA_CWES = {
    "CWE-78",
    "CWE-80",
    "CWE-89",
    "CWE-90",
    "CWE-113",
    "CWE-190",
    "CWE-191",
    "CWE-327",
    "CWE-328",
    "CWE-330",
    "CWE-501",
    "CWE-601",
    "CWE-614",
    "CWE-643",
}

_BAD_METHOD_RE = re.compile(r"\bvoid\s+bad\s*\(")
_GOOD_METHOD_RE = re.compile(r"\bvoid\s+good\w*\s*\(")
_ACTION_RE = re.compile(r"\bvoid\s+(?:action|bad|good\w*)\s*\(")


def _first_line(code: str, pattern: re.Pattern[str]) -> int:
    m = pattern.search(code)
    return code.count("\n", 0, m.start()) + 1 if m else 1


def _spread(items: list, n: int) -> list:
    """Pick ``n`` items evenly spread across ``items`` (deterministic)."""
    if n >= len(items):
        return list(items)
    return [items[(i * len(items)) // n] for i in range(n)]


@register_adapter
class JulietJavaAdapter(DatasetAdapter):
    name = "juliet-java"
    langs = ("java",)
    family = "synthetic"
    option_schema = {
        "cwes": OptionSpec(
            _to_csv_list,
            default=None,
            help="Comma list of CWEs (e.g. 'CWE-89,CWE-78') or 'all'. Default: built-in Java set.",
        ),
        "per_cwe_limit": OptionSpec(
            int,
            default=0,
            help="Max entries per CWE, balanced TP/FP (N//2 each), evenly spread "
            "across the CWE's files. 0 = no cap.",
        ),
    }
    install_url = (
        "https://samate.nist.gov/SARD/downloads/test-suites/"
        "2017-10-01-juliet-test-suite-for-java-v1-3.zip"
    )
    expected_files = ("src/testcases",)

    def __init__(self, dataset_path: Path) -> None:
        self.dataset_path = Path(dataset_path)

    def _find_testcases_dir(self) -> Path:
        for candidate in (
            self.dataset_path / "src" / "testcases",
            self.dataset_path / "testcases",
            self.dataset_path,
        ):
            if candidate.is_dir() and any(
                d.is_dir() and d.name.upper().startswith("CWE") for d in candidate.iterdir()
            ):
                return candidate
        raise FileNotFoundError(
            f"Cannot find Juliet Java testcases under {self.dataset_path}. "
            "Expected src/testcases/CWE*/ layout."
        )

    def load(
        self,
        limit: int = 0,
        cwes: list[str] | None = None,
        per_cwe_limit: int = 0,
    ) -> list[GroundTruthEntry]:
        testcases = self._find_testcases_dir()
        if cwes and [c.lower() for c in cwes] == ["all"]:
            active: set[str] | None = None
        elif cwes:
            active = {c.upper() if c.upper().startswith("CWE-") else f"CWE-{c}" for c in cwes}
        else:
            active = DEFAULT_JAVA_CWES

        entries: list[GroundTruthEntry] = []
        for cwe_dir in sorted(testcases.iterdir()):
            if not cwe_dir.is_dir():
                continue
            cwe_id = _dir_to_cwe_id(cwe_dir.name)
            if cwe_id is None or (active is not None and cwe_id not in active):
                continue
            rule_id = primary_rule_for_lang(cwe_id, "java")
            cwe_entries: list[GroundTruthEntry] = []
            for jf in sorted(cwe_dir.rglob("*.java")):
                try:
                    code = jf.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                rel = str(jf.relative_to(self.dataset_path))
                cands: list[tuple[str, str, int]] = []
                # Split-flow variants (``*_81_bad.java`` / ``*_81_goodG2B.java``)
                # implement ``action()`` rather than bad()/good(), so the
                # filename alone decides the label for those.
                if _is_bad_file(jf):
                    cands.append((LABEL_TP, "bad()", _first_line(code, _ACTION_RE)))
                elif _is_good_file(jf):
                    cands.append((LABEL_FP, "good()", _first_line(code, _ACTION_RE)))
                elif not (_is_bad_file(jf) or _is_good_file(jf)):
                    if _BAD_METHOD_RE.search(code):
                        cands.append((LABEL_TP, "bad()", _first_line(code, _BAD_METHOD_RE)))
                    if _GOOD_METHOD_RE.search(code):
                        cands.append((LABEL_FP, "good()", _first_line(code, _GOOD_METHOD_RE)))
                for label, func, line in cands:
                    eid = hashlib.md5(f"{rel}:{label}".encode()).hexdigest()[:12]  # noqa: S324
                    cwe_entries.append(
                        GroundTruthEntry(
                            id=f"juliet-java_{eid}",
                            source_dataset="juliet-java",
                            cwe_id=cwe_id,
                            rule_id=rule_id,
                            file_path=rel,
                            function_name=func,
                            start_line=line,
                            lang="java",
                            label=label,
                            code_snippet=code[:8000],
                            metadata={"cwe_dir": cwe_dir.name, "filename": jf.name},
                        )
                    )

            if per_cwe_limit and cwe_entries:
                half = max(1, per_cwe_limit // 2)
                cwe_entries = _spread(
                    [e for e in cwe_entries if e.label == LABEL_TP], half
                ) + _spread([e for e in cwe_entries if e.label == LABEL_FP], half)
            entries.extend(cwe_entries)

        if limit:
            entries = entries[:limit]
        logger.info("Juliet-Java: loaded %d entries", len(entries))
        return entries
