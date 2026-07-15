# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Pure anchor-resolution unit tests (#118)."""

from __future__ import annotations

from vuln_hunter_x.context.anchor import (
    ABSENT,
    AMBIGUOUS,
    EXACT,
    LOCATED_UNVERIFIED,
    REANCHORED_UNIQUE,
    STRUCTURAL_NMD_RESOLUTIONS,
    resolve_anchor,
)
from vuln_hunter_x.core.types import Finding

_SRC = (
    "void ProcessImage() {\n"       # 1
    "  char *buff1 = malloc(n);\n"  # 2
    "  free(buff1);\n"              # 3
    "  int size3 = get();\n"        # 4
    "  char OOBR = buff3[size3];\n" # 5  <- scanner mis-reported the free here
    "  free(buff1);\n"             # 6  <- a second free -> ambiguous case
    "}\n"
)


def _f(line, snippet):
    return Finding(
        rule_id="cpp/double-free", message="m", file="imgRead.c",
        start_line=line, end_line=line, repo_name="dvcp", lang="cpp",
        sink_snippet=snippet,
    )


def test_exact_when_reported_line_matches():
    r = resolve_anchor(_f(3, "free(buff1);"), _SRC)
    assert r.resolution == EXACT and r.analysis_line == 3


def test_reanchored_unique_when_shifted():
    # Only ONE free(buff1) remains (line 3); reported at line 5 (the OOBR read).
    src = (
        "void ProcessImage() {\n"       # 1
        "  char *buff1 = malloc(n);\n"  # 2
        "  free(buff1);\n"              # 3  <- the unique free
        "  int size3 = get();\n"        # 4
        "  char OOBR = buff3[size3];\n" # 5  <- scanner mis-reported here
        "  puts(buff1);\n"            # 6
        "}\n"
    )
    r = resolve_anchor(_f(5, "free(buff1);"), src)
    assert r.resolution == REANCHORED_UNIQUE and r.analysis_line == 3
    assert "5" in r.detail and "3" in r.detail


def test_absent_when_construct_not_present():
    r = resolve_anchor(_f(5, "system(cmd);"), _SRC)
    assert r.resolution == ABSENT and r.analysis_line == 5
    assert ABSENT in STRUCTURAL_NMD_RESOLUTIONS


def test_ambiguous_when_multiple_matches_and_not_reported_line():
    r = resolve_anchor(_f(5, "free(buff1);"), _SRC)
    assert r.resolution == AMBIGUOUS and r.analysis_line == 5
    assert AMBIGUOUS in STRUCTURAL_NMD_RESOLUTIONS


def test_no_snippet_is_located_unverified():
    r = resolve_anchor(_f(5, ""), _SRC)
    assert r.resolution == LOCATED_UNVERIFIED and r.analysis_line == 5
    assert LOCATED_UNVERIFIED not in STRUCTURAL_NMD_RESOLUTIONS


def test_no_source_is_located_unverified():
    r = resolve_anchor(_f(5, "free(buff1);"), None)
    assert r.resolution == LOCATED_UNVERIFIED and r.analysis_line == 5


def test_whitespace_and_substring_normalization():
    r = resolve_anchor(_f(3, "free(buff1)"), _SRC)
    assert r.resolution == EXACT
