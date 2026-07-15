# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Deterministic #118 acceptance panel — misaligned-slice shapes across C / PHP /
JS resolve to a correct analysis anchor or an honest structural NMD, never a
dismissal. Resolver-level (no LLM), real line numbers (not the line-1 adapters).
"""

from __future__ import annotations

from vuln_hunter_x.context.anchor import (
    ABSENT,
    EXACT,
    REANCHORED_UNIQUE,
    resolve_anchor,
)
from vuln_hunter_x.core.types import Finding


def _f(file, lang, line, snippet, rule):
    return Finding(rule_id=rule, message="m", file=file, start_line=line,
                   end_line=line, repo_name="panel", lang=lang, sink_snippet=snippet)


# dvcp imgRead.c:62 — scanner line points at an array read; the real free() is elsewhere.
_C_SRC = (
    "void ProcessImage(){\n"          # 1
    "  char *buff1 = malloc(n);\n"    # 2
    "  read(buff1);\n"                # 3
    "  free(buff1);\n"               # 4   <- the real free
    "  int size3 = width*height;\n"   # 5
    "  char OOBR = buff3[size3];\n"   # 6   <- scanner mis-reported line
)


def test_c_double_free_reanchors_to_real_free():
    r = resolve_anchor(_f("imgRead.c", "cpp", 6, "free(buff1);", "cpp/double-free"), _C_SRC)
    assert r.resolution == REANCHORED_UNIQUE and r.analysis_line == 4


# dvwa sqli_blind/high.php:33 — scanner reports the tainted SELECT; slice showed num_rows.
_PHP_SRC = (
    "<?php\n"                                                          # 1
    "$id = $_GET['id'];\n"                                            # 2
    "$query = \"SELECT first_name FROM users WHERE id = '$id';\";\n"  # 3  <- real sink
    "$result = mysqli_query($db, $query);\n"                         # 4
    "$num = mysqli_num_rows($result);\n"                             # 5
)


def test_php_sqli_confirms_reported_line_exact():
    r = resolve_anchor(
        _f("high.php", "php", 3, "SELECT first_name FROM users WHERE id = '$id';",
           "tainted-sql-string"), _PHP_SRC)
    assert r.resolution == EXACT and r.analysis_line == 3


# nodegoat server.js:78 — CSRF middleware line shifted after an edit.
_JS_SRC = (
    "app.use(express.json());\n"          # 1
    "app.use(session(cfg));\n"           # 2
    "app.use(csrf());  // token check\n"  # 3  <- real construct
    "app.use(logger());\n"               # 4
)


def test_js_missing_token_reanchors():
    r = resolve_anchor(
        _f("server.js", "javascript", 1, "app.use(csrf());",
           "js/missing-token-validation"), _JS_SRC)
    assert r.resolution == REANCHORED_UNIQUE and r.analysis_line == 3


def test_absent_construct_is_structural_nmd_not_dismissal():
    # scanner snippet nowhere in source (stale index / wrong revision) -> NMD, not FP
    r = resolve_anchor(_f("x.php", "php", 3, "eval($totally_absent);", "eval-use"), _PHP_SRC)
    assert r.resolution == ABSENT
