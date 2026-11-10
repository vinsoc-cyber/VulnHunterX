# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for benchmarks.adapters.juliet_java_adapter (synthetic tree)."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP
from benchmarks.adapters.juliet_java_adapter import JulietJavaAdapter
from benchmarks.adapters.registry import get_adapter

MIXED = """package testcases;
public class X {
    public void bad() throws Throwable {
        String d = "a";
    }
    private void goodG2B() throws Throwable {
    }
    public void good() throws Throwable { goodG2B(); }
}
"""
SPLIT = """package testcases;
public class Y {
    public void action(String d) throws Throwable { }
}
"""


def _mk(root: Path, cwe_dir: str, name: str, body: str, sub: str = "s01") -> None:
    d = root / "src" / "testcases" / cwe_dir / sub
    d.mkdir(parents=True, exist_ok=True)
    (d / name).write_text(body)


def test_registered():
    assert get_adapter("juliet-java") is JulietJavaAdapter


def test_mixed_and_split_files(tmp_path):
    _mk(tmp_path, "CWE89_SQL_Injection", "CWE89_A_01.java", MIXED)
    _mk(tmp_path, "CWE89_SQL_Injection", "CWE89_A_81_bad.java", SPLIT)
    _mk(tmp_path, "CWE89_SQL_Injection", "CWE89_A_81_goodG2B.java", SPLIT)
    _mk(
        tmp_path,
        "CWE89_SQL_Injection",
        "CWE89_A_81_base.java",
        SPLIT.replace("void action", "abstract void act"),
    )
    entries = JulietJavaAdapter(tmp_path).load()
    assert len(entries) == 4  # base file skipped
    assert {e.lang for e in entries} == {"java"}
    assert {e.source_dataset for e in entries} == {"juliet-java"}
    assert all(e.cwe_id == "CWE-89" and e.rule_id.startswith("java/") for e in entries)
    tp = [e for e in entries if e.label == LABEL_TP]
    fp = [e for e in entries if e.label == LABEL_FP]
    assert len(tp) == 2 and len(fp) == 2
    mixed_tp = next(e for e in tp if e.metadata["filename"] == "CWE89_A_01.java")
    assert mixed_tp.start_line == 3
    assert mixed_tp.sink_line is None
    assert mixed_tp.metadata["cwe_dir"] == "CWE89_SQL_Injection"


def test_default_cwe_filter_and_override(tmp_path):
    _mk(tmp_path, "CWE89_SQL_Injection", "CWE89_A_01.java", MIXED)
    _mk(tmp_path, "CWE999_Other", "CWE999_A_01.java", MIXED)
    a = JulietJavaAdapter(tmp_path)
    assert {e.cwe_id for e in a.load()} == {"CWE-89"}
    assert {e.cwe_id for e in a.load(cwes=["all"])} == {"CWE-89", "CWE-999"}
    assert {e.cwe_id for e in a.load(cwes=["999"])} == {"CWE-999"}


def test_per_cwe_limit_balanced_and_spread(tmp_path):
    for i in range(10):
        _mk(tmp_path, "CWE89_SQL_Injection", f"CWE89_A_{i:02d}.java", MIXED)
    a = JulietJavaAdapter(tmp_path)
    out = a.load(per_cwe_limit=6)
    assert sum(e.label == LABEL_TP for e in out) == 3
    assert sum(e.label == LABEL_FP for e in out) == 3
    files = [e.metadata["filename"] for e in out if e.label == LABEL_TP]
    assert files[1] != "CWE89_A_01.java"  # evenly spread, not first-N
    assert len(a.load(limit=2)) == 2


def test_missing_layout_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        JulietJavaAdapter(tmp_path).load()
