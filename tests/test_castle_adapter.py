# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for benchmarks.adapters.castle_adapter (synthetic tmp_path tree)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.adapters.castle_adapter import CastleAdapter
from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP
from benchmarks.adapters.registry import get_adapter, load_dataset


def _test(
    tid: str, cwe: int, vulnerable: bool, lines: list[int], code: str = "int main(){}\n"
) -> dict:
    return {
        "name": f"CASTLE-{tid}.c",
        "id": tid,
        "vulnerable": vulnerable,
        "cwe": cwe,
        "lines": lines,
        "description": "desc",
        "code": code,
    }


def _write(root: Path, tests: list[dict], rel: str = "datasets/CASTLE-C250.json") -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"tests": tests}))


def test_registered():
    assert get_adapter("castle") is CastleAdapter


def test_labels_sink_and_metadata(tmp_path):
    _write(tmp_path, [_test("22-1", 22, True, [16, 19]), _test("22-7", 22, False, [])])
    entries = CastleAdapter(tmp_path).load()
    by_id = {e.id: e for e in entries}
    tp, fp = by_id["castle_22-1"], by_id["castle_22-7"]
    assert tp.label == LABEL_TP and tp.sink_line == 16 and tp.lang == "c"
    assert tp.cwe_id == "CWE-22" and tp.metadata["vulnerable_lines"] == [16, 19]
    assert tp.metadata["original_filename"] == "CASTLE-22-1.c"
    assert fp.label == LABEL_FP and fp.sink_line is None
    assert tp.source_dataset == "castle"


def test_cwes_filter_and_per_cwe_limit(tmp_path):
    tests = [_test(f"22-{i}", 22, i % 2 == 0, [3] if i % 2 == 0 else []) for i in range(8)]
    tests += [_test("78-1", 78, True, [2])]
    _write(tmp_path, tests)
    a = CastleAdapter(tmp_path)
    assert {e.cwe_id for e in a.load(cwes=["78"])} == {"CWE-78"}
    capped = a.load(cwes=["CWE-22"], per_cwe_limit=4)
    assert [e.label for e in capped].count(LABEL_TP) == 2
    assert [e.label for e in capped].count(LABEL_FP) == 2
    assert len(a.load(limit=3)) == 3


def test_min_json_and_source_file_fallback(tmp_path):
    t = _test("1-1", 1, True, [1])
    del t["code"]
    _write(tmp_path, [t], rel="datasets/CASTLE-C250.min.json")
    src = tmp_path / "datasets" / "CASTLE-C250"
    src.mkdir()
    (src / "CASTLE-1-1.c").write_text("int x;\n")
    assert CastleAdapter(tmp_path).load()[0].code_snippet == "int x;\n"


def test_registry_option_coercion(tmp_path):
    _write(tmp_path, [_test("22-1", 22, True, [1]), _test("78-1", 78, True, [1])])
    out = load_dataset("castle", tmp_path, options={"cwes": "CWE-78"})
    assert [e.cwe_id for e in out] == ["CWE-78"]


def test_missing_dataset_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        CastleAdapter(tmp_path).load()
