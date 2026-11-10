# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for benchmarks.adapters.perturbation and the SecLLMHolmes options."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.adapters.ground_truth import GroundTruthEntry
from benchmarks.adapters.perturbation import KINDS, perturb_entry
from benchmarks.adapters.secllmholmes_adapter import SecLLMHolmesAdapter

C_CODE = """#include <stdio.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char buf[16];
    int count = 0;
    strcpy(buf, argv[1]);
    printf("buf %s count %d\\n", buf, count);
    return 0;
}
"""
PY_CODE = """import os
from flask import request

def view():
    name = request.args.get("name")
    query = f"select * from t where n = {name}"
    cursor.execute(query)
    return name
"""


def _entry(code: str, lang: str, sink: int | None, cwe: str = "CWE-89") -> GroundTruthEntry:
    return GroundTruthEntry(
        id="e1",
        source_dataset="t",
        cwe_id=cwe,
        rule_id="",
        file_path="f",
        function_name="",
        start_line=1,
        lang=lang,
        label="TP",
        code_snippet=code,
        metadata={"k": 1},
        sink_line=sink,
    )


def test_unknown_kind():
    with pytest.raises(ValueError):
        perturb_entry(_entry(C_CODE, "c", 7), "bogus")


@pytest.mark.parametrize("kind", KINDS)
def test_metadata_id_and_determinism(kind):
    e = _entry(C_CODE, "c", 7)
    a, b = perturb_entry(e, kind, 3), perturb_entry(e, kind, 3)
    assert a.code_snippet == b.code_snippet
    assert a.id == f"e1__{kind}" and a.label == e.label
    p = a.metadata["perturbation"]
    assert p["kind"] == kind and p["seed"] == 3 and p["original_id"] == "e1"
    assert a.metadata["k"] == 1 and "perturbation" not in e.metadata


def test_rename_c_preserves_lines_and_protects_strings():
    out = perturb_entry(_entry(C_CODE, "c", 7), "rename_locals", 1)
    assert out.sink_line == 7
    assert out.code_snippet.count("\n") == C_CODE.count("\n")
    ren = out.metadata["perturbation"]["renamed"]
    assert set(ren) == {"buf", "count"}  # argc/argv/main untouched
    assert "buf %s count %d" in out.code_snippet  # string literal intact
    assert f"strcpy({ren['buf']}, argv[1]);" in out.code_snippet
    assert "int main(int argc, char *argv[])" in out.code_snippet


def test_rename_python_fstring_and_kwarg():
    code = PY_CODE + "    foo(name=name)\n"
    out = perturb_entry(_entry(code, "python", 7), "rename_locals", 1)
    ren = out.metadata["perturbation"]["renamed"]
    n, q = ren["name"], ren["query"]
    assert f"{{{n}}}" in out.code_snippet  # f-string expr renamed
    assert f"cursor.execute({q})" in out.code_snippet
    assert f"foo(name={n})" in out.code_snippet  # kwarg key kept
    assert "request.args.get" in out.code_snippet
    assert out.code_snippet.count("\n") == code.count("\n")
    compile(out.code_snippet, "<p>", "exec")


def test_comment_trailing_keeps_line_count():
    out = perturb_entry(_entry(C_CODE, "c", 7), "misleading_comment", 0)
    lines = out.code_snippet.split("\n")
    assert out.sink_line == 7 and len(lines) == len(C_CODE.split("\n"))
    assert lines[6].startswith("    strcpy(buf, argv[1]);  // ")
    py = perturb_entry(_entry(PY_CODE, "python", 7), "misleading_comment", 0)
    assert "  # " in py.code_snippet.split("\n")[6]
    compile(py.code_snippet, "<p>", "exec")


def test_comment_without_sink_line_uses_heuristic():
    out = perturb_entry(_entry(C_CODE, "c", None), "misleading_comment", 0)
    assert out.metadata["perturbation"]["applied"]
    assert out.sink_line is None


def test_sanitizer_wrap_c_shifts_sink():
    out = perturb_entry(_entry(C_CODE, "c", 7, "CWE-89"), "sanitizer_wrap", 0)
    lines = out.code_snippet.split("\n")
    assert "#define escape_sql(x) (x)" in lines
    assert out.sink_line == 8
    assert "escape_sql(" in lines[out.sink_line - 1]
    assert lines.index("#define escape_sql(x) (x)") == 2  # after last include


def test_sanitizer_wrap_python_fstring():
    out = perturb_entry(_entry(PY_CODE, "python", 6, "CWE-89"), "sanitizer_wrap", 0)
    lines = out.code_snippet.split("\n")
    assert "def escape_sql(x): return x" in lines
    assert out.sink_line == 7
    assert "{escape_sql(name)}" in lines[6]
    compile(out.code_snippet, "<p>", "exec")


def test_unsupported_language_not_applied():
    out = perturb_entry(_entry("class A {}", "java", 1), "sanitizer_wrap", 0)
    assert out.metadata["perturbation"]["applied"] is False
    assert out.code_snippet == "class A {}"


# ── SecLLMHolmes options ─────────────────────────────────────────────


def _slh_tree(root: Path) -> None:
    for variant in ("hand-crafted", "augmented/trivial/A1"):
        d = root / "datasets" / variant / "dataset" / "CWE-89"
        d.mkdir(parents=True)
        (d / "1.py").write_text(PY_CODE)
        (d / "p_1.py").write_text(PY_CODE.replace("{name}", "{escape(name)}"))


def test_secllmholmes_default_unchanged(tmp_path):
    _slh_tree(tmp_path)
    entries = SecLLMHolmesAdapter(tmp_path).load()
    assert len(entries) == 4
    assert all("perturbation" not in e.metadata for e in entries)


def test_secllmholmes_perturb_option(tmp_path):
    _slh_tree(tmp_path)
    entries = SecLLMHolmesAdapter(tmp_path).load(
        perturb=["rename_locals", "misleading_comment"], perturb_seed=5
    )
    assert len(entries) == 4 + 8
    ids = {e.id for e in entries}
    perturbed = [e for e in entries if "perturbation" in e.metadata]
    assert len(perturbed) == 8
    for e in perturbed:
        assert e.metadata["perturbation"]["original_id"] in ids
        assert (
            e.id
            == f"{e.metadata['perturbation']['original_id']}__{e.metadata['perturbation']['kind']}"
        )
    with pytest.raises(ValueError):
        SecLLMHolmesAdapter(tmp_path).load(perturb=["nope"])


def test_secllmholmes_aug_as_perturbation(tmp_path):
    _slh_tree(tmp_path)
    entries = SecLLMHolmesAdapter(tmp_path).load(aug_as_perturbation=True)
    aug = [e for e in entries if "perturbation" in e.metadata]
    assert len(aug) == 2
    originals = {e.id for e in entries if "perturbation" not in e.metadata}
    for e in aug:
        assert e.metadata["perturbation"]["kind"] == "secllmholmes-aug"
        assert e.metadata["perturbation"]["original_id"] in originals
