# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Label-leak redaction (benchmarks/adapters/redaction.py)."""

from __future__ import annotations

import re
from pathlib import Path

from benchmarks.adapters.ground_truth import GroundTruthEntry, load_entries
from benchmarks.adapters.redaction import (
    RedactionRules,
    has_redaction_rules,
    redact_entries,
    redact_entry,
    register_redaction_rules,
)

_FIXTURES = Path(__file__).resolve().parents[1] / "benchmarks" / "fixtures"

_JULIET_CODE = """/* TEMPLATE GENERATED TESTCASE FILE
Filename: CWE121_Stack_Based_Buffer_Overflow__char_01.c
@description
CWE: 121 Stack Based Buffer Overflow
Sinks: memcpy
*/
#include "std_testcase.h"

void CWE121_Stack_Based_Buffer_Overflow__char_01_bad()
{
    char buf[10];
    /* FLAW: copy 20 bytes into a 10 byte buffer
       and more */
    memcpy(buf, src, 20);
    badSink(buf); // FLAW: sink
}

static void goodG2B()
{
    /* FIX: bounded copy */
    memcpy(buf, src, 10);
    goodG2BSink(buf);
}

void good1() { goodG2B(); }
"""


def _juliet(label: str = "TP", func: str = "bad()") -> GroundTruthEntry:
    return GroundTruthEntry(
        id="juliet_x1",
        source_dataset="juliet",
        cwe_id="CWE-121",
        rule_id="cpp/overflow",
        file_path="C/testcases/CWE121_Stack_Based_Buffer_Overflow/s01/CWE121_x_01_bad.c",
        function_name=func,
        start_line=1,
        lang="c",
        label=label,
        code_snippet=_JULIET_CODE,
        metadata={"cwe_dir": "CWE121_Stack", "filename": "CWE121_x_01_bad.c", "message": "m"},
        sink_line=15,
    )


_LEAK_RE = re.compile(r"CWE|FLAW|FIX|\bbad|\bgood|[A-Za-z_]bad|[A-Za-z_]good", re.IGNORECASE)


def test_juliet_redaction_removes_label_tokens_and_keeps_lines():
    e = _juliet()
    r = redact_entry(e)
    assert r.code_snippet.count("\n") == e.code_snippet.count("\n")
    assert len(r.code_snippet.splitlines()) == len(e.code_snippet.splitlines())
    for text in (r.code_snippet, r.file_path, r.function_name):
        assert not _LEAK_RE.search(text), text
    assert r.sink_line == e.sink_line
    # code semantics survive
    assert "memcpy(buf, src, 20);" in r.code_snippet
    assert r.function_name == "target_fn()"
    assert r.metadata["redaction"]["applied"] is True
    assert r.metadata["redaction"]["original_file_path"] == e.file_path
    assert r.metadata["redaction"]["residual_tokens"] == []
    assert "cwe_dir" not in r.metadata and "filename" in r.metadata
    assert "CWE" not in r.metadata["filename"]
    assert r.metadata["message"] == "m"


def test_redaction_is_deterministic_and_does_not_mutate_input():
    e = _juliet()
    before = e.code_snippet
    a, b = redact_entry(e), redact_entry(e)
    assert a.code_snippet == b.code_snippet and a.file_path == b.file_path
    assert e.code_snippet == before and "redaction" not in e.metadata
    assert redact_entry(a) is a  # idempotent


def test_bad_and_good_do_not_map_to_ordered_names():
    bad = redact_entry(_juliet("TP", "bad()"))
    good = redact_entry(_juliet("FP", "good()"))
    assert bad.function_name == good.function_name != "bad()"


def test_secllmholmes_prefix_and_cwe_removed():
    e = GroundTruthEntry(
        id="slh_1",
        source_dataset="secllmholmes",
        cwe_id="CWE-416",
        rule_id="r",
        file_path="dataset_hand-crafted/c/CWE-416/p_1.c",
        function_name="",
        start_line=1,
        lang="c",
        label="FP",
        code_snippet="// CWE-416 sample\nint main(){return 0;}\n",
        metadata={"variant": "hand-crafted", "filename": "p_1.c"},
        sink_line=2,
    )
    r = redact_entry(e)
    assert "p_" not in r.file_path and "CWE" not in r.file_path
    assert r.file_path.endswith(".c")
    assert "CWE" not in r.code_snippet
    assert r.code_snippet.count("\n") == e.code_snippet.count("\n")
    assert r.metadata["redaction"]["original_file_path"] == e.file_path
    n = redact_entry(
        GroundTruthEntry(**{**e.to_dict(), "id": "slh_2", "file_path": "x/CWE-416/n_1.c"})
    )
    assert "n_" not in n.file_path


def test_fixtures_clean_after_redaction():
    for name in ("juliet", "secllmholmes"):
        for e in redact_entries(load_entries(_FIXTURES / f"{name}_sample.json")):
            for text in (e.code_snippet, e.file_path, e.function_name):
                assert not re.search(r"CWE|FLAW|FIX", text), (name, text)
                assert not re.search(r"(?:^|[/_])(?:bad|good)", text, re.IGNORECASE), text
            assert not re.search(r"(?:^|/)[pn]_\d", e.file_path)
            assert e.metadata["redaction"]["applied"]


def test_unregistered_dataset_untouched_and_opt_in():
    e = GroundTruthEntry(
        id="c1",
        source_dataset="castle_x",
        cwe_id="CWE-79",
        rule_id="",
        file_path="CWE-79_a.c",
        function_name="bad()",
        start_line=1,
        lang="c",
        label="TP",
        code_snippet="/* FLAW */\n",
    )
    assert redact_entry(e) is e
    assert not has_redaction_rules("castle_x")
    register_redaction_rules("castle_x", RedactionRules(rename_label_identifiers=True))
    try:
        r = redact_entry(e)
        assert r is not e and "FLAW" not in r.code_snippet and "CWE" not in r.file_path
    finally:
        from benchmarks.adapters import redaction

        redaction._RULES.pop("castle_x", None)
