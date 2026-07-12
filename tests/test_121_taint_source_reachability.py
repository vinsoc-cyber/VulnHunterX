# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""#121 — the verifier must weight the scanner's data-flow SOURCE: a remote/request
source means external reachability is already established; a command-line/operator
source is not an external trust boundary. Both facts are already in Finding.dataflow_path."""
from __future__ import annotations

from vuln_hunter_x.llm.prompts import PromptBuilder
from vuln_hunter_x.verification.engine import (
    _classify_dataflow_source_kind,
    _dataflow_source_note,
    _first_source_step,
)


def test_first_source_step_skips_flow_separators():
    assert _first_source_step(["--- Flow 1 ---", "line 34: req.body", "line 34: eval"]) == "line 34: req.body"
    assert _first_source_step([]) == ""


def test_classify_remote_source():
    # NodeGoat eval case: source is req.body
    assert _classify_dataflow_source_kind(["line 34: req.body", "line 34: req.body.roth"]) == "remote"
    assert _classify_dataflow_source_kind(["line 5: $_REQUEST['ip']"]) == "remote"


def test_classify_operator_cli_source():
    # dvcp path-injection case: source is **argv
    assert _classify_dataflow_source_kind(["line 126: **argv", "line 132: *access to array"]) == "operator_cli"
    assert _classify_dataflow_source_kind(["line 3: getenv(\"PATH\")"]) == "operator_cli"


def test_classify_unknown_is_failsafe():
    assert _classify_dataflow_source_kind(["line 7: localBuffer"]) == ""
    assert _classify_dataflow_source_kind([]) == ""


def test_dataflow_source_note_remote_and_filter_safe():
    note = _dataflow_source_note(["line 34: req.body", "line 34: req.body.roth"])
    assert len(note) == 1
    (key, text), = note.items()
    assert "remote" in key.lower()
    assert "reachab" in text.lower()
    # must survive the client.py:479 prefetch filter
    assert "[No " not in text and "[Unknown" not in text


def test_dataflow_source_note_operator_gated_by_class():
    # A/B 11e2a2f regressed 10 real memory-safety findings because the operator/CLI
    # "not a trust boundary → weight FP" note fired class-blindly. It must apply ONLY
    # to trust-boundary classes; for memory-safety/format-string, argv is a valid
    # exploit vector.
    # trust-boundary class (path-injection) → note fires
    note = _dataflow_source_note(["line 126: **argv"], "cpp/path-injection")
    (key, text), = note.items()
    assert "operator" in key.lower() or "command-line" in key.lower()
    assert "false positive" in text.lower()
    # memory-safety / format-string classes → suppressed (no note)
    assert _dataflow_source_note(["line 126: **argv"], "cpp/unbounded-write") == {}
    assert _dataflow_source_note(["line 10: **argv"], "cpp/tainted-format-string") == {}
    assert _dataflow_source_note(["line 9: **argv"], "cpp/non-constant-format") == {}
    # remote source is NOT gated by class — fires regardless of rule
    assert _dataflow_source_note(["line 34: req.body"], "cpp/unbounded-write") != {}
    # unknown source → nothing
    assert _dataflow_source_note(["line 7: localBuffer"], "cpp/path-injection") == {}


def test_system_prompt_has_taint_source_clause():
    sp = PromptBuilder().get_system_prompt(tool_name="CodeQL", lang="javascript")
    low = sp.lower()
    assert "taint-source" in low or "data-flow source" in low
    # remote source ⇒ reachability established, don't hedge — this is the ONLY
    # taint-source guidance in the GLOBAL prompt; it is ungated and safe.
    assert "remote" in low and "reachab" in low
    # reachability, not exploitability — a visible sanitizer is still FP
    assert "exploitab" in low
    # the operator-CLI "weight FP" guidance must NOT live in the global prompt: it
    # leaked onto memory-safety findings there (A/B @0104961). It now travels only
    # via the class-gated NOTE (_dataflow_source_note).
    assert "not an external trust boundary" not in low
    # Step-0 preserved; the prompt still builds — a stray unescaped brace in the
    # added clause would raise KeyError/ValueError in get_system_prompt()'s .format().
    assert "step 0" in low
    assert '"verdict":' in sp  # strict-JSON response block intact
