# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""#121 — the verifier must weight the scanner's data-flow SOURCE: a remote/request
source means external reachability is already established; a command-line/operator
source is not an external trust boundary. Both facts are already in Finding.dataflow_path."""
from __future__ import annotations

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


def test_dataflow_source_note_operator_and_unknown():
    note = _dataflow_source_note(["line 126: **argv"])
    (key, text), = note.items()
    assert "operator" in key.lower() or "command-line" in key.lower()
    assert "false positive" in text.lower()
    assert _dataflow_source_note(["line 7: localBuffer"]) == {}
