# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P3a — structured observation + anchor fidelity (closes #118).

Covers the reported-snippet retention, the re-aligned analysis anchor, the
structural-gate Needs-More-Data for unplaceable anchors, and finalizer isolation.
Deterministic — no LLM.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

from vuln_hunter_x.core.types import Finding, Verdict, VerdictType
from vuln_hunter_x.sarif.parser import SarifParser


# --------------------------------------------------------------------------- #
# Task 1 — reported snippet retention
# --------------------------------------------------------------------------- #
def test_finding_snippet_fields_default_empty_and_roundtrip():
    f = Finding(
        rule_id="cpp/double-free", message="m", file="imgRead.c",
        start_line=62, end_line=62, repo_name="dvcp", lang="cpp",
    )
    assert f.sink_snippet == ""
    assert f.start_column == 0 and f.end_column == 0

    f2 = Finding(
        rule_id="cpp/double-free", message="m", file="imgRead.c",
        start_line=62, end_line=62, repo_name="dvcp", lang="cpp",
        sink_snippet="free(buff1);", start_column=5, end_column=17,
    )
    restored = Finding.from_dict(f2.to_dict())
    assert restored.sink_snippet == "free(buff1);"
    assert restored.start_column == 5 and restored.end_column == 17


def _write_sarif(tmp_path: Path, region: dict) -> Path:
    doc = {
        "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": [
                {"id": "cpp/double-free",
                 "properties": {"tags": ["external/cwe/cwe-415"]}}
            ]}},
            "results": [{
                "ruleId": "cpp/double-free",
                "message": {"text": "double free of buff1"},
                "locations": [{"physicalLocation": {
                    "artifactLocation": {"uri": "imgRead.c"},
                    "region": region,
                }}],
            }],
        }],
    }
    p = tmp_path / "codeql.sarif"
    p.write_text(json.dumps(doc))
    return p


def test_parser_retains_region_snippet(tmp_path):
    p = _write_sarif(tmp_path, {
        "startLine": 34, "startColumn": 5, "endColumn": 17,
        "snippet": {"text": "free(buff1);"},
    })
    findings = SarifParser(p).parse_findings("cpp", "dvcp")
    assert findings[0].sink_snippet == "free(buff1);"
    assert findings[0].start_column == 5 and findings[0].end_column == 17


def test_parser_snippet_absent_is_empty(tmp_path):
    p = _write_sarif(tmp_path, {"startLine": 34})
    findings = SarifParser(p).parse_findings("cpp", "dvcp")
    assert findings[0].sink_snippet == ""
