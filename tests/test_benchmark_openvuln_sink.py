# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""OpenVuln adapter: sink_line derivation from the shipped SARIF."""

from __future__ import annotations

import json
from pathlib import Path

from benchmarks.adapters.ground_truth import load_entries
from benchmarks.adapters.openvuln_adapter import OpenVulnAdapter


def _dataset(tmp_path: Path, sarif_rule: str = "java/path-injection") -> Path:
    base = tmp_path / "OpenVuln"
    (base / "sarif-files").mkdir(parents=True)
    (base / "ground_truth.csv").write_text(
        "project_slug,alert_number,cve_id,filename,is_vulnerable\n"
        "proj,1,CVE-1,vulnerability_java_path-injection_1.txt,True\n"
        "proj,2,CVE-1,vulnerability_java_path-injection_2.txt,False\n"
        "proj,9,CVE-1,vulnerability_java_path-injection_9.txt,False\n"
        "nosarif,1,CVE-2,vulnerability_java_xss_1.txt,True\n"
    )

    def _res(line: int) -> dict:
        return {
            "ruleId": sarif_rule,
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": "src/A.java"},
                        "region": {"startLine": line},
                    }
                }
            ],
        }

    (base / "sarif-files" / "proj.sarif").write_text(
        json.dumps({"runs": [{"results": [_res(42), _res(77)]}]})
    )
    return tmp_path


def test_sink_line_derived_from_sarif(tmp_path):
    by_id = {e.id: e for e in OpenVulnAdapter(_dataset(tmp_path)).load()}
    e1 = by_id["openvuln-proj-1"]
    assert e1.sink_line == 42 and e1.is_line_anchored
    assert e1.metadata["sink_line_source"] == "sarif"
    assert by_id["openvuln-proj-2"].sink_line == 77


def test_unresolvable_left_none_with_reason(tmp_path):
    by_id = {e.id: e for e in OpenVulnAdapter(_dataset(tmp_path)).load()}
    assert by_id["openvuln-proj-9"].sink_line is None
    assert by_id["openvuln-proj-9"].metadata["sink_line_reason"] == "alert_index_out_of_range"
    assert by_id["openvuln-nosarif-1"].metadata["sink_line_reason"] == "sarif_missing_or_empty"


def test_rule_mismatch_not_guessed(tmp_path):
    entries = OpenVulnAdapter(_dataset(tmp_path, sarif_rule="java/xss")).load()
    e1 = next(e for e in entries if e.id == "openvuln-proj-1")
    assert e1.sink_line is None
    assert e1.metadata["sink_line_reason"] == "sarif_rule_mismatch"


def test_fixture_entries_are_anchored():
    fixture = Path(__file__).resolve().parents[1] / "benchmarks/fixtures/openvuln_sample.json"
    entries = load_entries(fixture)
    assert entries and all(e.is_line_anchored for e in entries)
    assert all(e.metadata["sink_line_source"] == "fixture" for e in entries)
