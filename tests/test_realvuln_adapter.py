# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for benchmarks.adapters.realvuln_adapter."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, load_entries
from benchmarks.adapters.realvuln_adapter import RealVulnAdapter, _normalize_cwe


# ── Schema fixture builder ────────────────────────────────────────────────────

def _write_manifest(root: Path, repo_id: str, findings: list[dict]) -> Path:
    """Write a ground-truth.json under root/ground-truth/<repo_id>/."""
    manifest_dir = root / "ground-truth" / repo_id
    manifest_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "repo_id": repo_id,
        "repo_url": f"https://example.com/{repo_id}",
        "commit_sha": "deadbeef",
        "language": "python",
        "framework": "flask",
        "findings": findings,
    }
    path = manifest_dir / "ground-truth.json"
    path.write_text(json.dumps(manifest))
    return path


def _finding(
    fid: str, is_vuln: bool, cwe: str, file: str, sl: int, el: int,
    function: str = "f", source: str = "cve", cve_id: str = ""
) -> dict:
    return {
        "id": fid,
        "is_vulnerable": is_vuln,
        "primary_cwe": cwe,
        "vulnerability_class": "xss",
        "file": file,
        "location": {"start_line": sl, "end_line": el, "function": function},
        "evidence": {"source": source, "cve_id": cve_id},
    }


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestCweNormalization:
    def test_already_prefixed(self):
        assert _normalize_cwe("CWE-89") == "CWE-89"

    def test_lowercase_prefixed(self):
        assert _normalize_cwe("cwe-89") == "CWE-89"

    def test_bare_number(self):
        assert _normalize_cwe("89") == "CWE-89"
        assert _normalize_cwe(89) == "CWE-89"

    def test_empty(self):
        assert _normalize_cwe(None) == ""
        assert _normalize_cwe("") == ""


class TestRealVulnAdapter:
    def test_loads_tp_and_fp(self, tmp_path):
        _write_manifest(tmp_path, "repo-A", [
            _finding("a1", True,  "CWE-79", "app.py", 10, 12, source="cve", cve_id="CVE-1"),
            _finding("a2", False, "CWE-79", "app.py", 30, 32, source="semgrep"),
        ])
        entries = RealVulnAdapter(tmp_path).load()
        assert len(entries) == 2
        labels = {e.id: e.label for e in entries}
        assert labels["realvuln-repo-A-a1"] == LABEL_TP
        assert labels["realvuln-repo-A-a2"] == LABEL_FP

    def test_cwe_and_rule_id(self, tmp_path):
        _write_manifest(tmp_path, "r", [
            _finding("f", True, "89", "x.py", 1, 5),
        ])
        e = RealVulnAdapter(tmp_path).load()[0]
        assert e.cwe_id == "CWE-89"
        # primary_rule for CWE-89 starts with py/ in the current map ordering
        assert e.rule_id.startswith("py/")

    def test_metadata_carries_evidence(self, tmp_path):
        _write_manifest(tmp_path, "r", [
            _finding("f", True, "CWE-22", "x.py", 1, 5,
                     source="cve", cve_id="CVE-2024-9999"),
        ])
        e = RealVulnAdapter(tmp_path).load()[0]
        assert e.metadata["repo_id"] == "r"
        assert e.metadata["commit_sha"] == "deadbeef"
        assert e.metadata["evidence_source"] == "cve"
        assert e.metadata["cve_id"] == "CVE-2024-9999"
        assert e.metadata["end_line"] == 5
        assert e.metadata["vulnerability_class"] == "xss"

    def test_skips_findings_without_cwe(self, tmp_path):
        _write_manifest(tmp_path, "r", [
            _finding("f1", True, "", "x.py", 1, 5),
            _finding("f2", True, "CWE-22", "x.py", 1, 5),
        ])
        entries = RealVulnAdapter(tmp_path).load()
        assert len(entries) == 1
        assert entries[0].cwe_id == "CWE-22"

    def test_limit_caps_entries(self, tmp_path):
        _write_manifest(tmp_path, "r", [
            _finding(f"f{i}", True, "CWE-22", "x.py", i, i + 1)
            for i in range(1, 11)
        ])
        entries = RealVulnAdapter(tmp_path).load(limit=4)
        assert len(entries) == 4

    def test_missing_ground_truth_dir_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            RealVulnAdapter(tmp_path).load()

    def test_corrupt_manifest_skipped(self, tmp_path):
        good = _write_manifest(tmp_path, "good", [
            _finding("g", True, "CWE-79", "x.py", 1, 5),
        ])
        bad_dir = tmp_path / "ground-truth" / "bad"
        bad_dir.mkdir(parents=True)
        (bad_dir / "ground-truth.json").write_text("{ not json")
        entries = RealVulnAdapter(tmp_path).load()
        assert len(entries) == 1
        assert entries[0].id.startswith("realvuln-good-")
        assert good.exists()  # sanity

    def test_snippet_resolver_injected(self, tmp_path):
        _write_manifest(tmp_path, "r", [
            _finding("f", True, "CWE-79", "x.py", 1, 5),
        ])
        called = {}

        def resolver(repo_id: str, finding: dict) -> str:
            called["repo_id"] = repo_id
            called["fid"] = finding["id"]
            return "FAKE_SOURCE"

        e = RealVulnAdapter(tmp_path, code_resolver=resolver).load()[0]
        assert e.code_snippet == "FAKE_SOURCE"
        assert e.metadata["snippet_kind"] == "resolver"
        assert called == {"repo_id": "r", "fid": "f"}

    def test_snippet_from_repos_cache(self, tmp_path):
        _write_manifest(tmp_path, "r", [
            _finding("f", True, "CWE-79", "src/app.py", 2, 3, function="hello"),
        ])
        cache = tmp_path / "_repos" / "r" / "src"
        cache.mkdir(parents=True)
        (cache / "app.py").write_text(
            "import flask\n"
            "def hello():\n"
            "    return 'hi'\n"
            "# trailing\n"
        )
        e = RealVulnAdapter(tmp_path).load()[0]
        assert "def hello" in e.code_snippet
        assert e.metadata["snippet_kind"] == "checkout"

    def test_snippet_missing_when_no_checkout(self, tmp_path):
        _write_manifest(tmp_path, "r", [
            _finding("f", True, "CWE-79", "x.py", 1, 5),
        ])
        e = RealVulnAdapter(tmp_path).load()[0]
        assert e.code_snippet == ""
        assert e.metadata["snippet_kind"] == "missing"


class TestRealVulnFixture:
    FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "fixtures" / "realvuln_sample.json"

    def test_fixture_loads(self):
        entries = load_entries(self.FIXTURE)
        assert len(entries) >= 5
        assert {e.lang for e in entries} == {"python"}
        assert {e.label for e in entries} == {LABEL_TP, LABEL_FP}
        cwes = {e.cwe_id for e in entries}
        assert {"CWE-79", "CWE-89", "CWE-22"} <= cwes
