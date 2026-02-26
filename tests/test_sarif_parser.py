"""Tests for SARIF file parsing and discovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from vuln_hunter_x.sarif.parser import SarifParser, discover_sarif_files, parse_sarif_file


def _write_sarif(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data))


MINIMAL_SARIF = {
    "version": "2.1.0",
    "runs": [
        {
            "results": [
                {
                    "ruleId": "cpp/use-after-free",
                    "message": {"text": "Use of pointer after free"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/buf.c"},
                                "region": {"startLine": 42, "endLine": 44},
                            }
                        }
                    ],
                }
            ]
        }
    ],
}


class TestSarifParserParsing:
    def test_parse_basic_finding(self, tmp_path):
        sarif_file = tmp_path / "test.sarif"
        _write_sarif(sarif_file, MINIMAL_SARIF)

        findings = parse_sarif_file(sarif_file, "c", "myrepo")

        assert len(findings) == 1
        f = findings[0]
        assert f.rule_id == "cpp/use-after-free"
        assert f.file == "src/buf.c"
        assert f.start_line == 42
        assert f.end_line == 44
        assert f.repo_name == "myrepo"
        assert f.lang == "c"

    def test_parse_empty_runs(self, tmp_path):
        sarif_file = tmp_path / "empty.sarif"
        _write_sarif(sarif_file, {"version": "2.1.0", "runs": []})

        findings = parse_sarif_file(sarif_file, "c", "myrepo")

        assert findings == []

    def test_parse_missing_runs_key(self, tmp_path):
        sarif_file = tmp_path / "noruns.sarif"
        _write_sarif(sarif_file, {"version": "2.1.0"})

        findings = parse_sarif_file(sarif_file, "c", "myrepo")

        assert findings == []

    def test_parse_result_without_location(self, tmp_path):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "cpp/overflow",
                            "message": {"text": "Overflow"},
                        }
                    ]
                }
            ],
        }
        sarif_file = tmp_path / "noloc.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "myrepo")

        assert len(findings) == 1
        assert findings[0].file == ""
        assert findings[0].start_line == 0

    def test_parse_start_line_defaults_to_one_when_region_missing(self, tmp_path):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "cpp/test",
                            "message": {"text": "msg"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "foo.c"},
                                        # No "region" key
                                    }
                                }
                            ],
                        }
                    ]
                }
            ],
        }
        sarif_file = tmp_path / "noregion.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "myrepo")

        assert len(findings) == 1
        assert findings[0].start_line == 1

    def test_artifact_index_resolution(self, tmp_path):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "artifacts": [
                        {"location": {"uri": "resolved/path.c"}},
                    ],
                    "results": [
                        {
                            "ruleId": "cpp/test",
                            "message": {"text": "msg"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "fallback.c", "index": 0},
                                        "region": {"startLine": 10},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        sarif_file = tmp_path / "artifact.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "myrepo")

        assert findings[0].file == "resolved/path.c"

    def test_file_not_found_raises(self, tmp_path):
        with pytest.raises(FileNotFoundError):
            parse_sarif_file(tmp_path / "nonexistent.sarif", "c", "repo")

    def test_multiple_results_parsed(self, tmp_path):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": f"cpp/rule-{i}",
                            "message": {"text": f"msg {i}"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": f"src/file{i}.c"},
                                        "region": {"startLine": i + 1},
                                    }
                                }
                            ],
                        }
                        for i in range(5)
                    ]
                }
            ],
        }
        sarif_file = tmp_path / "multi.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "myrepo")

        assert len(findings) == 5
        assert {f.rule_id for f in findings} == {f"cpp/rule-{i}" for i in range(5)}


class TestDiscoverSarifFiles:
    def test_discovers_codeql_and_semgrep(self, tmp_path):
        repo_dir = tmp_path / "c" / "myrepo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "myrepo.sarif").write_text("{}")
        (repo_dir / "myrepo_semgrep.sarif").write_text("{}")

        results = discover_sarif_files(tmp_path)

        assert len(results) == 2
        names = {r[0].name for r in results}
        assert "myrepo.sarif" in names
        assert "myrepo_semgrep.sarif" in names
        for _, lang, repo_name in results:
            assert lang == "c"
            assert repo_name == "myrepo"

    def test_repo_name_from_directory(self, tmp_path):
        repo_dir = tmp_path / "python" / "dvpwa"
        repo_dir.mkdir(parents=True)
        (repo_dir / "dvpwa.sarif").write_text("{}")

        results = discover_sarif_files(tmp_path)

        assert len(results) == 1
        assert results[0][2] == "dvpwa"
        assert results[0][1] == "python"

    def test_empty_output_dir(self, tmp_path):
        results = discover_sarif_files(tmp_path / "nonexistent")
        assert results == []

    def test_multiple_langs_and_repos(self, tmp_path):
        for lang, repo in [("c", "repo1"), ("python", "repo2"), ("javascript", "repo3")]:
            d = tmp_path / lang / repo
            d.mkdir(parents=True)
            (d / f"{repo}.sarif").write_text("{}")

        results = discover_sarif_files(tmp_path)

        assert len(results) == 3
        langs = {r[1] for r in results}
        assert langs == {"c", "python", "javascript"}
