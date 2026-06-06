# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

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


class TestSarifEnrichment:
    """Tests for SARIF enrichment: precision, severity, CWE, relatedLocations."""

    def _make_sarif_with_rules(self, rules: list, results: list) -> dict:
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "CodeQL",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    def test_rule_properties_extracted(self, tmp_path):
        data = self._make_sarif_with_rules(
            rules=[
                {
                    "id": "cpp/use-after-free",
                    "properties": {
                        "precision": "high",
                        "security-severity": "9.8",
                        "tags": ["CWE-416", "security", "correctness"],
                    },
                }
            ],
            results=[
                {
                    "ruleId": "cpp/use-after-free",
                    "message": {"text": "Use after free"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/buf.c"},
                                "region": {"startLine": 10},
                            }
                        }
                    ],
                }
            ],
        )
        sarif_file = tmp_path / "test.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "repo")

        assert len(findings) == 1
        f = findings[0]
        assert f.precision == "high"
        assert f.severity == "9.8"
        assert f.cwe_ids == ["CWE-416"]
        assert "security" in f.tags
        assert "CWE-416" not in f.tags

    def test_related_locations_extracted(self, tmp_path):
        data = self._make_sarif_with_rules(
            rules=[],
            results=[
                {
                    "ruleId": "cpp/use-after-free",
                    "message": {"text": "Use after free"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "src/buf.c"},
                                "region": {"startLine": 42},
                            }
                        }
                    ],
                    "relatedLocations": [
                        {
                            "location": {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/buf.c"},
                                    "region": {"startLine": 30},
                                },
                                "message": {"text": "pointer freed here"},
                            }
                        }
                    ],
                }
            ],
        )
        sarif_file = tmp_path / "related.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "repo")

        assert len(findings) == 1
        assert len(findings[0].related_locations) == 1
        assert "src/buf.c:30" in findings[0].related_locations[0]
        assert "pointer freed here" in findings[0].related_locations[0]

    def test_result_level_as_severity_fallback(self, tmp_path):
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": "cpp/overflow",
                            "level": "error",
                            "message": {"text": "Buffer overflow"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "src/a.c"},
                                        "region": {"startLine": 5},
                                    }
                                }
                            ],
                        }
                    ]
                }
            ],
        }
        sarif_file = tmp_path / "level.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "repo")

        assert findings[0].severity == "error"
        assert findings[0].precision == ""
        assert findings[0].cwe_ids == []

    def test_no_rules_array_graceful(self, tmp_path):
        """No crash or error when rules[] is absent."""
        data = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "CodeQL"}},
                    "results": [
                        {
                            "ruleId": "cpp/overflow",
                            "message": {"text": "Overflow"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.c"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
        sarif_file = tmp_path / "norules.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "repo")

        assert len(findings) == 1
        f = findings[0]
        assert f.severity == ""
        assert f.precision == ""
        assert f.cwe_ids == []
        assert f.tags == []
        assert f.related_locations == []

    def test_security_severity_preferred_over_level(self, tmp_path):
        data = self._make_sarif_with_rules(
            rules=[
                {
                    "id": "cpp/uaf",
                    "properties": {"security-severity": "8.1"},
                }
            ],
            results=[
                {
                    "ruleId": "cpp/uaf",
                    "level": "warning",
                    "message": {"text": "UAF"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": "a.c"},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                }
            ],
        )
        sarif_file = tmp_path / "pref.sarif"
        _write_sarif(sarif_file, data)

        findings = parse_sarif_file(sarif_file, "c", "repo")

        # security-severity score takes priority over SARIF level
        assert findings[0].severity == "8.1"


class TestDiscoverSarifFiles:
    def test_discovers_codeql_semgrep_and_opengrep(self, tmp_path):
        repo_dir = tmp_path / "c" / "myrepo"
        repo_dir.mkdir(parents=True)
        (repo_dir / "myrepo.sarif").write_text("{}")
        (repo_dir / "myrepo_semgrep.sarif").write_text("{}")
        (repo_dir / "myrepo_opengrep.sarif").write_text("{}")

        results = discover_sarif_files(tmp_path)

        assert len(results) == 3
        names = {r[0].name for r in results}
        assert "myrepo.sarif" in names
        assert "myrepo_semgrep.sarif" in names
        assert "myrepo_opengrep.sarif" in names
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


class TestToolNameFallback:
    """Test that tool name is correctly inferred from filename when SARIF lacks tool.driver.name."""

    SARIF_NO_TOOL_NAME = {
        "version": "2.1.0",
        "runs": [
            {
                "results": [
                    {
                        "ruleId": "test-rule",
                        "message": {"text": "test"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/foo.c"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    def test_codeql_sarif_fallback(self, tmp_path):
        sarif_file = tmp_path / "myrepo.sarif"
        _write_sarif(sarif_file, self.SARIF_NO_TOOL_NAME)
        findings = parse_sarif_file(sarif_file, "c", "myrepo")
        assert findings[0].tool == "CodeQL"

    def test_semgrep_sarif_fallback(self, tmp_path):
        sarif_file = tmp_path / "myrepo_semgrep.sarif"
        _write_sarif(sarif_file, self.SARIF_NO_TOOL_NAME)
        findings = parse_sarif_file(sarif_file, "c", "myrepo")
        assert findings[0].tool == "Semgrep"

    def test_opengrep_sarif_fallback(self, tmp_path):
        sarif_file = tmp_path / "myrepo_opengrep.sarif"
        _write_sarif(sarif_file, self.SARIF_NO_TOOL_NAME)
        findings = parse_sarif_file(sarif_file, "c", "myrepo")
        assert findings[0].tool == "OpenGrep"


def _sarif_with_driver_name(driver_name: str) -> dict:
    """Return a minimal SARIF dict with tool.driver.name set to *driver_name*."""
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": driver_name}},
                "results": [
                    {
                        "ruleId": "test-rule",
                        "message": {"text": "test"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/foo.c"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


class TestToolNameNormalization:
    """Test that raw tool.driver.name values are normalized to canonical labels."""

    @pytest.mark.parametrize(
        "raw_name,expected",
        [
            ("opengrep", "OpenGrep"),
            ("OpenGrep", "OpenGrep"),
            ("OPENGREP", "OpenGrep"),
            ("semgrep", "Semgrep"),
            ("Semgrep", "Semgrep"),
            ("SEMGREP", "Semgrep"),
            ("codeql", "CodeQL"),
            ("CodeQL", "CodeQL"),
            ("CODEQL", "CodeQL"),
        ],
    )
    def test_known_tool_names_normalized(self, tmp_path, raw_name: str, expected: str):
        sarif_file = tmp_path / "myrepo.sarif"
        _write_sarif(sarif_file, _sarif_with_driver_name(raw_name))
        findings = parse_sarif_file(sarif_file, "c", "myrepo")
        assert findings[0].tool == expected

    def test_unknown_tool_name_preserved(self, tmp_path):
        """Unknown tool names are kept as-is rather than silently dropped."""
        sarif_file = tmp_path / "myrepo.sarif"
        _write_sarif(sarif_file, _sarif_with_driver_name("MyCustomTool"))
        findings = parse_sarif_file(sarif_file, "c", "myrepo")
        assert findings[0].tool == "MyCustomTool"


class TestNonSecurityRuleFiltering:
    """Code-quality lint rules are dropped at parse time (not vulnerabilities)."""

    def _sarif_with_rules(self, rule_ids):
        return {
            "version": "2.1.0",
            "runs": [
                {
                    "results": [
                        {
                            "ruleId": rid,
                            "message": {"text": "msg"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "a.ts"},
                                        "region": {"startLine": 1, "endLine": 1},
                                    }
                                }
                            ],
                        }
                        for rid in rule_ids
                    ]
                }
            ],
        }

    def test_unused_local_variable_dropped(self, tmp_path):
        p = tmp_path / "q.sarif"
        _write_sarif(p, self._sarif_with_rules(
            ["js/unused-local-variable", "js/sql-injection", "js/trivial-conditional"]
        ))
        findings = SarifParser(p).parse_findings("javascript", "repo")
        ids = {f.rule_id for f in findings}
        assert ids == {"js/sql-injection"}

    def test_security_rules_preserved(self, tmp_path):
        p = tmp_path / "q.sarif"
        _write_sarif(p, self._sarif_with_rules(
            ["js/prototype-pollution-ext", "js/missing-authentication"]
        ))
        findings = SarifParser(p).parse_findings("javascript", "repo")
        assert len(findings) == 2

    def test_expanded_quality_lint_dropped(self, tmp_path):
        # Quality smells that flooded the eoffice-superweb SPA scan.
        p = tmp_path / "q.sarif"
        _write_sarif(p, self._sarif_with_rules([
            "js/redundant-operation",
            "js/unneeded-defensive-code",
            "js/useless-assignment-to-local",
            "js/unreachable-statement",
            "js/nosql-injection",  # security — must survive
        ]))
        findings = SarifParser(p).parse_findings("javascript", "repo")
        assert {f.rule_id for f in findings} == {"js/nosql-injection"}

    def test_comparison_incompatible_types_preserved(self, tmp_path):
        # NOT denylisted — can hide real type-confusion bugs.
        p = tmp_path / "q.sarif"
        _write_sarif(p, self._sarif_with_rules(["js/comparison-between-incompatible-types"]))
        findings = SarifParser(p).parse_findings("javascript", "repo")
        assert len(findings) == 1
