# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for benchmarks.adapters.owasp_benchmark_adapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.adapters.ground_truth import LABEL_FP, LABEL_TP, load_entries
from benchmarks.adapters.owasp_benchmark_adapter import OwaspBenchmarkAdapter


# ── Synthetic mini-repo helpers ───────────────────────────────────────────────

_JAVA_SNIPPET = """package org.owasp.benchmark.testcode;
import javax.servlet.http.*;
public class BenchmarkTest{num} extends HttpServlet {{
  public void doPost(HttpServletRequest req, HttpServletResponse res) {{
    String p = req.getParameter(\"BenchmarkTest{num}\");
    // ...
  }}
}}
"""

_PY_SNIPPET = """from flask import request

def handle():
    name = request.args.get('BenchmarkTest{num}', '')
    return name
"""


def _build_java_repo(root: Path, rows: list[tuple[str, bool, str, str]]) -> Path:
    """rows: list of (test_name, is_real_vuln, cwe, category)."""
    src = root / "src" / "main" / "java" / "org" / "owasp" / "benchmark" / "testcode"
    src.mkdir(parents=True, exist_ok=True)
    for name, _, _, _ in rows:
        num = name.removeprefix("BenchmarkTest")
        (src / f"{name}.java").write_text(_JAVA_SNIPPET.format(num=num))
    csv_lines = [
        "# test name, category, real vulnerability, cwe, Benchmark version, time"
    ]
    for name, real, cwe, cat in rows:
        csv_lines.append(f"{name},{cat},{'true' if real else 'false'},{cwe},1.2,1.0")
    (root / "expectedresults-1.2.csv").write_text("\n".join(csv_lines) + "\n")
    return root


def _build_python_repo(root: Path, rows: list[tuple[str, bool, str, str]]) -> Path:
    """Mirror BenchmarkPython's real layout: testcode/BenchmarkTest*.py at root."""
    src = root / "testcode"
    src.mkdir(parents=True, exist_ok=True)
    for name, _, _, _ in rows:
        num = name.removeprefix("BenchmarkTest")
        (src / f"{name}.py").write_text(_PY_SNIPPET.format(num=num))
    csv_lines = [
        "# test name, category, real vulnerability, cwe, Benchmark version, time"
    ]
    for name, real, cwe, cat in rows:
        csv_lines.append(f"{name},{cat},{'true' if real else 'false'},{cwe},0.1,1.0")
    (root / "expectedresults-0.1.csv").write_text("\n".join(csv_lines) + "\n")
    return root


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestOwaspJavaAdapter:
    def test_loads_tp_and_fp(self, tmp_path):
        root = _build_java_repo(tmp_path / "BenchmarkJava", [
            ("BenchmarkTest00001", True,  "89", "sqli"),
            ("BenchmarkTest00002", False, "89", "sqli"),
            ("BenchmarkTest00045", True,  "22", "pathtraver"),
        ])
        entries = OwaspBenchmarkAdapter(root, lang="java").load()
        assert len(entries) == 3
        labels = {e.id: e.label for e in entries}
        assert labels["owasp-java-BenchmarkTest00001"] == LABEL_TP
        assert labels["owasp-java-BenchmarkTest00002"] == LABEL_FP
        assert labels["owasp-java-BenchmarkTest00045"] == LABEL_TP

    def test_cwe_and_rule_id(self, tmp_path):
        root = _build_java_repo(tmp_path / "BenchmarkJava", [
            ("BenchmarkTest00001", True, "89", "sqli"),
        ])
        e = OwaspBenchmarkAdapter(root, lang="java").load()[0]
        assert e.cwe_id == "CWE-89"
        # cwe_rule_map now includes java/sql-injection for CWE-89
        assert "java/" in e.rule_id or e.rule_id == ""

    def test_metadata_contains_version_and_category(self, tmp_path):
        root = _build_java_repo(tmp_path / "BenchmarkJava", [
            ("BenchmarkTest00120", True, "330", "weakrand"),
        ])
        e = OwaspBenchmarkAdapter(root, lang="java").load()[0]
        assert e.metadata["version"] == "1.2"
        assert e.metadata["category"] == "weakrand"
        assert e.metadata["test_name"] == "BenchmarkTest00120"
        assert e.lang == "java"
        assert e.source_dataset == "owasp-java"

    def test_limit_caps_entries(self, tmp_path):
        root = _build_java_repo(tmp_path / "BenchmarkJava", [
            (f"BenchmarkTest{i:05d}", True, "89", "sqli") for i in range(1, 11)
        ])
        entries = OwaspBenchmarkAdapter(root, lang="java").load(limit=4)
        assert len(entries) == 4

    def test_missing_manifest_raises(self, tmp_path):
        bad = tmp_path / "empty"
        bad.mkdir()
        with pytest.raises(FileNotFoundError):
            OwaspBenchmarkAdapter(bad, lang="java").load()

    def test_missing_source_file_skipped(self, tmp_path):
        root = _build_java_repo(tmp_path / "BenchmarkJava", [
            ("BenchmarkTest00001", True, "89", "sqli"),
        ])
        # Add an extra row whose source file is absent
        manifest = root / "expectedresults-1.2.csv"
        manifest.write_text(manifest.read_text() + "BenchmarkTest99999,sqli,true,89,1.2,1.0\n")
        entries = OwaspBenchmarkAdapter(root, lang="java").load()
        assert len(entries) == 1  # missing test file silently skipped

    def test_function_name_extracted(self, tmp_path):
        root = _build_java_repo(tmp_path / "BenchmarkJava", [
            ("BenchmarkTest00001", True, "89", "sqli"),
        ])
        e = OwaspBenchmarkAdapter(root, lang="java").load()[0]
        assert e.function_name == "doPost"


class TestOwaspPythonAdapter:
    def test_loads_python_entries(self, tmp_path):
        root = _build_python_repo(tmp_path / "BenchmarkPython", [
            ("BenchmarkTest00001", True,  "79", "xss"),
            ("BenchmarkTest00002", False, "79", "xss"),
        ])
        entries = OwaspBenchmarkAdapter(root, lang="python").load()
        assert len(entries) == 2
        assert {e.lang for e in entries} == {"python"}
        labels = {e.id: e.label for e in entries}
        assert labels["owasp-python-BenchmarkTest00001"] == LABEL_TP
        assert labels["owasp-python-BenchmarkTest00002"] == LABEL_FP

    def test_python_function_name(self, tmp_path):
        root = _build_python_repo(tmp_path / "BenchmarkPython", [
            ("BenchmarkTest00001", True, "79", "xss"),
        ])
        e = OwaspBenchmarkAdapter(root, lang="python").load()[0]
        assert e.function_name == "handle"

    def test_python_requires_testcode_dir_not_src(self, tmp_path):
        """BenchmarkPython ships files under testcode/, not src/. The adapter
        must reject a repo that only has src/ for the python lang."""
        root = tmp_path / "BenchmarkPython"
        (root / "src" / "main").mkdir(parents=True)
        (root / "src" / "main" / "BenchmarkTest00001.py").write_text(_PY_SNIPPET.format(num="00001"))
        (root / "expectedresults-0.1.csv").write_text(
            "# test name, category, real vulnerability, cwe, Benchmark version, time\n"
            "BenchmarkTest00001,xss,true,79,0.1,1.0\n"
        )
        with pytest.raises(FileNotFoundError, match="testcode/"):
            OwaspBenchmarkAdapter(root, lang="python").load()


class TestOwaspAdapterValidation:
    def test_invalid_lang_raises(self, tmp_path):
        with pytest.raises(ValueError):
            OwaspBenchmarkAdapter(tmp_path, lang="ruby")


class TestOwaspFixture:
    """Ensure the bundled fixture parses and matches expected shape."""

    FIXTURE = Path(__file__).resolve().parents[1] / "benchmarks" / "fixtures" / "owasp_benchmark_sample.json"

    def test_fixture_loads(self):
        entries = load_entries(self.FIXTURE)
        assert len(entries) >= 5
        # Must contain at least one Java + one Python entry
        langs = {e.lang for e in entries}
        assert "java" in langs
        assert "python" in langs
        # Both labels represented
        labels = {e.label for e in entries}
        assert LABEL_TP in labels
        assert LABEL_FP in labels
