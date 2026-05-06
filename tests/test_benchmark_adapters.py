# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Unit tests for benchmark adapters (ground_truth, cwe_rule_map, dataset adapters)."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

from benchmarks.adapters.cwe_rule_map import (
    all_mapped_cwes,
    cwe_to_rules,
    primary_rule,
    rule_to_cwe,
)
from benchmarks.adapters.ground_truth import (
    LABEL_BENIGN,
    LABEL_FP,
    LABEL_TP,
    GroundTruthEntry,
    load_entries,
    save_entries,
)


# ── GroundTruthEntry ──────────────────────────────────────────────────────────

class TestGroundTruthEntry:
    def test_creation_tp(self):
        entry = GroundTruthEntry(
            id="test_001",
            source_dataset="secllmholmes",
            cwe_id="CWE-416",
            rule_id="cpp/use-after-free",
            file_path="bad/uaf.c",
            function_name="bad",
            start_line=1,
            lang="c",
            label=LABEL_TP,
            code_snippet="void bad() { free(p); *p = 1; }",
        )
        assert entry.id == "test_001"
        assert entry.label == LABEL_TP
        assert entry.cwe_id == "CWE-416"

    def test_creation_fp(self):
        entry = GroundTruthEntry(
            id="test_002",
            source_dataset="juliet",
            cwe_id="CWE-416",
            rule_id="cpp/use-after-free",
            file_path="good/uaf.c",
            function_name="good",
            start_line=1,
            lang="c",
            label=LABEL_FP,
            code_snippet="void good() { *p = 1; free(p); }",
        )
        assert entry.label == LABEL_FP

    def test_creation_benign(self):
        entry = GroundTruthEntry(
            id="test_003",
            source_dataset="juliet",
            cwe_id="",
            rule_id="",
            file_path="helpers.c",
            function_name="helper",
            start_line=1,
            lang="c",
            label=LABEL_BENIGN,
            code_snippet="void helper() { printf(\"ok\\n\"); }",
        )
        assert entry.label == LABEL_BENIGN

    def test_invalid_label_raises(self):
        with pytest.raises(ValueError, match="Invalid label"):
            GroundTruthEntry(
                id="bad",
                source_dataset="test",
                cwe_id="",
                rule_id="",
                file_path="",
                function_name="",
                start_line=1,
                lang="c",
                label="UNKNOWN",
                code_snippet="",
            )

    def test_roundtrip_to_dict(self):
        entry = GroundTruthEntry(
            id="test_rt",
            source_dataset="secllmholmes",
            cwe_id="CWE-89",
            rule_id="py/sql-injection",
            file_path="bad/sqli.py",
            function_name="bad",
            start_line=5,
            lang="python",
            label=LABEL_TP,
            code_snippet="query = f'SELECT * FROM t WHERE id={user_id}'",
            metadata={"complexity": "basic"},
        )
        d = entry.to_dict()
        restored = GroundTruthEntry.from_dict(d)
        assert restored.id == entry.id
        assert restored.label == entry.label
        assert restored.metadata["complexity"] == "basic"

    def test_from_dict_defaults(self):
        entry = GroundTruthEntry.from_dict({"id": "x", "source_dataset": "test", "label": "TP"})
        assert entry.lang == "c"
        assert entry.start_line == 1
        assert entry.code_snippet == ""

    def test_load_entries_list(self, tmp_path):
        entries = [
            GroundTruthEntry(
                id=f"e{i}",
                source_dataset="test",
                cwe_id="CWE-416",
                rule_id="cpp/use-after-free",
                file_path="f.c",
                function_name="fn",
                start_line=1,
                lang="c",
                label=LABEL_TP if i % 2 == 0 else LABEL_FP,
                code_snippet="code",
            )
            for i in range(5)
        ]
        p = tmp_path / "entries.json"
        save_entries(entries, p)
        loaded = load_entries(p)
        assert len(loaded) == 5
        assert loaded[0].id == "e0"
        assert loaded[1].label == LABEL_FP

    def test_load_entries_single_object(self, tmp_path):
        p = tmp_path / "single.json"
        p.write_text(
            json.dumps({
                "id": "s1",
                "source_dataset": "test",
                "label": "TP",
                "cwe_id": "CWE-416",
            })
        )
        loaded = load_entries(p)
        assert len(loaded) == 1
        assert loaded[0].id == "s1"


# ── CWE Rule Map ──────────────────────────────────────────────────────────────

class TestCweRuleMap:
    def test_cwe_to_rules_use_after_free(self):
        rules = cwe_to_rules("CWE-416")
        assert "cpp/use-after-free" in rules

    def test_cwe_to_rules_without_prefix(self):
        # Accept "416" as well as "CWE-416"
        assert cwe_to_rules("416") == cwe_to_rules("CWE-416")

    def test_cwe_to_rules_unknown(self):
        assert cwe_to_rules("CWE-9999") == []

    def test_rule_to_cwe_roundtrip(self):
        rules = cwe_to_rules("CWE-416")
        assert rules, "CWE-416 should have mappings"
        cwe = rule_to_cwe(rules[0])
        assert cwe == "CWE-416"

    def test_rule_to_cwe_unknown(self):
        assert rule_to_cwe("unknown/rule") == ""

    def test_primary_rule_returns_first(self):
        rule = primary_rule("CWE-416")
        assert rule == "cpp/use-after-free"

    def test_primary_rule_unknown_returns_empty(self):
        assert primary_rule("CWE-9999") == ""

    def test_all_mapped_cwes_not_empty(self):
        cwes = all_mapped_cwes()
        assert len(cwes) >= 20
        assert "CWE-416" in cwes
        assert "CWE-89" in cwes

    def test_sql_injection_mapping(self):
        rules = cwe_to_rules("CWE-89")
        assert any("sql" in r for r in rules)

    def test_python_path_injection(self):
        rules = cwe_to_rules("CWE-22")
        assert any("py/" in r or "js/" in r for r in rules)

    def test_java_rule_coverage_for_owasp_cwes(self):
        # OWASP BenchmarkJava primary categories must each have a java/ rule
        for cwe in ("CWE-22", "CWE-78", "CWE-79", "CWE-89", "CWE-327"):
            rules = cwe_to_rules(cwe)
            assert any(r.startswith("java/") for r in rules), (
                f"{cwe} missing a java/* rule mapping"
            )

    def test_owasp_only_cwes_present(self):
        # CWEs unique to OWASP Benchmark (not previously mapped)
        for cwe in ("CWE-90", "CWE-328", "CWE-330", "CWE-501", "CWE-614", "CWE-643"):
            assert cwe in all_mapped_cwes(), f"{cwe} should be mapped for OWASP"
            assert primary_rule(cwe) != "", f"{cwe} should have a primary rule"


# ── Fixture Files ──────────────────────────────────────────────────────────────

class TestFixtureFiles:
    """Verify fixture files are valid and contain expected data."""

    FIXTURES_DIR = Path(__file__).resolve().parents[1] / "benchmarks" / "fixtures"

    def test_secllmholmes_fixture_loads(self):
        fixture = self.FIXTURES_DIR / "secllmholmes_sample.json"
        assert fixture.is_file(), "secllmholmes_sample.json must exist"
        entries = load_entries(fixture)
        assert len(entries) == 10

    def test_secllmholmes_fixture_has_both_labels(self):
        entries = load_entries(self.FIXTURES_DIR / "secllmholmes_sample.json")
        labels = {e.label for e in entries}
        assert LABEL_TP in labels
        assert LABEL_FP in labels

    def test_juliet_fixture_loads(self):
        fixture = self.FIXTURES_DIR / "juliet_sample.json"
        assert fixture.is_file(), "juliet_sample.json must exist"
        entries = load_entries(fixture)
        assert len(entries) == 10

    def test_juliet_fixture_all_c_lang(self):
        entries = load_entries(self.FIXTURES_DIR / "juliet_sample.json")
        for e in entries:
            assert e.lang in ("c", "cpp"), f"Unexpected lang: {e.lang}"

    def test_fixtures_have_code_snippets(self):
        for fname in ("secllmholmes_sample.json", "juliet_sample.json"):
            entries = load_entries(self.FIXTURES_DIR / fname)
            for e in entries:
                assert e.code_snippet.strip(), f"Empty code snippet in {fname}: {e.id}"


# ── SecLLMHolmes Adapter ──────────────────────────────────────────────────────

class TestSecLLMHolmesAdapter:
    def test_adapter_on_synthetic_dir(self, tmp_path):
        """Adapter must parse bad/good directories into TP/FP entries."""
        from benchmarks.adapters.secllmholmes_adapter import SecLLMHolmesAdapter

        # Adapter expects: dataset/CWE-*/file.c (files directly in CWE dir)
        # FP = filename starts with "p_", TP = anything else
        cwe_dir = tmp_path / "dataset" / "CWE-416"
        cwe_dir.mkdir(parents=True)
        (cwe_dir / "bad.c").write_text("void bad() { free(p); *p = 1; }")
        (cwe_dir / "p_good.c").write_text("void good() { *p = 1; free(p); }")

        adapter = SecLLMHolmesAdapter(tmp_path)
        entries = adapter.load()

        assert len(entries) == 2
        labels = {e.label for e in entries}
        assert LABEL_TP in labels
        assert LABEL_FP in labels

    def test_adapter_cwe_extraction(self, tmp_path):
        from benchmarks.adapters.secllmholmes_adapter import SecLLMHolmesAdapter

        cwe_dir = tmp_path / "dataset" / "CWE-89"
        cwe_dir.mkdir(parents=True)
        (cwe_dir / "sqli.py").write_text("query = f'SELECT * FROM t WHERE id={x}'")

        adapter = SecLLMHolmesAdapter(tmp_path)
        entries = adapter.load()
        assert entries[0].cwe_id == "CWE-89"
        assert entries[0].lang == "python"

    def test_adapter_limit(self, tmp_path):
        from benchmarks.adapters.secllmholmes_adapter import SecLLMHolmesAdapter

        for i in range(5):
            cwe_dir = tmp_path / "dataset" / f"CWE-41{i}"
            cwe_dir.mkdir(parents=True)
            (cwe_dir / f"f{i}.c").write_text("void bad() {}")

        adapter = SecLLMHolmesAdapter(tmp_path)
        entries = adapter.load(limit=3)
        assert len(entries) == 3


# ── Juliet Adapter ────────────────────────────────────────────────────────────

class TestJulietAdapter:
    def test_adapter_bad_file(self, tmp_path):
        from benchmarks.adapters.juliet_adapter import JulietAdapter

        cwe_dir = tmp_path / "CWE416_Use_After_Free"
        cwe_dir.mkdir()
        (cwe_dir / "CWE416_bad.c").write_text(
            "void bad() { char *p = malloc(10); free(p); *p = 0; }"
        )

        adapter = JulietAdapter(tmp_path)
        entries = adapter.load()

        assert len(entries) >= 1
        tp_entries = [e for e in entries if e.label == LABEL_TP]
        assert len(tp_entries) >= 1

    def test_adapter_good_file(self, tmp_path):
        from benchmarks.adapters.juliet_adapter import JulietAdapter

        cwe_dir = tmp_path / "CWE416_Use_After_Free"
        cwe_dir.mkdir()
        (cwe_dir / "CWE416_good.c").write_text(
            "void goodG2B() { char *p = malloc(10); free(p); }"
        )

        adapter = JulietAdapter(tmp_path)
        entries = adapter.load()
        fp_entries = [e for e in entries if e.label == LABEL_FP]
        assert len(fp_entries) >= 1

    def test_adapter_skips_non_target_cwes(self, tmp_path):
        from benchmarks.adapters.juliet_adapter import JulietAdapter

        # CWE999 is not in TARGET_CWES
        d = tmp_path / "CWE999_Unknown"
        d.mkdir()
        (d / "test_bad.c").write_text("void bad() {}")

        adapter = JulietAdapter(tmp_path)
        entries = adapter.load()
        assert len(entries) == 0
