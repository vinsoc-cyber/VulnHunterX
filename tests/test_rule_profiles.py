"""Tests for rule profiles, security categories, and CWE mapping."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_hunter_x.core.rule_profiles import RuleProfileManager, RuleProfile, SecurityCategory

# Path to the actual config shipped with the repo
_CATEGORIES_YAML = Path(__file__).resolve().parents[1] / "config" / "rule_categories.yaml"


@pytest.fixture()
def mgr() -> RuleProfileManager:
    return RuleProfileManager(_CATEGORIES_YAML)


# ── Profile Loading ──────────────────────────────────────────────────────────


class TestProfileLoading:
    def test_loads_without_error(self, mgr: RuleProfileManager) -> None:
        assert mgr.profile_names

    def test_standard_profile(self, mgr: RuleProfileManager) -> None:
        p = mgr.get_profile("standard")
        assert isinstance(p, RuleProfile)
        assert p.codeql_suite_suffix == "security-extended"
        assert "auto" in p.semgrep_configs

    def test_extended_profile(self, mgr: RuleProfileManager) -> None:
        p = mgr.get_profile("extended")
        assert "p/security-audit" in p.semgrep_configs
        assert "p/secrets" in p.semgrep_configs

    def test_maximum_profile(self, mgr: RuleProfileManager) -> None:
        p = mgr.get_profile("maximum")
        assert p.codeql_suite_suffix == "security-and-quality"
        assert "p/owasp-top-ten" in p.semgrep_configs

    def test_unknown_profile_raises(self, mgr: RuleProfileManager) -> None:
        with pytest.raises(ValueError, match="Unknown rule profile"):
            mgr.get_profile("nonexistent")


# ── CodeQL Suite Resolution ──────────────────────────────────────────────────


class TestCodeQLSuite:
    def test_suite_for_python_standard(self, mgr: RuleProfileManager) -> None:
        suite = mgr.get_codeql_suite("standard", "python")
        assert "python-security-extended" in suite
        assert suite.endswith(".qls")

    def test_suite_for_python_maximum(self, mgr: RuleProfileManager) -> None:
        suite = mgr.get_codeql_suite("maximum", "python")
        assert "python-security-and-quality" in suite

    def test_suite_for_c_uses_cpp(self, mgr: RuleProfileManager) -> None:
        suite = mgr.get_codeql_suite("standard", "c")
        assert "cpp-security-extended" in suite

    def test_suite_for_go(self, mgr: RuleProfileManager) -> None:
        suite = mgr.get_codeql_suite("extended", "go")
        assert "go-security-extended" in suite


# ── Categories ───────────────────────────────────────────────────────────────


class TestCategories:
    def test_categories_loaded(self, mgr: RuleProfileManager) -> None:
        cats = mgr.list_categories()
        assert "injection" in cats
        assert "xss" in cats
        assert "memory-safety" in cats

    def test_category_has_cwes(self, mgr: RuleProfileManager) -> None:
        cats = mgr.list_categories()
        inj = cats["injection"]
        assert isinstance(inj, SecurityCategory)
        assert "CWE-89" in inj.cwes  # SQL injection

    def test_get_cwes_for_categories(self, mgr: RuleProfileManager) -> None:
        cwes = mgr.get_cwes_for_categories(["injection", "xss"])
        assert "CWE-89" in cwes  # injection
        assert "CWE-79" in cwes  # xss
        assert "CWE-416" not in cwes  # memory-safety, not requested

    def test_get_cwes_for_unknown_category(self, mgr: RuleProfileManager) -> None:
        cwes = mgr.get_cwes_for_categories(["nonexistent"])
        assert cwes == set()

    def test_finding_matches_categories_positive(self, mgr: RuleProfileManager) -> None:
        assert mgr.finding_matches_categories(["CWE-89"], ["injection"])

    def test_finding_matches_categories_negative(self, mgr: RuleProfileManager) -> None:
        assert not mgr.finding_matches_categories(["CWE-416"], ["injection"])

    def test_finding_matches_multiple_categories(self, mgr: RuleProfileManager) -> None:
        assert mgr.finding_matches_categories(["CWE-79"], ["injection", "xss"])


# ── CWE Question Map ────────────────────────────────────────────────────────


class TestCWEQuestionMap:
    def test_map_loaded(self, mgr: RuleProfileManager) -> None:
        m = mgr.cwe_question_map
        assert len(m) > 30  # We have 50+ mappings

    def test_sql_injection(self, mgr: RuleProfileManager) -> None:
        assert mgr.get_question_suffix_for_cwe("CWE-89") == "sql-injection"

    def test_use_after_free(self, mgr: RuleProfileManager) -> None:
        assert mgr.get_question_suffix_for_cwe("CWE-416") == "use-after-free"

    def test_xss(self, mgr: RuleProfileManager) -> None:
        assert mgr.get_question_suffix_for_cwe("CWE-79") == "xss"

    def test_unknown_cwe_returns_none(self, mgr: RuleProfileManager) -> None:
        assert mgr.get_question_suffix_for_cwe("CWE-99999") is None


# ── Fallback Defaults ────────────────────────────────────────────────────────


class TestFallbackDefaults:
    def test_no_config_uses_defaults(self) -> None:
        mgr = RuleProfileManager(None)
        p = mgr.get_profile("standard")
        assert p.codeql_suite_suffix == "security-extended"

    def test_missing_file_uses_defaults(self, tmp_path: Path) -> None:
        mgr = RuleProfileManager(tmp_path / "nonexistent.yaml")
        assert "standard" in mgr.profile_names
