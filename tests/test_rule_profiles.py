# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

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


# ── Full Profile (Stage 1 custom-rule plumbing) ──────────────────────────────


class TestFullProfile:
    """The ``full`` profile activates custom CodeQL + custom Semgrep packs."""

    def test_full_profile_exists(self, mgr: RuleProfileManager) -> None:
        assert "full" in mgr.profile_names

    def test_full_profile_flags_custom_codeql(self, mgr: RuleProfileManager) -> None:
        p = mgr.get_profile("full")
        assert p.include_custom_codeql is True

    def test_full_profile_custom_semgrep_path_template(self, mgr: RuleProfileManager) -> None:
        p = mgr.get_profile("full")
        assert "${LANG}" in p.custom_semgrep_path
        assert "semgrep-custom" in p.custom_semgrep_path

    def test_other_profiles_default_off(self, mgr: RuleProfileManager) -> None:
        for name in ("standard", "extended", "maximum"):
            p = mgr.get_profile(name)
            assert p.include_custom_codeql is False, f"{name} should not enable custom codeql"
            assert p.custom_semgrep_path == "", f"{name} should have empty custom_semgrep_path"


class TestCodeQLSuiteStacking:
    """``get_codeql_suites`` returns [built-in, custom] only when enabled."""

    def test_standard_returns_single_suite(self, mgr: RuleProfileManager) -> None:
        suites = mgr.get_codeql_suites("standard", "python")
        assert len(suites) == 1
        assert "python-security-extended" in suites[0]

    @staticmethod
    def _make_pack(root: Path, lang: str, with_ql: bool = True) -> Path:
        """Create a synthetic custom-pack layout. Returns the suite.qls path."""
        pack = root / lang
        src = pack / "src"
        src.mkdir(parents=True)
        suite = pack / "suite.qls"
        suite.write_text("- queries: src\n")
        if with_ql:
            (src / "stub.ql").write_text(
                "/** @kind problem @id " + lang + "/stub */\n"
                "import codeql\n"
                "from string s where false select s, \"stub\"\n"
            )
        return suite

    def test_full_returns_two_when_custom_exists(
        self, mgr: RuleProfileManager, tmp_path: Path,
    ) -> None:
        # Build a synthetic custom-root layout with at least one .ql
        custom_root = tmp_path / "codeql-custom"
        suite_file = self._make_pack(custom_root, "python")
        suites = mgr.get_codeql_suites("full", "python", custom_root=custom_root)
        assert len(suites) == 2
        assert "python-security-and-quality" in suites[0]
        assert suites[1] == str(suite_file)

    def test_full_skips_missing_custom_suite(
        self, mgr: RuleProfileManager, tmp_path: Path,
    ) -> None:
        # custom_root points at an empty dir — no python/suite.qls
        suites = mgr.get_codeql_suites("full", "python", custom_root=tmp_path / "empty")
        assert len(suites) == 1

    def test_full_skips_empty_custom_pack(
        self, mgr: RuleProfileManager, tmp_path: Path,
    ) -> None:
        """suite.qls exists but src/ has no .ql files — silently skip."""
        custom_root = tmp_path / "codeql-custom"
        self._make_pack(custom_root, "python", with_ql=False)
        suites = mgr.get_codeql_suites("full", "python", custom_root=custom_root)
        assert len(suites) == 1, (
            "empty pack must be skipped to prevent CodeQL 'no queries found' errors"
        )

    def test_c_language_maps_to_cpp_custom_dir(
        self, mgr: RuleProfileManager, tmp_path: Path,
    ) -> None:
        custom_root = tmp_path / "codeql-custom"
        self._make_pack(custom_root, "cpp")
        # Passing lang="c" should still resolve to the cpp/ custom dir
        suites = mgr.get_codeql_suites("full", "c", custom_root=custom_root)
        assert len(suites) == 2
        assert suites[1].endswith("cpp/suite.qls")


class TestExtendedRegistryProfile:
    """Stage-2 ``extended-registry`` profile carries verified registry packs."""

    def test_profile_exists(self, mgr: RuleProfileManager) -> None:
        assert "extended-registry" in mgr.profile_names

    def test_universal_packs_present(self, mgr: RuleProfileManager) -> None:
        p = mgr.get_profile("extended-registry")
        for pack in ("auto", "p/security-audit", "p/secrets",
                     "p/owasp-top-ten", "p/cwe-top-25", "p/gitleaks",
                     "p/jwt", "p/insecure-transport"):
            assert pack in p.semgrep_configs, f"missing {pack}"

    def test_python_language_packs(self, mgr: RuleProfileManager) -> None:
        configs = mgr.get_semgrep_configs("extended-registry", lang="python")
        assert "p/python" in configs
        assert "p/django" in configs
        assert "p/flask" in configs

    def test_php_language_packs(self, mgr: RuleProfileManager) -> None:
        configs = mgr.get_semgrep_configs("extended-registry", lang="php")
        assert "p/php" in configs

    def test_go_language_packs(self, mgr: RuleProfileManager) -> None:
        configs = mgr.get_semgrep_configs("extended-registry", lang="go")
        assert "p/gosec" in configs

    def test_cpp_falls_back_to_universal_only(self, mgr: RuleProfileManager) -> None:
        # No working p/cpp pack as of Stage-2 — only universal packs apply
        configs = mgr.get_semgrep_configs("extended-registry", lang="cpp")
        assert all(not c.startswith("p/cpp") for c in configs)
        assert "p/security-audit" in configs

    def test_no_lang_means_no_language_specific(self, mgr: RuleProfileManager) -> None:
        configs = mgr.get_semgrep_configs("extended-registry", lang="")
        assert "p/django" not in configs
        assert "p/security-audit" in configs

    def test_opengrep_same_as_semgrep(self, mgr: RuleProfileManager) -> None:
        sg = mgr.get_semgrep_configs("extended-registry", lang="python")
        og = mgr.get_opengrep_configs("extended-registry", lang="python")
        # OpenGrep accepts the same registry handles as Semgrep
        assert set(sg) == set(og)


class TestFullProfileWithLanguageSpecific:
    """The ``full`` profile inherits all extended-registry packs + custom rules."""

    def test_full_has_language_specific(self, mgr: RuleProfileManager) -> None:
        configs = mgr.get_semgrep_configs("full", lang="python")
        assert "p/django" in configs
        assert "p/flask" in configs

    def test_full_keeps_custom_semgrep_path_field(self, mgr: RuleProfileManager) -> None:
        p = mgr.get_profile("full")
        assert "${LANG}" in p.custom_semgrep_path


class TestSemgrepConfigExpansion:
    """``get_semgrep_configs`` expands ``${LANG}`` and appends custom path."""

    def test_no_template_in_standard(self, mgr: RuleProfileManager) -> None:
        configs = mgr.get_semgrep_configs("standard", lang="python")
        assert configs == ["auto"]

    def test_template_expansion_with_existing_file(
        self, mgr: RuleProfileManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        # The full profile's custom_semgrep_path is "config/semgrep-custom/${LANG}.yaml".
        # Build a synthetic file under the repo's actual layout and chdir there.
        custom_dir = tmp_path / "config" / "semgrep-custom"
        custom_dir.mkdir(parents=True)
        custom_file = custom_dir / "python.yaml"
        custom_file.write_text("rules: []\n")
        monkeypatch.chdir(tmp_path)
        configs = mgr.get_semgrep_configs("full", lang="python")
        # The expanded relative path should be the last entry
        assert configs[-1] == "config/semgrep-custom/python.yaml"

    def test_template_drops_when_file_missing(
        self, mgr: RuleProfileManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.chdir(tmp_path)
        configs = mgr.get_semgrep_configs("full", lang="python")
        # No file exists at config/semgrep-custom/python.yaml — should not be in list
        assert not any("python.yaml" in c for c in configs)
