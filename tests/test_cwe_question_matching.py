# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Tests for CWE-based guided question matching in QuestionsLoader."""

from __future__ import annotations

from pathlib import Path

import pytest

from vuln_hunter_x.core.types import GuidedQuestions
from vuln_hunter_x.questions.loader import QuestionsLoader

# Path to the actual prompts shipped with the repo
_PROMPTS_DIR = Path(__file__).resolve().parents[1] / "config" / "prompts"
_CATEGORIES_YAML = Path(__file__).resolve().parents[1] / "config" / "rule_categories.yaml"


def _make_loader_with_cwe_map() -> QuestionsLoader:
    """Create a fully loaded QuestionsLoader with CWE mapping enabled."""
    from vuln_hunter_x.core.rule_profiles import RuleProfileManager

    loader = QuestionsLoader(_PROMPTS_DIR)
    mgr = RuleProfileManager(_CATEGORIES_YAML)
    loader.set_cwe_question_map(mgr.cwe_question_map)
    return loader


@pytest.fixture()
def loader() -> QuestionsLoader:
    return _make_loader_with_cwe_map()


# ── CWE-Based Matching ──────────────────────────────────────────────────────


class TestCWEMatching:
    def test_semgrep_rule_with_cwe_gets_specific_questions(
        self, loader: QuestionsLoader,
    ) -> None:
        """A Semgrep-style rule_id with CWE-89 should get py/sql-injection questions."""
        q, match_type = loader.get_questions_with_match_info(
            "python.django.security.injection.sql.raw-query",
            cwe_ids=["CWE-89"],
            lang="python",
        )
        assert match_type == "cwe"
        assert q.questions  # Non-empty question list

    def test_cwe_match_uses_correct_language(
        self, loader: QuestionsLoader,
    ) -> None:
        """CWE-89 + lang=javascript should match js/sql-injection, not py/."""
        q, match_type = loader.get_questions_with_match_info(
            "javascript.express.security.sqli.tainted-query",
            cwe_ids=["CWE-89"],
            lang="javascript",
        )
        assert match_type == "cwe"
        # The returned questions should be relevant (from js/ prefix)

    def test_cwe_match_priority_below_exact(
        self, loader: QuestionsLoader,
    ) -> None:
        """An exact match should always win over CWE-based matching."""
        q, match_type = loader.get_questions_with_match_info(
            "py/sql-injection",
            cwe_ids=["CWE-89"],
            lang="python",
        )
        assert match_type == "exact"

    def test_cwe_match_priority_above_default(
        self, loader: QuestionsLoader,
    ) -> None:
        """CWE-based match should win over generic default questions."""
        q, match_type = loader.get_questions_with_match_info(
            "some.unknown.semgrep.rule.id.for.sqli",
            cwe_ids=["CWE-89"],
            lang="python",
        )
        assert match_type == "cwe"
        assert match_type != "default"

    def test_no_cwe_ids_skips_cwe_tier(
        self, loader: QuestionsLoader,
    ) -> None:
        """Without CWE IDs, CWE-based matching should be skipped."""
        q, match_type = loader.get_questions_with_match_info(
            "some.unknown.semgrep.rule",
        )
        assert match_type in ("default", "generic")

    def test_unknown_cwe_falls_to_default(
        self, loader: QuestionsLoader,
    ) -> None:
        """A CWE with no mapping should fall through to default questions."""
        q, match_type = loader.get_questions_with_match_info(
            "some.unknown.rule",
            cwe_ids=["CWE-99999"],
            lang="python",
        )
        assert match_type in ("default", "generic")

    def test_multiple_cwes_first_match_wins(
        self, loader: QuestionsLoader,
    ) -> None:
        """When multiple CWE IDs are provided, the first matching one is used."""
        q, match_type = loader.get_questions_with_match_info(
            "generic.secrets.hardcoded-key",
            cwe_ids=["CWE-99999", "CWE-798"],
            lang="python",
        )
        assert match_type == "cwe"

    def test_cwe_match_with_go_language(
        self, loader: QuestionsLoader,
    ) -> None:
        """CWE-based matching should work for Go findings."""
        q, match_type = loader.get_questions_with_match_info(
            "go.grpc.security.injection.tainted-sql",
            cwe_ids=["CWE-89"],
            lang="go",
        )
        assert match_type == "cwe"

    def test_xss_cwe_match(self, loader: QuestionsLoader) -> None:
        """CWE-79 should map to XSS questions."""
        q, match_type = loader.get_questions_with_match_info(
            "javascript.browser.security.reflected-xss",
            cwe_ids=["CWE-79"],
            lang="javascript",
        )
        assert match_type == "cwe"

    def test_memory_safety_cwe_match(self, loader: QuestionsLoader) -> None:
        """CWE-416 should map to use-after-free questions for C++."""
        q, match_type = loader.get_questions_with_match_info(
            "c.memory.use-after-free-detected",
            cwe_ids=["CWE-416"],
            lang="cpp",
        )
        assert match_type == "cwe"


# ── Backward Compatibility ───────────────────────────────────────────────────


class TestBackwardCompatibility:
    def test_exact_match_still_works(self, loader: QuestionsLoader) -> None:
        """Existing exact matches should continue to work unchanged."""
        q, match_type = loader.get_questions_with_match_info("cpp/use-after-free")
        assert match_type == "exact"

    def test_default_fallback_still_works(self, loader: QuestionsLoader) -> None:
        """Unknown rules without CWE IDs still get default questions."""
        q, match_type = loader.get_questions_with_match_info("completely/unknown/rule")
        assert match_type in ("default", "generic")
        assert q.questions  # Non-empty

    def test_loader_without_cwe_map(self) -> None:
        """A loader without CWE map should work normally (no CWE tier)."""
        loader = QuestionsLoader(_PROMPTS_DIR)
        # No set_cwe_question_map called
        q, match_type = loader.get_questions_with_match_info(
            "some.semgrep.rule",
            cwe_ids=["CWE-89"],
            lang="python",
        )
        # Should fall through to default since no CWE map is set
        assert match_type in ("default", "generic")
