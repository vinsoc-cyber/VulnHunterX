# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Triage-quality regression tests: autoescape routing (#2) + the repo-relative
path equality that case identity keys on.

Cross-rule/same-line verdict reconciliation was retired (#122): different rules
ask different security questions, so their verdicts are left independent rather
than forced to agree. That behavior is covered end-to-end by the case-identity
acceptance panel.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from vuln_hunter_x.questions.loader import QuestionsLoader


# ── #2: autoescape findings route to config-weakness questions, not taint xss ─
def _loader() -> QuestionsLoader:
    ql = QuestionsLoader(Path("config/prompts"))
    cats = yaml.safe_load(Path("config/rule_categories.yaml").read_text())
    ql.set_cwe_question_map(cats.get("cwe_question_map", {}))
    return ql


def test_codeql_autoescape_routes_to_config_weakness() -> None:
    ql = _loader()
    q, match = ql.get_questions_with_match_info(
        "py/jinja-autoescape-disabled", cwe_ids=["CWE-79"], lang="python")
    assert match == "exact"
    assert "autoescap" in q.short_description.lower()


def test_semgrep_autoescape_routes_to_config_weakness_not_xss() -> None:
    ql = _loader()
    q, match = ql.get_questions_with_match_info(
        "config.semgrep-custom.vulnhunterx.python.template-autoescape-disabled",
        cwe_ids=["CWE-79"], lang="python")
    assert match == "exact"
    assert "autoescap" in q.short_description.lower()


def test_real_taint_xss_still_routes_to_xss() -> None:
    ql = _loader()
    q, _ = ql.get_questions_with_match_info(
        "py/reflected-xss", cwe_ids=["CWE-79"], lang="python")
    assert "autoescap" not in q.short_description.lower()


# ── repo-relative path equality (case identity's cross-tool path key) ────────
def test_repo_relative_path_equality_matches_abs_and_rel(tmp_path) -> None:
    # Case identity keys on the repo-relative path so an absolute (Semgrep) and a
    # repo-relative (CodeQL) observation of one sink land in the same case, while
    # a monorepo sibling with the same tail but a different dir does not.
    from vuln_hunter_x.verification.engine import _repo_relative_path
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "sqli" / "dao"
    sub.mkdir(parents=True)
    (sub / "student.py").write_text("x = 1\n")
    abs_path = str(sub / "student.py")
    assert _repo_relative_path(abs_path) == "sqli/dao/student.py"
    assert _repo_relative_path(abs_path) != _repo_relative_path("svc2/dao/student.py")
