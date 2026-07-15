# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Triage-quality regression tests: autoescape routing (#2) + cross-rule
verdict reconciliation (#3)."""

from __future__ import annotations

from pathlib import Path

import yaml

from vuln_hunter_x.core.types import Finding, Verdict
from vuln_hunter_x.questions.loader import QuestionsLoader
from vuln_hunter_x.verification.engine import _reconcile_conflicting_verdicts


def _mk(rule: str, file: str, line: int, verdict: str, cwe: list[str],
        score: float = 0.9, conf: str = "High") -> Verdict:
    f = Finding(rule_id=rule, message="", file=file, start_line=line, end_line=line,
                repo_name="dvpwa", lang="python", cwe_ids=cwe)
    return Verdict(finding=f, verdict=verdict, confidence=conf, reasoning="r",
                   answers=[], raw_response="", model="m", confidence_score=score)


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


# ── #3: cross-rule, path-normalised reconciliation + guards ─────────────────
_REL = "sqli/dao/student.py"


def test_cross_rule_distinct_obligations_left_independent() -> None:
    # Different rules ask different security questions (#122): a django-raw-sql FP
    # and a SQLi TP on one line are NOT a contradiction. Cross-rule verdicts are
    # left independent — never forced to agree. The old FP→Needs-More-Data
    # reconciliation is retired (forcing agreement degraded correct verdicts).
    out = _reconcile_conflicting_verdicts([
        _mk("py/django-raw-sql", _REL, 45, "False Positive", ["CWE-89"]),
        _mk("python.formatted-sql-query", _REL, 45, "True Positive", ["CWE-89"]),
        _mk("python.sqlalchemy-raw", _REL, 45, "True Positive", ["CWE-89"]),
    ])
    assert [v.verdict for v in out] == ["False Positive", "True Positive", "True Positive"]


def test_memory_safety_cross_rule_left_independent() -> None:
    # dvcp imgRead.c:62 — CodeQL cpp/double-free→FP vs a Semgrep double-free→TP.
    # Distinct rules → distinct obligations; the verdicts are left independent
    # (no manufactured Needs-More-Data). A per-finding wrong verdict is a
    # correctness concern for its own rule, not a reconciliation concern.
    out = _reconcile_conflicting_verdicts([
        _mk("cpp/double-free", "linux/imgRead.c", 62, "False Positive", ["CWE-415"]),
        _mk("c.lang.security.double-free", "linux/imgRead.c", 62, "True Positive", ["CWE-415"]),
    ])
    assert [v.verdict for v in out] == ["False Positive", "True Positive"]


def test_buffer_overflow_family_cross_rule_left_independent() -> None:
    # #122 Row 4 — insecure-coding-examples if_constexpr.cpp:15: cpp/static-buffer-
    # overflow (TP) vs cpp/overflow-buffer (FP) at the SAME memcpy line. A shared
    # broad CWE-119 is NOT obligation equivalence — the two rules may ask different
    # questions (size-calc error vs destination-bound violation). They are left
    # independent, never forced to agree. If the FP is itself wrong that is a
    # per-finding correctness bug (#120), not something reconciliation should mask.
    out = _reconcile_conflicting_verdicts([
        _mk("cpp/static-buffer-overflow", "practice/if_constexpr.cpp", 15,
            "True Positive", ["CWE-119", "CWE-131"]),
        _mk("cpp/overflow-buffer", "practice/if_constexpr.cpp", 15,
            "False Positive", ["CWE-119", "CWE-121", "CWE-122", "CWE-126"]),
    ])
    assert [v.verdict for v in out] == ["True Positive", "False Positive"]


def test_broad_buffer_parent_alone_not_merged() -> None:
    # Sharing ONLY the broad CWE-119 parent (no specific buffer CWE on at least one
    # side) is too generic to fuse — the guard mirrors the CWE-20 exclusion.
    out = _reconcile_conflicting_verdicts([
        _mk("cpp/a-buffer-rule", _REL, 12, "True Positive", ["CWE-119", "CWE-787"]),
        _mk("cpp/some-other-rule", _REL, 12, "False Positive", ["CWE-119"]),
    ])
    assert [v.verdict for v in out] == ["True Positive", "False Positive"]


def test_broad_cwe_cross_rule_not_merged() -> None:
    # CWE-20 is broad/structural and excluded from cross-rule clustering, so two
    # different rules sharing only CWE-20 are NOT fused.
    out = _reconcile_conflicting_verdicts([
        _mk("r.a", _REL, 12, "True Positive", ["CWE-20"]),
        _mk("r.b", _REL, 12, "False Positive", ["CWE-20"]),
    ])
    assert [v.verdict for v in out] == ["True Positive", "False Positive"]


def test_vendored_or_minified_paths_skipped() -> None:
    out = _reconcile_conflicting_verdicts([
        _mk("r.a", "sqli/static/js/materialize.js", 5, "True Positive", ["CWE-79"]),
        _mk("r.b", "sqli/static/js/materialize.js", 5, "False Positive", ["CWE-79"]),
        _mk("r.c", "app/vendor/lib.min.js", 5, "True Positive", ["CWE-89"]),
    ])
    # Untouched — vendored/minified findings are out of scope for reconciliation.
    assert [v.verdict for v in out] == ["True Positive", "False Positive", "True Positive"]


def test_dense_hotspot_skips_cross_rule() -> None:
    # 7 distinct rules at one line (> threshold) → cross-rule merging disabled;
    # the FP is left as-is (not promoted to Needs More Data).
    verdicts = [_mk(f"r.{i}", _REL, 50, "True Positive", ["CWE-89"]) for i in range(6)]
    verdicts.append(_mk("r.fp", _REL, 50, "False Positive", ["CWE-89"]))
    out = _reconcile_conflicting_verdicts(verdicts)
    assert out[-1].verdict == "False Positive"


def test_same_basename_different_dir_not_merged() -> None:
    out = _reconcile_conflicting_verdicts([
        _mk("r.x", "a/student.py", 45, "True Positive", ["CWE-89"]),
        _mk("r.y", "b/other/student.py", 45, "False Positive", ["CWE-89"]),
    ])
    assert [v.verdict for v in out] == ["True Positive", "False Positive"]


def test_sibling_tool_tie_keeps_flagged() -> None:
    # Same rule id (broad CWE is irrelevant for same-rule clustering).
    out = _reconcile_conflicting_verdicts([
        _mk("r.log", _REL, 33, "True Positive", ["CWE-200"], score=0.90),
        _mk("r.log", _REL, 33, "False Positive", ["CWE-200"], score=0.95),
    ])
    assert [v.verdict for v in out] == ["True Positive", "True Positive"]


def test_repo_relative_path_equality_matches_abs_and_rel(tmp_path) -> None:
    # Absolute (Semgrep) vs repo-relative (CodeQL) resolve to the same file.
    from vuln_hunter_x.verification.engine import _paths_same_file
    (tmp_path / ".git").mkdir()
    sub = tmp_path / "sqli" / "dao"
    sub.mkdir(parents=True)
    (sub / "student.py").write_text("x = 1\n")
    abs_path = str(sub / "student.py")
    assert _paths_same_file(abs_path, "sqli/dao/student.py")
    # A monorepo sibling with the same tail but different dir must NOT match.
    assert not _paths_same_file(abs_path, "svc2/dao/student.py")
