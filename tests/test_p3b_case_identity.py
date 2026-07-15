# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P3b Task 1 — pure case identity (#122).

Two scanner observations form one VerificationCase iff EVERY semantic input is
identical: same canonical sink + same obligation. Everything else — a different
rule (obligation), a different flow, a different construct on the same line — is a
distinct case that may legitimately differ. Snippet-less or unplaceable anchors
never merge (key None → singleton), keeping the current snippet-less corpus
verdict-neutral. Pure, no IO, deterministic.
"""

from __future__ import annotations

from vuln_hunter_x.context.anchor import (
    ABSENT,
    AMBIGUOUS,
    EXACT,
    LOCATED_UNVERIFIED,
    REANCHORED_UNIQUE,
    AnchorResolution,
)
from vuln_hunter_x.core.types import Finding
from vuln_hunter_x.verification.case import (
    VerificationCase,
    build_cases,
    case_key,
)


def _f(rule="tainted-filename", file="a/b.php", line=10, snippet="sink($x);",
       flow=None, sc=1, ec=5, repo="repo", lang="php"):
    return Finding(rule_id=rule, message="m", file=file, start_line=line,
                   end_line=line, repo_name=repo, lang=lang, sink_snippet=snippet,
                   dataflow_path=list(flow or []), start_column=sc, end_column=ec)


def _a(line=10, resolution=EXACT):
    return AnchorResolution(reported_line=line, analysis_line=line, resolution=resolution)


# --- case_key -------------------------------------------------------------

def test_exact_duplicate_shares_key():
    k1 = case_key(_f(), _a(), norm_path="a/b.php")
    k2 = case_key(_f(), _a(), norm_path="a/b.php")
    assert k1 is not None and k1 == k2


def test_different_rule_distinct_key():
    # obligation = exact rule identity; different rule = different question.
    k1 = case_key(_f(rule="cpp/toctou-race-condition"), _a(), norm_path="a/b.php")
    k2 = case_key(_f(rule="cpp/path-injection"), _a(), norm_path="a/b.php")
    assert k1 != k2


def test_different_flow_distinct_key():
    k1 = case_key(_f(flow=["src:1", "sink:10"]), _a(), norm_path="a/b.php")
    k2 = case_key(_f(flow=["src:2", "sink:10"]), _a(), norm_path="a/b.php")
    assert k1 != k2


def test_different_columns_distinct_when_exact():
    k1 = case_key(_f(sc=1, ec=5), _a(resolution=EXACT), norm_path="a/b.php")
    k2 = case_key(_f(sc=9, ec=13), _a(resolution=EXACT), norm_path="a/b.php")
    assert k1 != k2


def test_reanchored_ignores_stale_columns():
    # After re-anchoring, reported columns are stale (resolver matches the first
    # non-blank snippet line, ignores columns). Same resolved line + snippet +
    # rule → one case regardless of the stale reported columns.
    k1 = case_key(_f(sc=1, ec=5), _a(resolution=REANCHORED_UNIQUE), norm_path="a/b.php")
    k2 = case_key(_f(sc=9, ec=13), _a(resolution=REANCHORED_UNIQUE), norm_path="a/b.php")
    assert k1 is not None and k1 == k2


def test_snippet_whitespace_insensitive_identifier_sensitive():
    same = case_key(_f(snippet="file_get_contents($id);"), _a(), norm_path="a/b.php")
    indented = case_key(_f(snippet="   file_get_contents($id);  "), _a(), norm_path="a/b.php")
    assert same == indented  # leading/trailing indentation whitespace-insensitive
    safe = case_key(_f(snippet="file_get_contents($safe);"), _a(), norm_path="a/b.php")
    tainted = case_key(_f(snippet="file_get_contents($tainted);"), _a(), norm_path="a/b.php")
    assert safe != tainted  # identifiers encode the security distinction


def test_snippetless_key_is_none():
    assert case_key(_f(snippet=""), _a(), norm_path="a/b.php") is None
    assert case_key(_f(snippet="   "), _a(), norm_path="a/b.php") is None


def test_unplaceable_anchor_key_is_none():
    assert case_key(_f(), _a(resolution=ABSENT), norm_path="a/b.php") is None
    assert case_key(_f(), _a(resolution=AMBIGUOUS), norm_path="a/b.php") is None


def test_located_unverified_uses_columns():
    k1 = case_key(_f(sc=1, ec=5), _a(resolution=LOCATED_UNVERIFIED), norm_path="a/b.php")
    k2 = case_key(_f(sc=9, ec=13), _a(resolution=LOCATED_UNVERIFIED), norm_path="a/b.php")
    assert k1 != k2


def test_key_uses_resolved_analysis_line_not_reported():
    # Two findings reported at different lines that re-anchor to the SAME real
    # line are the same sink → one case.
    fa = _f(line=6)
    fb = _f(line=1)
    a_res = AnchorResolution(reported_line=6, analysis_line=4, resolution=REANCHORED_UNIQUE)
    b_res = AnchorResolution(reported_line=1, analysis_line=4, resolution=REANCHORED_UNIQUE)
    assert case_key(fa, a_res, norm_path="a/b.php") == case_key(fb, b_res, norm_path="a/b.php")


# --- build_cases ----------------------------------------------------------

def test_build_cases_groups_exact_dups():
    k = case_key(_f(), _a(), norm_path="a/b.php")
    other = case_key(_f(rule="other-rule"), _a(), norm_path="a/b.php")
    cases = build_cases([k, other, k])
    assert len(cases) == 2
    dup = next(c for c in cases if len(c.observation_indices) == 2)
    assert dup.observation_indices == [0, 2]
    assert dup.representative_index == 0
    assert dup.case_id != ""
    singleton = next(c for c in cases if len(c.observation_indices) == 1)
    assert singleton.observation_indices == [1]
    assert singleton.case_id == ""


def test_build_cases_none_keys_are_distinct_singletons():
    cases = build_cases([None, None])
    assert len(cases) == 2
    assert all(len(c.observation_indices) == 1 and c.case_id == "" for c in cases)


def test_build_cases_order_is_first_appearance():
    k1 = case_key(_f(rule="r1"), _a(), norm_path="a/b.php")
    k2 = case_key(_f(rule="r2"), _a(), norm_path="a/b.php")
    cases = build_cases([k2, k1, k2])
    assert [c.representative_index for c in cases] == [0, 1]


def test_build_cases_covers_every_index_once():
    keys = [case_key(_f(rule=f"r{i % 2}"), _a(), norm_path="a/b.php") for i in range(5)]
    keys.append(None)
    cases = build_cases(keys)
    seen = sorted(i for c in cases for i in c.observation_indices)
    assert seen == list(range(6))


def test_build_cases_case_id_deterministic():
    k = case_key(_f(), _a(), norm_path="a/b.php")
    id1 = build_cases([k, k])[0].case_id
    id2 = build_cases([k, k])[0].case_id
    assert id1 == id2 and id1 != ""


def test_verification_case_is_dataclass():
    c = VerificationCase(representative_index=0, observation_indices=[0], case_id="")
    assert c.representative_index == 0
