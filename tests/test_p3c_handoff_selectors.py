# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""P3c Task 3: cross-family handoff selectors.

A rule named for one CWE can LOCATE another family's sink (e.g. a
``tainted-filename`` tagged SSRF that is really a path-access read). The
``handoff_from`` selector block declares that candidacy separately from primary
``selectors`` so it is neither ownership nor a primary-overlap error. Dedup: a
finding a family PRIMARILY owns is not also that family's handoff candidate.
More than one distinct handoff target fails closed.
"""

from __future__ import annotations

import pytest

from vuln_hunter_x.verification.policy.loader import (
    PolicyOverlapError,
    PolicyRegistry,
    load_policy_from_mapping,
)

_TAINTED_FILENAME = "php.lang.security.injection.tainted-filename.tainted-filename"


def _path_access(name: str = "path_access"):
    return load_policy_from_mapping({
        "family": name,
        "selectors": {
            "languages": ["php"],
            "cwes": ["CWE-22", "CWE-98"],
            "rule_aliases": ["php/path-injection"],
        },
        "handoff_from": {
            "languages": ["php"],
            "rule_aliases": [_TAINTED_FILENAME, "php.lang.security.eval-use.eval-use"],
        },
        "applicability": {
            "slot": "sink_binding",
            "applicable_values": ["QUALIFYING_PATH_ACCESS_SINK"],
            "not_applicable_values": ["NOT_PATH_ACCESS_SINK"],
        },
        "fact_slots": {"sink_binding": ["QUALIFYING_PATH_ACCESS_SINK", "NOT_PATH_ACCESS_SINK"]},
        "decisive_slots": ["sink_binding"],
        "entailment": {"true_positive": {"sink_binding": "QUALIFYING_PATH_ACCESS_SINK"}},
    })


def _log_injection():
    # No handoff_from — must never be a handoff candidate.
    return load_policy_from_mapping({
        "family": "log_injection",
        "selectors": {"cwes": ["CWE-117"]},
        "fact_slots": {"sink_binding": ["QUALIFYING_LOG_SINK", "NOT_LOG_SINK"]},
        "decisive_slots": ["sink_binding"],
        "entailment": {"true_positive": {"sink_binding": "QUALIFYING_LOG_SINK"}},
    })


def test_tainted_filename_resolves_as_path_access_handoff():
    reg = PolicyRegistry([_path_access(), _log_injection()])
    p = reg.resolve_handoff(cwe_ids=["CWE-918"], rule_id=_TAINTED_FILENAME, lang="php")
    assert p is not None and p.family == "path_access"


def test_primary_owner_is_not_a_handoff_candidate():
    # A native php/path-injection finding is PRIMARILY owned -> not a handoff.
    reg = PolicyRegistry([_path_access()])
    assert reg.resolve_handoff(cwe_ids=["CWE-22"], rule_id="php/path-injection", lang="php") is None


def test_language_gate_blocks_non_php_handoff():
    reg = PolicyRegistry([_path_access()])
    assert reg.resolve_handoff(cwe_ids=["CWE-918"], rule_id=_TAINTED_FILENAME, lang="go") is None


def test_family_without_handoff_block_never_matches():
    reg = PolicyRegistry([_log_injection()])
    assert reg.resolve_handoff(cwe_ids=["CWE-117"], rule_id="js/log-injection", lang="javascript") is None


def test_multiple_distinct_handoff_targets_fail_closed():
    reg = PolicyRegistry([_path_access("path_access"), _path_access("path_access_2")])
    with pytest.raises(PolicyOverlapError):
        reg.resolve_handoff(cwe_ids=["CWE-918"], rule_id=_TAINTED_FILENAME, lang="php")
