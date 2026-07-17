# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Language-scoped family-policy selection (P2c S1).

A policy that declares ``selectors.languages`` matches only findings in those
languages; a policy with no ``languages`` stays language-agnostic (so the
CWE-117 log-injection policy is unchanged). This stops a CWE-643 / XPath policy
from silently capturing PHP/Go/Java/C#/C++ XPath findings.
"""

from __future__ import annotations

from vuln_hunter_x.verification.policy.loader import (
    PolicyRegistry,
    load_policy_from_mapping,
)

_LOG = {  # language-agnostic (no selectors.languages) — like CWE-117
    "family": "log_injection",
    "selectors": {"cwes": ["CWE-117"], "rule_aliases": ["*/log-injection"]},
    "fact_slots": {"sink_binding": ["QUALIFYING_LOG_SINK", "NOT_LOG_SINK"]},
    "decisive_slots": ["sink_binding"],
    "entailment": {
        "true_positive": {"sink_binding": "QUALIFYING_LOG_SINK"},
        "false_positive_if_any": [{"sink_binding": "NOT_LOG_SINK"}],
    },
    "admissibility": {
        "sink_binding": {
            "QUALIFYING_LOG_SINK": "LOCAL_POSITIVE",
            "NOT_LOG_SINK": "LOCAL_POSITIVE",
        }
    },
}

_XPATH = {  # python-scoped
    "family": "xpath_injection",
    "selectors": {
        "languages": ["python"],
        "cwes": ["CWE-643"],
        "rule_aliases": ["py/xpath-injection"],
    },
    "fact_slots": {"sink_binding": ["QUALIFYING_XPATH_SINK", "NOT_XPATH_SINK"]},
    "decisive_slots": ["sink_binding"],
    "entailment": {
        "true_positive": {"sink_binding": "QUALIFYING_XPATH_SINK"},
        "false_positive_if_any": [{"sink_binding": "NOT_XPATH_SINK"}],
    },
    "admissibility": {
        "sink_binding": {
            "QUALIFYING_XPATH_SINK": "LOCAL_POSITIVE",
            "NOT_XPATH_SINK": "LOCAL_POSITIVE",
        }
    },
}


def _registry():
    return PolicyRegistry([load_policy_from_mapping(_LOG), load_policy_from_mapping(_XPATH)])


def test_python_cwe643_selects_xpath():
    p = _registry().resolve_family(
        cwe_ids=["CWE-643"], rule_id="py/xpath-injection", lang="python"
    )
    assert p is not None and p.family == "xpath_injection"


def test_non_python_cwe643_stays_legacy():
    # A PHP XPath finding (CWE-643) must NOT be captured by the python-scoped policy.
    p = _registry().resolve_family(
        cwe_ids=["CWE-643"], rule_id="php/xpath-injection", lang="php"
    )
    assert p is None


def test_language_agnostic_policy_matches_any_language():
    # log_injection declares no languages -> matches regardless of lang (CWE-117 unchanged).
    p = _registry().resolve_family(
        cwe_ids=["CWE-117"], rule_id="js/log-injection", lang="javascript"
    )
    assert p is not None and p.family == "log_injection"


def test_language_match_is_case_insensitive():
    p = _registry().resolve_family(
        cwe_ids=["CWE-643"], rule_id="py/xpath-injection", lang="Python"
    )
    assert p is not None and p.family == "xpath_injection"


def test_missing_lang_matches_agnostic_only():
    reg = _registry()
    assert (
        reg.resolve_family(cwe_ids=["CWE-117"], rule_id="x/log-injection", lang="").family
        == "log_injection"
    )
    assert reg.resolve_family(cwe_ids=["CWE-643"], rule_id="py/xpath-injection", lang="") is None
