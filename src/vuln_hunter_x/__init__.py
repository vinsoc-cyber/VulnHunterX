# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""
CodeQL + LLM Bug Verification Framework

A framework for combining CodeQL static analysis with LLM-based
bug verification using guided questions (LLM verification).

Example usage:
    from vuln_hunter_x import VerificationEngine

    engine = VerificationEngine.from_config("config/confirm_findings.yaml")
    results = engine.verify_sarif("output/c/repo/repo.sarif", lang="c", repo_name="repo")

    for verdict in results.verdicts:
        print(f"{verdict.finding.rule_id}: {verdict.verdict}")
"""

__version__ = "1.0.0"
__author__ = "VulnHunterX Team"

from vuln_hunter_x.core.types import Finding, GuidedQuestions, Verdict
from vuln_hunter_x.verification.engine import VerificationEngine

__all__ = [
    "Finding",
    "Verdict",
    "GuidedQuestions",
    "VerificationEngine",
    "__version__",
]
