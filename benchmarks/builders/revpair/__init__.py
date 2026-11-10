# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Revision-pair (vulnerable parent vs. patched fix commit) manifest builder.

For every CVE fix commit the builder checks out the parent ("vulnerable") and
the fix ("patched") revision, runs the product's own scanners on both with
identical rules, and labels each vulnerable-side alert automatically by diffing
the two alert sets against the fix's ``git diff``. Labels are *silver*: every
emitted entry carries ``metadata.label_source="auto-diff"`` and
``metadata.adjudication="pending"``.

Modules:
    checkout   — bare mirror cache + detached worktrees, SHA/URL validation
    hunks      — ``git diff -U0 -M`` parser and old→new line mapping
    alert_key  — line-shift-robust alert identity and cross-revision matching
    label      — tier assignment (silver-tp / silver-tp-weak / persistent / ambiguous)
    runner     — per-revision scanner orchestration with stale-output guards
    manifest   — frozen JSONL manifest + sha256 + attrition JSON
"""
