# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Prompt-policy lint: covered-family rules gather facts, they don't command a
verdict. Scoped to the CWE-117 first cut — the legacy python/java/cpp
verdict-forcing directives are intentionally NOT rewritten here, and this lint
inventories them so that fact is explicit (not silently claimed closed)."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

_PROMPTS = Path(__file__).resolve().parents[1] / "config" / "prompts"
_VERDICT_CMD = re.compile(
    r"verdict\s+(?:False|True)\s+Positive|the rule is likely correct", re.IGNORECASE
)


def _rule_text(entry: dict) -> str:
    parts = list(entry.get("questions", []))
    parts.append(entry.get("context_hint", ""))
    parts.append(entry.get("short_description", ""))
    return " ".join(parts)


def test_js_log_injection_rule_is_locators_only():
    data = yaml.safe_load((_PROMPTS / "javascript_questions.yaml").read_text())
    entry = data["js/log-injection"]
    assert not _VERDICT_CMD.search(_rule_text(entry)), (
        "the covered CWE-117 rule must gather facts, not command a verdict"
    )


def test_legacy_verdict_commands_are_inventoried_not_removed():
    # P2b does NOT close the global open/closed-world prompt contradiction. These
    # directives still exist (python/java/cpp); removing them is the CWE-643
    # follow-on increment. If this changes, update the follow-on scope.
    counts = {
        lang: len(_VERDICT_CMD.findall((_PROMPTS / f"{lang}_questions.yaml").read_text()))
        for lang in ("python", "java", "cpp")
    }
    assert counts["python"] > 0
    assert counts["java"] > 0
    assert counts["cpp"] > 0
