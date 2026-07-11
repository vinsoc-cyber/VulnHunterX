# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""#144 — the system-prompt loader is packaged, fail-fast, and single-source:
a missing/malformed prompt raises instead of silently serving a stale in-code
copy, and the divergent DEFAULT_SYSTEM_PROMPT is gone."""

from __future__ import annotations

import pytest

import vuln_hunter_x.llm.prompts as prompts
from vuln_hunter_x.llm.prompts import (
    PromptBuilder,
    _load_system_prompt_template,
    _parse_system_prompt,
)

_MARKER = "ANALYSIS METHODOLOGY"


def test_parse_accepts_valid() -> None:
    assert _parse_system_prompt("system_prompt: hello") == "hello"


def test_parse_rejects_non_mapping() -> None:
    with pytest.raises(RuntimeError):
        _parse_system_prompt("- a\n- b")


def test_parse_rejects_missing_key() -> None:
    with pytest.raises(RuntimeError):
        _parse_system_prompt("other_key: x")


def test_packaged_prompt_loads_and_is_canonical() -> None:
    text = _load_system_prompt_template()
    assert isinstance(text, str) and _MARKER in text


def test_default_system_prompt_removed() -> None:
    # Single source of truth — the divergent in-code copy must be gone.
    assert not hasattr(prompts, "DEFAULT_SYSTEM_PROMPT")


def test_promptbuilder_loads_eagerly() -> None:
    # Eager load in __init__ so a broken prompt fails before the analysis phase.
    pb = PromptBuilder()
    assert _MARKER in pb.get_system_prompt(tool_name="Semgrep", lang="php")
