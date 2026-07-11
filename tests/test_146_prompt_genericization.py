# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""#146 — target-specific tokens must not leak into prompt text.

The prompt string sent to the model should carry the GENERAL test/benchmark/
vendored discipline, not one target's specific filenames, a codec-shaped loop
bound, or a dated point-in-time accuracy statistic. Target provenance belongs
in a code comment, not the model-facing text.
"""
from __future__ import annotations

from pathlib import Path

from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.questions.loader import QuestionsLoader

_PROMPTS = Path("config/prompts")


def test_cpp_int_mult_prompt_free_of_target_tokens() -> None:
    q = QuestionsLoader(_PROMPTS).get_questions("cpp/integer-multiplication-cast-to-long")
    text = " ".join(q.questions)
    # target-specific tokens (libjpeg-turbo filenames / bundled deps / codec bound)
    for tok in ("tjunittest", "tjbench", "zlib", "spng", "w<48", "h<2048"):
        assert tok not in text, f"target-specific token {tok!r} leaked into prompt text"
    # the GENERAL non-production discipline must remain
    lower = text.lower()
    assert "vendored" in lower and "third-party" in lower
    assert "benchmark" in lower and "fuzz" in lower


def test_second_opinion_prompt_qualitative_not_dated_stat() -> None:
    p = LLMClient._SECOND_OPINION_PROMPT
    # the point-in-time statistic and its date must not be asserted to the model
    assert "80%" not in p and "2026-05-15" not in p
    assert "% of the time" not in p
    # the enumerate-the-defense method and the FP-challenge framing must survive
    assert "(a)" in p and "(b)" in p and "(c)" in p
    assert "False Positive" in p
