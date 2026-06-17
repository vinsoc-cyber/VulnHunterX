# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""LLM client abstraction for OpenAI and Ollama."""

from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.llm.prompts import PromptBuilder

__all__ = [
    "LLMClient",
    "PromptBuilder",
]
