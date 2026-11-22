# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 VinSOC Cyber

"""LLM client abstraction for OpenAI and Ollama."""

from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.llm.prompts import PromptBuilder

__all__ = [
    "LLMClient",
    "PromptBuilder",
]
