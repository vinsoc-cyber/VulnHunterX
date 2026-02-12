"""LLM client abstraction for OpenAI and Ollama."""

from vuln_hunter_x.llm.client import LLMClient
from vuln_hunter_x.llm.prompts import PromptBuilder

__all__ = [
    "LLMClient",
    "PromptBuilder",
]
