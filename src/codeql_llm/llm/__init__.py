"""LLM client abstraction for OpenAI and Ollama."""

from codeql_llm.llm.client import LLMClient
from codeql_llm.llm.prompts import PromptBuilder

__all__ = [
    "LLMClient",
    "PromptBuilder",
]
