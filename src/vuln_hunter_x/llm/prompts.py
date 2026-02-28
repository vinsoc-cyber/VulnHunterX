"""Prompt templates for LLM bug verification."""

from __future__ import annotations

import logging
from pathlib import Path

import yaml

from vuln_hunter_x.core.types import Finding, GuidedQuestions

logger = logging.getLogger(__name__)

# Default system prompt used when config/prompts/system_prompt.yaml is missing.
DEFAULT_SYSTEM_PROMPT = """You are a security static-analysis expert specializing in {lang} code.

You are reviewing a finding reported by {tool_name}. Your task is to determine
whether it is a real vulnerability (True Positive) or a false alarm (False Positive).

ANALYSIS METHODOLOGY — follow these steps IN ORDER:
1. IDENTIFY the vulnerability class from the rule ID and description.
2. ANSWER every guided question by examining ONLY the provided code context.
   - Cite specific line numbers when referencing code.
   - If information is not visible, say "Not visible in provided context".
3. TRACE the data flow: source → any transformations/sanitization → sink.
   - List each step with line numbers.
4. EVALUATE whether the code path is actually reachable and exploitable.
5. ONLY THEN provide your verdict.

VERDICT RULES:
- "True Positive": The code is CLEARLY vulnerable — an exploitable path exists
  with NO adequate sanitization or bounds checking.
- "False Positive": The code is SAFE — you can point to specific checks,
  constraints, type guarantees, or language features that prevent exploitation.
- "Needs More Data": Critical information is missing (caller context, type
  definitions, etc.) that would change your verdict either way.

IMPORTANT CONSTRAINTS:
- Do NOT speculate beyond the shown code — base your analysis only on visible evidence.
- Do NOT call something a True Positive unless the vulnerability is CLEARLY present.
- When in doubt between True Positive and False Positive, prefer "Needs More Data" over guessing.
- Language-specific safety: consider {lang} memory model, type system, and
  standard library guarantees when evaluating.

If answering "Needs More Data", specify EXACTLY what you need:
- "caller:function_name" — the calling function's code
- "struct:type_name" — a struct/class definition
- "global:variable_name" — a global variable declaration
- "macro:MACRO_NAME" — a macro definition

Response format (strict JSON):
{{
  "answers": ["answer to Q1 with line references", "answer to Q2", ...],
  "data_flow": "source (line N) → transform (line M) → sink (line K)",
  "verdict": "True Positive" | "False Positive" | "Needs More Data",
  "confidence": "High" | "Medium" | "Low",
  "reasoning": "1-2 sentence explanation referencing your answers and data flow",
  "context_needed": ["caller:main", "struct:buffer_t"]
}}"""

_SYSTEM_PROMPT_YAML = (
    Path(__file__).resolve().parents[3] / "config" / "prompts" / "system_prompt.yaml"
)


def _load_system_prompt_template() -> str:
    """Load the system prompt template from YAML, falling back to the built-in default."""
    try:
        if _SYSTEM_PROMPT_YAML.is_file():
            with open(_SYSTEM_PROMPT_YAML, encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict) and "system_prompt" in data:
                return data["system_prompt"]
    except Exception:
        logger.warning(
            "Failed to load system prompt from %s; using built-in default",
            _SYSTEM_PROMPT_YAML,
            exc_info=True,
        )
    return DEFAULT_SYSTEM_PROMPT


class PromptBuilder:
    """Builds prompts for LLM bug verification."""

    def __init__(self) -> None:
        self._template: str | None = None

    @property
    def _system_prompt_template(self) -> str:
        """Lazy-load the system prompt template."""
        if self._template is None:
            self._template = _load_system_prompt_template()
        return self._template

    def get_system_prompt(
        self,
        tool_name: str = "static analysis",
        lang: str = "",
    ) -> str:
        """Return the system prompt with placeholders filled in."""
        return self._system_prompt_template.format(
            tool_name=tool_name or "static analysis",
            lang=lang or "the target",
        )

    @property
    def system_prompt(self) -> str:
        """Get the system prompt (generic, no tool/lang context).

        Kept for backward compatibility; prefer get_system_prompt().
        """
        return self.get_system_prompt()

    def build_user_prompt(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
    ) -> str:
        """Build the user prompt for the LLM."""
        questions_text = "\n".join(f"{i + 1}. {q}" for i, q in enumerate(questions.questions))
        return self._build_prompt(finding, context, questions, func_name, questions_text)

    def _build_prompt(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
        questions_text: str,
    ) -> str:
        """Build LLM mode prompt."""
        tool_label = finding.tool or "Static Analysis"
        lang_tag = finding.lang or ""
        return f"""## {tool_label} Finding

**Rule**: {finding.rule_id}
**Description**: {questions.short_description}
**Message**: {finding.message}
**File**: {finding.file}
**Flagged line**: {finding.start_line}
**Language**: {finding.lang}

## Code Context

Function: `{func_name}`

```{lang_tag}
{context}
```

## Before deciding if this is a real issue, you MUST answer the following questions FIRST:

{questions_text}

---

IMPORTANT: Answer ALL {len(questions.questions)} questions above by examining the code context.
Cite specific line numbers in your answers.
ONLY AFTER answering every question, provide your final verdict in JSON format."""

    def build_followup_prompt(self, additional_context: dict[str, str]) -> str:
        """Build a follow-up prompt with additional context."""
        additional_text = "\n\n".join(
            f"### {req}\n```\n{code}\n```" for req, code in additional_context.items()
        )

        return f"""Here is the additional context you requested:

{additional_text}

INSTRUCTIONS:
1. Re-examine the original guided questions — does this new context change any of your previous answers?
2. Re-trace the data flow with the additional context included.
3. Provide your updated verdict in the same JSON format."""
