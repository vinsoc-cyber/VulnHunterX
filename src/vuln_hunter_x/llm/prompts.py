"""Prompt templates for LLM bug verification."""

from __future__ import annotations

from vuln_hunter_x.core.types import Finding, GuidedQuestions

# LLM mode: Multi-turn prompt with step-by-step reasoning and context expansion
SYSTEM_PROMPT = """You are a security static-analysis assistant.

Your task is to determine if a CodeQL finding is a real vulnerability or a false positive.

CRITICAL INSTRUCTIONS:
1. You will receive a CodeQL alert with code context and guided questions.
2. You MUST answer EVERY guided question FIRST, based ONLY on the code shown.
3. ONLY AFTER answering ALL questions, provide your verdict.
4. Do NOT speculate beyond the shown code.
5. Do NOT call something a bug unless the code is CLEARLY unsafe.

Rules for answering questions:
- Trace variable declarations, sizes, and values step by step.
- Note any assignments, reallocations, or changes to values.
- Identify checks, constraints, or sanitization on the data path.
- If you cannot find the answer in the code, say "Not visible in context".

Rules for verdict:
- "True Positive": The code is CLEARLY vulnerable based on the evidence.
- "False Positive": The code is SAFE because of checks, constraints, or context.
- "Needs More Data": You need additional context (caller, struct definition, etc.).

If answering "Needs More Data", specify EXACTLY what context you need:
- "caller:function_name" - need to see the calling function
- "struct:type_name" - need the struct/class definition
- "global:variable_name" - need to see a global variable
- "macro:MACRO_NAME" - need the macro definition

Response format (JSON):
{
  "answers": ["detailed answer to Q1", "detailed answer to Q2", ...],
  "verdict": "True Positive" | "False Positive" | "Needs More Data",
  "confidence": "High" | "Medium" | "Low",
  "reasoning": "1-2 sentence explanation based on your answers",
  "context_needed": ["caller:main", "struct:buffer_t"]  // only if verdict is "Needs More Data"
}"""


class PromptBuilder:
    """Builds prompts for LLM bug verification (LLM mode only)."""
    
    @property
    def system_prompt(self) -> str:
        """Get the system prompt."""
        return SYSTEM_PROMPT
    
    def build_user_prompt(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
    ) -> str:
        """Build the user prompt for the LLM."""
        questions_text = "\n".join(
            f"{i+1}. {q}" for i, q in enumerate(questions.questions)
        )
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
        return f"""## CodeQL Finding

**Rule**: {finding.rule_id}
**Description**: {questions.short_description}
**Message**: {finding.message}
**File**: {finding.file}
**Line**: {finding.start_line}

## Code Context

Function: `{func_name}`

```
{context}
```

## Before deciding if this is a real issue, you MUST answer the following questions FIRST:

{questions_text}

---

IMPORTANT: Answer ALL {len(questions.questions)} questions above by examining the code context.
ONLY AFTER answering every question, provide your final verdict in JSON format."""
    
    def build_followup_prompt(self, additional_context: dict[str, str]) -> str:
        """Build a follow-up prompt with additional context."""
        additional_text = "\n\n".join(
            f"### {req}\n```\n{code}\n```"
            for req, code in additional_context.items()
        )
        
        return f"""Here is the additional context you requested:

{additional_text}

Now, please re-analyze the finding with this additional context and provide your final verdict in JSON format."""
