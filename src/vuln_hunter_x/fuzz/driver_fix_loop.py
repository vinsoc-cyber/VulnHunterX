"""
Stage 7.5: LLM fix loop for harness compile/link failures.

Given harness source + compile/link errors, ask LLM for corrected source,
replace file, re-run build; repeat up to max iterations.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from vuln_hunter_x.core.constants import BUILD_LOG_LLM_PREVIEW_CHARS, DEFAULT_MAX_FIX_ITERATIONS
from vuln_hunter_x.core.validation import normalize_ollama_model, openai_compat_kwargs

logger = logging.getLogger(__name__)


@dataclass
class FixIterationRecord:
    """Detail of a single LLM fix iteration."""

    iteration: int
    errors: str
    error_class: str
    llm_response_preview: str  # first N chars of LLM response
    result: str  # "still_failing" | "fixed" | "llm_rejected" | "linker_bail"


@dataclass
class FixResult:
    """Rich result from fix_harness_with_llm(); backward-compatible with tuple unpacking."""

    status: str
    iterations_used: int
    last_errors: str
    iteration_history: list[FixIterationRecord] = field(default_factory=list)

    def __iter__(self):  # type: ignore[override]
        return iter((self.status, self.iterations_used, self.last_errors))


# Must appear in LLM output for us to accept it
REQUIRED_ENTRY = "LLVMFuzzerTestOneInput"


def _extract_cpp_block(text: str) -> str | None:
    """Extract first ```cpp ... ``` or ``` ... ``` block, or return full text if no block."""
    if not text or not text.strip():
        return None
    # Prefer ```cpp ... ```
    m = re.search(r"```\s*cpp\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
    if m:
        return m.group(1).strip()
    m = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)
    if m:
        return m.group(1).strip()
    return text.strip()


_REQUIRED_INCLUDES = ("cstdint", "cstdlib", "cstring")


def _validate_harness_source(source: str) -> bool:
    """Ensure source contains required entry point and essential C++ includes."""
    if REQUIRED_ENTRY not in source:
        return False
    # Reject sources missing critical headers (prevents LLM from gutting harness)
    for inc in _REQUIRED_INCLUDES:
        if f"#include <{inc}>" not in source and f"#include<{inc}>" not in source:
            return False
    return True


def fix_harness_with_llm(
    harness_path: Path,
    build_fn: Callable[[], tuple[bool, str, str]],
    llm_completion_fn: Callable[[str, str, str], str],
    max_iterations: int = DEFAULT_MAX_FIX_ITERATIONS,
) -> FixResult:
    """
    Run fix loop: on build failure, send source + errors to LLM, replace source, retry.

    Args:
        harness_path: Path to .cc file (will be overwritten).
        build_fn: No-arg callable that returns (success, stderr, command).
        llm_completion_fn: (source, errors, command) -> new source string from LLM.
        max_iterations: Max fix attempts.

    Returns:
        FixResult (supports tuple unpacking as (status, iterations_used, last_errors)).
    """
    harness_path = Path(harness_path)
    original_source = harness_path.read_text(encoding="utf-8")
    last_errors = ""
    history: list[FixIterationRecord] = []

    for iteration in range(max_iterations + 1):
        ok, err, cmd = build_fn()
        if ok:
            history.append(
                FixIterationRecord(
                    iteration=iteration,
                    errors="",
                    error_class="",
                    llm_response_preview="",
                    result="fixed",
                )
            )
            return FixResult("compiled", iteration, "", history)
        last_errors = err
        err_class = classify_errors(err)

        if iteration == max_iterations:
            history.append(
                FixIterationRecord(
                    iteration=iteration,
                    errors=err,
                    error_class=err_class,
                    llm_response_preview="",
                    result="still_failing",
                )
            )
            break

        # Linker errors (undefined reference) can't be fixed in source — stop early
        if "undefined reference" in err or "ld returned" in err.lower():
            history.append(
                FixIterationRecord(
                    iteration=iteration,
                    errors=err,
                    error_class=err_class,
                    llm_response_preview="",
                    result="linker_bail",
                )
            )
            harness_path.write_text(original_source, encoding="utf-8")
            return FixResult("link_failed", iteration, last_errors, history)

        source = harness_path.read_text(encoding="utf-8")
        new_source = llm_completion_fn(source, err, cmd)
        llm_preview = (new_source or "")[:BUILD_LOG_LLM_PREVIEW_CHARS]

        if not new_source:
            history.append(
                FixIterationRecord(
                    iteration=iteration,
                    errors=err,
                    error_class=err_class,
                    llm_response_preview=llm_preview,
                    result="llm_rejected",
                )
            )
            harness_path.write_text(original_source, encoding="utf-8")
            return FixResult("llm_fix_failed", iteration + 1, last_errors, history)

        extracted = _extract_cpp_block(new_source)
        if not extracted or not _validate_harness_source(extracted):
            history.append(
                FixIterationRecord(
                    iteration=iteration,
                    errors=err,
                    error_class=err_class,
                    llm_response_preview=llm_preview,
                    result="llm_rejected",
                )
            )
            harness_path.write_text(original_source, encoding="utf-8")
            return FixResult("llm_fix_failed", iteration + 1, last_errors, history)

        history.append(
            FixIterationRecord(
                iteration=iteration,
                errors=err,
                error_class=err_class,
                llm_response_preview=llm_preview,
                result="still_failing",
            )
        )
        harness_path.write_text(extracted, encoding="utf-8")

    # Exhausted iterations — restore original so .cc file isn't corrupted
    harness_path.write_text(original_source, encoding="utf-8")
    if "undefined reference" in last_errors or "ld returned" in last_errors.lower():
        return FixResult("link_failed", max_iterations, last_errors, history)
    return FixResult("compile_failed", max_iterations, last_errors, history)


def classify_errors(errors: str) -> str:
    """Classify compiler/linker errors to provide targeted hints."""
    err_lower = errors.lower()
    if "multiple definition of `main'" in err_lower or 'multiple definition of "main"' in err_lower:
        return "multiple_main"
    if "undefined reference" in err_lower or "ld returned" in err_lower:
        return "linker"
    if "no such file or directory" in err_lower and "#include" in err_lower:
        return "missing_include"
    if "undeclared identifier" in err_lower or "use of undeclared" in err_lower:
        return "undefined_symbol"
    if "incompatible type" in err_lower or "cannot convert" in err_lower:
        return "type_mismatch"
    return "compilation"


def _error_specific_hint(error_class: str, symbol_context: str = "") -> str:
    """Return targeted hints based on error classification and symbol context."""
    hints = {
        "linker": (
            'HINT: This is a LINKER error. Check if extern "C" linkage is needed, '
            'HINT: This is a LINKER error. Check if extern "C" linkage is needed, '
            "if the function is in a different translation unit, or if a library "
            "needs to be linked. Do NOT change the function signature."
        ),
        "multiple_main": (
            "HINT: Multiple definition of main(). The harness likely #includes a .c "
            "file that contains main(). Add '#define main __original_main_disabled' "
            "BEFORE the #include and '#undef main' AFTER it."
        ),
        "missing_include": (
            "HINT: A required header file is missing. Add the appropriate #include "
            "directive. Check the project's include paths for the correct header name."
        ),
        "undefined_symbol": (
            "HINT: A symbol is not declared. Check if a header needs to be included, "
            "if the symbol is in a specific namespace, or if a forward declaration is needed."
        ),
        "type_mismatch": (
            "HINT: There is a type incompatibility. Check if a cast is needed, "
            "if the correct type is being used, or if a const qualifier is missing."
        ),
        "compilation": "HINT: Fix the compilation errors. Add missing includes or fix type issues.",
    }
    hint = hints.get(error_class, "")
    if symbol_context:
        hint += f"\n\nSymbol context:\n{symbol_context}"
    return hint


FUZZ_FIX_SYSTEM = """You are a C++ build fix assistant. You will be given:
1) A libFuzzer harness source that failed to compile or link.
2) The compiler/linker command that was run.
3) The compiler/linker error output.
4) Optionally, previous fix attempts and their results.
5) Optionally, symbol context: which symbols are in libraries vs static.

Respond with ONLY the corrected full C++ source file. No explanation, no markdown outside a code block.
The code must contain the function: extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size).
Fix only the reported errors: add missing includes, fix types, fix link order or symbols. Preserve the harness structure.
If you have seen previous fix attempts that failed, do NOT repeat the same approach — try a different fix strategy.

Key techniques for common issues:
- Static/file-local functions: use #include "source.c" to access them directly.
- If #including a .c file that has main(): add #define main __original_main_disabled before and #undef main after.
- Linker errors for library functions: add extern "C" forward declarations.
- Missing symbols: check if the function exists in any linked library or object."""


def make_llm_fix_fn(
    provider: str,
    model: str,
    max_tokens: int = 4000,
    type_context: str = "",
    symbol_context: str = "",
) -> Callable[[str, str, str], str]:
    """Build a multi-turn completion function that maintains conversation history.

    Args:
        provider: LLM provider (openai, anthropic, ollama).
        model: Model identifier.
        max_tokens: Max tokens for LLM response.
        type_context: Struct/enum/typedef definitions.
        symbol_context: Symbol linkability info (library exports, static symbols).
    """
    import litellm

    # Normalize model ID and resolve api_base — mirrors LLMClient._build_completion_kwargs()
    api_base: str | None = None
    if provider == "ollama":
        model_id = normalize_ollama_model(model)
    elif provider == "openai":
        model_id = model
        api_base = (
            os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_BASE") or ""
        ).strip().rstrip("/") or None
        if api_base and not model_id.startswith("openai/"):
            model_id = "openai/" + model_id
    elif provider == "anthropic":
        model_id = model if model.startswith("anthropic/") else "anthropic/" + model
    else:
        model_id = model

    # Filter type context to be more relevant (increased budget to 4000 chars)
    type_ctx_section = (
        f"\nAvailable type definitions:\n{type_context[:4000]}\n" if type_context else ""
    )
    _symbol_context = symbol_context

    # Maintain conversation history across iterations
    message_history: list[dict[str, str]] = [
        {"role": "system", "content": FUZZ_FIX_SYSTEM},
    ]

    def complete(source: str, errors: str, command: str) -> str:
        error_class = _classify_errors(errors)
        hint = _error_specific_hint(error_class, symbol_context=_symbol_context)

        user = f"""Harness source:
```cpp
{source}
```

Command:
{command}

Errors ({error_class}):
```
{errors[:3500]}
```
{type_ctx_section}
{hint}

Respond with the corrected full C++ source only (use a ```cpp ... ``` block or plain code)."""

        message_history.append({"role": "user", "content": user})

        try:
            kwargs = {
                "model": model_id,
                "messages": list(message_history),
                "max_tokens": max_tokens,
            }
            if api_base:
                kwargs["api_base"] = api_base
            kwargs.update(
                openai_compat_kwargs(
                    provider=provider,
                    model=model_id,
                    api_base=api_base,
                    stream=False,
                )
            )
            resp = litellm.completion(**kwargs)
            content = (resp.choices or [{}])[0].get("message", {}).get("content") or ""

            # Add assistant response to history for multi-turn context
            message_history.append({"role": "assistant", "content": content})

            return content
        except Exception:
            logger.warning("LLM fix completion failed", exc_info=True)
            return ""

    return complete
