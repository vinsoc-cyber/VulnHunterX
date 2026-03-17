"""
Stage 7.5: LLM fix loop for harness compile/link failures.

Given harness source + compile/link errors, ask LLM for corrected source,
replace file, re-run build; repeat up to max iterations.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import Path

from vuln_hunter_x.core.validation import normalize_ollama_model, openai_compat_kwargs

logger = logging.getLogger(__name__)

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


def _validate_harness_source(source: str) -> bool:
    """Ensure source contains the required entry point."""
    return REQUIRED_ENTRY in source


def fix_harness_with_llm(
    harness_path: Path,
    build_fn: Callable[[], tuple[bool, str, str]],
    llm_completion_fn: Callable[[str, str, str], str],
    max_iterations: int = 3,
) -> tuple[str, int, str]:
    """
    Run fix loop: on build failure, send source + errors to LLM, replace source, retry.

    Args:
        harness_path: Path to .cc file (will be overwritten).
        build_fn: No-arg callable that returns (success, stderr, command).
        llm_completion_fn: (source, errors, command) -> new source string from LLM.
        max_iterations: Max fix attempts.

    Returns:
        (final_status, iterations_used, last_errors)
        final_status: "compiled" | "compile_failed" | "link_failed" | "llm_fix_failed"
    """
    harness_path = Path(harness_path)
    last_errors = ""

    for iteration in range(max_iterations + 1):
        ok, err, cmd = build_fn()
        if ok:
            return "compiled", iteration, ""
        last_errors = err
        if iteration == max_iterations:
            break
        # Determine failure type for status
        if "undefined reference" in err or "ld returned" in err.lower() or "linker" in err.lower():
            pass
        else:
            pass

        source = harness_path.read_text(encoding="utf-8")
        new_source = llm_completion_fn(source, err, cmd)
        if not new_source:
            return "llm_fix_failed", iteration + 1, last_errors
        extracted = _extract_cpp_block(new_source)
        if not extracted or not _validate_harness_source(extracted):
            return "llm_fix_failed", iteration + 1, last_errors
        harness_path.write_text(extracted, encoding="utf-8")

    if "undefined reference" in last_errors or "ld returned" in last_errors.lower():
        return "link_failed", max_iterations, last_errors
    return "compile_failed", max_iterations, last_errors


def _classify_errors(errors: str) -> str:
    """Classify compiler/linker errors to provide targeted hints."""
    err_lower = errors.lower()
    if "undefined reference" in err_lower or "ld returned" in err_lower:
        return "linker"
    if "no such file or directory" in err_lower and "#include" in err_lower:
        return "missing_include"
    if "undeclared identifier" in err_lower or "use of undeclared" in err_lower:
        return "undefined_symbol"
    if "incompatible type" in err_lower or "cannot convert" in err_lower:
        return "type_mismatch"
    return "compilation"


def _error_specific_hint(error_class: str) -> str:
    """Return targeted hints based on error classification."""
    hints = {
        "linker": (
            "HINT: This is a LINKER error. Check if extern \"C\" linkage is needed, "
            "if the function is in a different translation unit, or if a library "
            "needs to be linked. Do NOT change the function signature."
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
    return hints.get(error_class, "")


FUZZ_FIX_SYSTEM = """You are a C++ build fix assistant. You will be given:
1) A libFuzzer harness source that failed to compile or link.
2) The compiler/linker command that was run.
3) The compiler/linker error output.
4) Optionally, previous fix attempts and their results.

Respond with ONLY the corrected full C++ source file. No explanation, no markdown outside a code block.
The code must contain the function: extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size).
Fix only the reported errors: add missing includes, fix types, fix link order or symbols. Preserve the harness structure.
If you have seen previous fix attempts that failed, do NOT repeat the same approach — try a different fix strategy."""


def make_llm_fix_fn(
    provider: str, model: str, max_tokens: int = 4000, type_context: str = ""
) -> Callable[[str, str, str], str]:
    """Build a multi-turn completion function that maintains conversation history."""
    import litellm

    model_id = normalize_ollama_model(model) if provider == "ollama" else model

    # Filter type context to be more relevant (increased budget to 4000 chars)
    type_ctx_section = (
        f"\nAvailable type definitions:\n{type_context[:4000]}\n" if type_context else ""
    )

    # Maintain conversation history across iterations
    message_history: list[dict[str, str]] = [
        {"role": "system", "content": FUZZ_FIX_SYSTEM},
    ]

    def complete(source: str, errors: str, command: str) -> str:
        error_class = _classify_errors(errors)
        hint = _error_specific_hint(error_class)

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
            kwargs.update(
                openai_compat_kwargs(
                    provider=provider,
                    model=model_id,
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
