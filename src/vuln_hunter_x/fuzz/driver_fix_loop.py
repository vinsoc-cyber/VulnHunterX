"""
Stage 7.5: LLM fix loop for harness compile/link failures.

Given harness source + compile/link errors, ask LLM for corrected source,
replace file, re-run build; repeat up to max iterations.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

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
    last_command = ""

    for iteration in range(max_iterations + 1):
        ok, err, cmd = build_fn()
        if ok:
            return "compiled", iteration, ""
        last_errors = err
        last_command = cmd
        if iteration == max_iterations:
            break
        # Determine failure type for status
        if "undefined reference" in err or "ld returned" in err.lower() or "linker" in err.lower():
            status_after = "link_failed"
        else:
            status_after = "compile_failed"

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


FUZZ_FIX_SYSTEM = """You are a C++ build fix assistant. You will be given:
1) A libFuzzer harness source that failed to compile or link.
2) The compiler/linker command that was run.
3) The compiler/linker error output.

Respond with ONLY the corrected full C++ source file. No explanation, no markdown outside a code block.
The code must contain the function: extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size).
Fix only the reported errors: add missing includes, fix types, fix link order or symbols. Preserve the harness structure."""


def make_llm_fix_fn(provider: str, model: str, max_tokens: int = 4000, type_context: str = "") -> Callable[[str, str, str], str]:
    """Build a completion function that calls the LLM with the fix prompt."""
    import litellm

    if provider == "ollama":
        model_id = f"ollama/{model}" if not model.startswith("ollama/") else model
    else:
        model_id = model

    type_ctx_section = (
        f"\nAvailable type definitions:\n{type_context[:2000]}\n"
        if type_context
        else ""
    )

    def complete(source: str, errors: str, command: str) -> str:
        user = f"""Harness source:
```cpp
{source}
```

Command:
{command}

Errors:
```
{errors[:3500]}
```
{type_ctx_section}
Respond with the corrected full C++ source only (use a ```cpp ... ``` block or plain code)."""
        try:
            resp = litellm.completion(
                model=model_id,
                messages=[
                    {"role": "system", "content": FUZZ_FIX_SYSTEM},
                    {"role": "user", "content": user},
                ],
                max_tokens=max_tokens,
            )
            content = (resp.choices or [{}])[0].get("message", {}).get("content") or ""
            return content
        except Exception:
            return ""

    return complete
