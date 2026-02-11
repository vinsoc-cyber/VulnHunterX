"""Fuzz-based vulnerability confirmation (Stages 5–8)."""

from codeql_llm.fuzz.build_sanitized import (
    build_sanitized_env,
    run_sanitized_build,
    write_manifest,
    build_sanitized,
)
from codeql_llm.fuzz.extract_fuzz_context import (
    extract_fuzz_context_for_db,
    extract_fuzz_context_all,
    FUZZ_QUERIES,
)
from codeql_llm.fuzz.target_selection import (
    select_targets,
    find_enclosing_function,
    load_verification_verdicts,
)
from codeql_llm.fuzz.fuzz_context import get_target_context, load_function_signatures, load_includes
from codeql_llm.fuzz.driver_generator import generate_harness
from codeql_llm.fuzz.generate_drivers import generate_fuzz_drivers

__all__ = [
    "build_sanitized_env",
    "run_sanitized_build",
    "write_manifest",
    "build_sanitized",
    "extract_fuzz_context_for_db",
    "extract_fuzz_context_all",
    "FUZZ_QUERIES",
    "select_targets",
    "find_enclosing_function",
    "load_verification_verdicts",
    "get_target_context",
    "load_function_signatures",
    "load_includes",
    "generate_harness",
    "generate_fuzz_drivers",
]
