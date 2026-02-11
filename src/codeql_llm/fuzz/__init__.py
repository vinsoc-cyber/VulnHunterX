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
from codeql_llm.fuzz.generate_drivers import generate_fuzz_drivers, build_and_record
from codeql_llm.fuzz.driver_builder import build_harness, find_manifest_for_repo, write_harness_status
from codeql_llm.fuzz.driver_fix_loop import fix_harness_with_llm, make_llm_fix_fn
from codeql_llm.fuzz.runner import run_fuzzer, run_fuzzers_for_repo, run_all_fuzzers

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
    "build_and_record",
    "build_harness",
    "find_manifest_for_repo",
    "write_harness_status",
    "fix_harness_with_llm",
    "make_llm_fix_fn",
    "run_fuzzer",
    "run_fuzzers_for_repo",
    "run_all_fuzzers",
]
