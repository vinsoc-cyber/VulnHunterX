# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Fuzz-based vulnerability confirmation (Stages 5–8)."""

from vuln_hunter_x.fuzz.build_sanitized import (
    build_sanitized,
    build_sanitized_env,
    run_sanitized_build,
    write_manifest,
)
from vuln_hunter_x.fuzz.driver_builder import (
    build_harness,
    find_manifest_for_repo,
    write_harness_status,
)
from vuln_hunter_x.fuzz.driver_fix_loop import fix_harness_with_llm, make_llm_fix_fn
from vuln_hunter_x.fuzz.driver_generator import generate_harness
from vuln_hunter_x.fuzz.extract_fuzz_context import (
    FUZZ_QUERIES,
    extract_fuzz_context_all,
    extract_fuzz_context_for_db,
)
from vuln_hunter_x.fuzz.fuzz_context import (
    build_type_context_string,
    get_target_context,
    load_callers,
    load_function_signatures,
    load_globals,
    load_includes,
    load_macros,
    load_structs,
)
from vuln_hunter_x.fuzz.generate_drivers import build_and_record, generate_fuzz_drivers
from vuln_hunter_x.fuzz.runner import run_all_fuzzers, run_fuzzer, run_fuzzers_for_repo
from vuln_hunter_x.fuzz.target_selection import (
    find_enclosing_function,
    load_verification_verdicts,
    score_target,
    select_targets,
)

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
    "load_structs",
    "load_globals",
    "load_macros",
    "load_callers",
    "build_type_context_string",
    "score_target",
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
