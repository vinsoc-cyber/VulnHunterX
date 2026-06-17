# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Centralized default values and constants.

All hardcoded defaults (model names, timeouts, URLs, truncation limits)
should be defined here so they can be easily found and updated.
"""

import multiprocessing

# ── LLM defaults ──────────────────────────────────────────────────────
DEFAULT_LLM_PROVIDER = "openai"
DEFAULT_LLM_MODEL = "gpt-4o"
DEFAULT_LLM_TEMPERATURE = 0.2
# 4096 was chosen after the 2026-05-15 diversevul benchmark revealed mid-
# verdict JSON truncation at 1500 (case dvul_58f5580c074a): the LLM had
# already enumerated the missing authorization check in its reasoning but
# ran out of budget before closing the JSON object, so the force-decision
# fallback fired and defaulted to FP. 4096 fits a 6-question verdict with
# line-cited answers comfortably.
DEFAULT_LLM_MAX_TOKENS = 4096
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"

# ── Verification defaults ─────────────────────────────────────────────
DEFAULT_MAX_ITERATIONS = 10

# ── Fuzz fix-loop defaults ───────────────────────────────────────────
DEFAULT_MAX_FIX_ITERATIONS = 5

# ── Timeout defaults (seconds) ────────────────────────────────────────
TIMEOUT_GIT_CLONE = 300  # 5 minutes
TIMEOUT_CODEQL_DB_CREATE = 1800  # 30 minutes
TIMEOUT_CODEQL_ANALYSIS = 3600  # 1 hour
TIMEOUT_CODEQL_QUERY = 600  # 10 minutes
TIMEOUT_CODEQL_FINALIZE = 120  # 2 minutes
TIMEOUT_SEMGREP_ANALYSIS = 3600  # 1 hour
TIMEOUT_SANITIZED_BUILD = 1800  # 30 minutes

# ── CodeQL resource defaults ──────────────────────────────────────────
CODEQL_THREADS = min(max(1, multiprocessing.cpu_count()), 8)  # cap at 8 to limit memory pressure
CODEQL_RAM_MB = 8192  # 8 GB — gives JVM ~3.6 GB heap for caching query stages
CODEQL_QUERY_TIMEOUT_SEC = 60  # 1 min per-query timeout (kills hanging queries)
CODEQL_PARALLEL_JOBS = 2  # default number of parallel repo analyses

# ── Truncation limits (characters) ────────────────────────────────────
TRUNCATION_VERBOSE_PROMPT = 1000
TRUNCATION_VERBOSE_MESSAGE = 2000
TRUNCATION_TYPE_CONTEXT = 2000
TRUNCATION_REASONING = 500
TRUNCATION_ERROR_OUTPUT = 2000

# ── Build log limits (characters) ────────────────────────────────────
BUILD_LOG_LLM_PREVIEW_CHARS = 500  # LLM response preview per fix iteration
BUILD_LOG_MAX_ERROR_CHARS = 10000  # full error text in build_log.json
