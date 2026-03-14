"""Centralized default values and constants.

All hardcoded defaults (model names, timeouts, URLs, truncation limits)
should be defined here so they can be easily found and updated.
"""

import multiprocessing

# ── LLM defaults ──────────────────────────────────────────────────────
DEFAULT_LLM_PROVIDER = "openai"
DEFAULT_LLM_MODEL = "gpt-4o"
DEFAULT_LLM_TEMPERATURE = 0.2
DEFAULT_LLM_MAX_TOKENS = 1500
DEFAULT_OLLAMA_BASE_URL = "http://localhost:11434"

# ── Verification defaults ─────────────────────────────────────────────
DEFAULT_MAX_ITERATIONS = 3

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
