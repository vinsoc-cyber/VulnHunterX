# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""LLM client abstraction for OpenAI, Anthropic, Ollama (local + cloud), DeepSeek, and Gemini via LiteLLM."""

from __future__ import annotations

import json
import logging
import os
import re
import time
from typing import Any


# Newer litellm versions log two benign WARNINGs on import when the optional
# AWS SDK (botocore) is absent — it is only needed for Bedrock/SageMaker
# event-stream decoding, which this project does not use. The warnings fire
# *during* `import litellm`, so drop them with a filter on litellm's logger
# installed beforehand. litellm never resets this logger's level, so the
# filter persists; unrelated litellm warnings/errors pass through unchanged.
def _drop_litellm_aws_preload_warnings(record: logging.LogRecord) -> bool:
    return "could not pre-load" not in str(record.msg)


logging.getLogger("LiteLLM").addFilter(_drop_litellm_aws_preload_warnings)

import litellm  # noqa: E402 — must follow the logger filter above

litellm.suppress_debug_info = True
# Drop per-model-unsupported params instead of erroring. Reasoning models
# (gpt-5 / gpt-5-codex / o-series) reject temperature != 1 with
# UnsupportedParamsError; with this set, litellm silently drops temperature
# for those models (they run at their forced default) while models that DO
# support it keep the configured value. Essential for a multi-model harness.
litellm.drop_params = True

from vuln_hunter_x.context.provider import ContextProvider
from vuln_hunter_x.core.config import _load_gemini_api_keys
from vuln_hunter_x.core.constants import (
    DEFAULT_LLM_MAX_TOKENS,
    DEFAULT_LLM_MODEL,
    DEFAULT_LLM_PROVIDER,
    DEFAULT_LLM_TEMPERATURE,
    DEFAULT_OLLAMA_BASE_URL,
    PROMPT_RETRY_MAX_TOKENS,
)
from vuln_hunter_x.core.types import Finding, GuidedQuestions, Verdict
from vuln_hunter_x.core.validation import openai_compat_kwargs
from vuln_hunter_x.llm.decision_strategy import (
    Abstain,
    DecisionStrategy,
    Finalize,
    Retrieve,
)
from vuln_hunter_x.llm.key_pool import KeyPool, extract_retry_after
from vuln_hunter_x.llm.prompts import PromptBuilder

logger = logging.getLogger(__name__)


def _extract_cached_input_tokens(usage: Any) -> int:
    """Pull cache-hit input-token count from a LiteLLM/OpenAI usage object.

    Different providers expose this differently:
      - OpenAI / LiteLLM normalised: ``usage.prompt_tokens_details.cached_tokens``
      - DeepSeek raw: ``usage.prompt_cache_hit_tokens``
    Returns 0 when neither is present.
    """
    if usage is None:
        return 0
    details = getattr(usage, "prompt_tokens_details", None)
    if details is not None:
        cached = getattr(details, "cached_tokens", None)
        if cached is None and isinstance(details, dict):
            cached = details.get("cached_tokens")
        if cached:
            return int(cached)
    cached = getattr(usage, "prompt_cache_hit_tokens", None)
    if cached is None and isinstance(usage, dict):
        cached = usage.get("prompt_cache_hit_tokens") or (
            usage.get("prompt_tokens_details", {}).get("cached_tokens")
            if isinstance(usage.get("prompt_tokens_details"), dict)
            else None
        )
    return int(cached or 0)


class LLMClient:
    """
    Unified LLM client using LiteLLM for OpenAI, Anthropic, Ollama, DeepSeek, and Gemini.

    Uses LLM mode only (multi-turn with context expansion).
    """

    def __init__(
        self,
        provider: str = DEFAULT_LLM_PROVIDER,
        model: str = DEFAULT_LLM_MODEL,
        temperature: float = DEFAULT_LLM_TEMPERATURE,
        max_tokens: int = DEFAULT_LLM_MAX_TOKENS,
        num_retries: int = 1,
        request_timeout: float = 180.0,
        ollama_api_keys: list[str] | None = None,
        ollama_key_state_path: str | os.PathLike[str] | None = None,
        gemini_api_keys: list[str] | None = None,
        gemini_key_state_path: str | os.PathLike[str] | None = None,
    ):
        """Initialize the LLM client.

        Args:
            provider: LLM provider ("openai", "anthropic", "ollama",
                "deepseek", or "gemini").
            model: Model name (e.g. "gpt-4o", "claude-sonnet-4-20250514").
            temperature: Sampling temperature for LLM responses.
            max_tokens: Maximum tokens in LLM response.
            num_retries: Times LiteLLM will retry transient failures
                (RateLimitError, APIConnectionError, Timeout, InternalServerError)
                with exponential backoff and Retry-After honored. 0 disables.
            request_timeout: Per-request timeout (seconds) forwarded to
                litellm.completion so a stuck call raises Timeout instead of
                hanging the run (#127). Retries multiply the effective ceiling.
            ollama_api_keys: Optional list of Ollama Cloud API keys (sourced
                from ``OLLAMA_API_KEYS`` as comma-separated values). When 2+
                keys are provided and the model targets Ollama Cloud, requests
                round-robin across them and a 429 parks the offending key
                until ``Retry-After`` elapses. A single key is sent verbatim.
            gemini_api_keys: Optional list of Gemini (AI Studio) API keys,
                same pool semantics as ``ollama_api_keys``. Defaults to
                ``GEMINI_API_KEYS`` / comma-separated ``GEMINI_API_KEY``
                (``GOOGLE_API_KEY`` single-key fallback) when omitted.
        """
        self.provider = provider
        self.model = model
        self.temperature = temperature
        self.max_tokens = max_tokens
        # #149: attach response_format=json_object where supported; cleared for
        # the session if an endpoint rejects it (see _completion).
        self._response_format_supported = True
        self.num_retries = num_retries
        self.request_timeout = request_timeout
        self.prompt_builder = PromptBuilder()

        # Configure provider-specific settings
        self._is_ollama_cloud = False
        if provider == "ollama":
            ollama_base = os.environ.get("OLLAMA_API_BASE", "").strip()
            # Ollama Cloud (ollama.com) uses bearer-auth chat-completions; local
            # ollama (localhost:11434) does not. Detect cloud by either the
            # endpoint or the model tag (cloud models carry a ":cloud" or
            # "-cloud" suffix, e.g. gpt-oss:120b-cloud, qwen3-coder-next:cloud).
            bare_model = self.model.removeprefix("ollama_chat/").removeprefix("ollama/")
            tag_is_cloud = bare_model.endswith(":cloud") or bare_model.endswith("-cloud")
            self._is_ollama_cloud = "ollama.com" in ollama_base or tag_is_cloud
            if self._is_ollama_cloud:
                if "ollama.com" not in ollama_base:
                    ollama_base = "https://ollama.com"
                if not self.model.startswith("ollama_chat/"):
                    self.model = "ollama_chat/" + bare_model
            else:
                ollama_base = ollama_base or DEFAULT_OLLAMA_BASE_URL
                if not self.model.startswith(("ollama/", "ollama_chat/")):
                    self.model = "ollama/" + self.model
            os.environ["OLLAMA_API_BASE"] = ollama_base
        elif provider == "anthropic":
            # LiteLLM reads ANTHROPIC_API_KEY from the environment automatically.
            # Prefix the model name so LiteLLM routes to the Anthropic backend.
            if not self.model.startswith("anthropic/"):
                self.model = "anthropic/" + self.model
        elif provider == "deepseek":
            # Route via LiteLLM's native DeepSeek provider (not openai/ + base_url)
            # so completion_cost() can price the call from the model name. Auth /
            # base_url are resolved in _build_completion_kwargs (DEEPSEEK_* with an
            # OPENAI_* fallback). Known ids (deepseek-chat/-reasoner/-v3.2) price
            # immediately; newer ids report $0 until LiteLLM's table includes them.
            if not self.model.startswith("deepseek/"):
                self.model = "deepseek/" + self.model
        elif provider == "gemini":
            # Google AI Studio via LiteLLM's native gemini/ route (Vertex AI
            # out of scope). Auth is injected in _build_completion_kwargs from
            # GEMINI_API_KEY (GOOGLE_API_KEY fallback) — NOT left to LiteLLM's
            # auto-read, whose precedence is GOOGLE-first and would invert ours.
            if not self.model.startswith("gemini/"):
                self.model = "gemini/" + self.model

        # Build key pool only when there's something to rotate. A single key
        # is stashed on the client and sent directly. Ollama Cloud and Gemini
        # support pools; other providers rely on env-based auth.
        pool_keys: list[str] = []
        pool_state_path: str | os.PathLike[str] | None = None
        pool_label = ""
        if self.provider == "ollama" and self._is_ollama_cloud and ollama_api_keys:
            pool_keys = ollama_api_keys
            pool_state_path = ollama_key_state_path
            pool_label = "Ollama Cloud"
        elif self.provider == "gemini":
            pool_keys = gemini_api_keys if gemini_api_keys is not None else _load_gemini_api_keys()
            pool_state_path = gemini_key_state_path
            pool_label = "Gemini"

        self._key_pool: KeyPool | None = None
        self._single_key: str | None = None
        if len(pool_keys) == 1:
            self._single_key = pool_keys[0]
        elif len(pool_keys) >= 2:
            self._key_pool = KeyPool(pool_keys, state_path=pool_state_path)
            status = self._key_pool.status()
            cooling = [(tail, secs) for tail, secs in status if secs > 0]
            logger.info(
                "%s key pool: %d key(s) [%s]%s",
                pool_label,
                len(status),
                ", ".join(f"…{tail}" for tail, _ in status),
                (
                    f"; {len(cooling)} cooling from prior runs: "
                    + ", ".join(f"…{t} ({int(s)}s)" for t, s in cooling)
                    if cooling
                    else ""
                ),
            )

    def _build_completion_kwargs(
        self,
        messages: list[dict],
        temperature: float | None = None,
    ) -> dict:
        """Build kwargs for litellm.completion with provider-specific settings."""
        model = self.model
        api_base = None
        api_key = None
        if self.provider == "openai":
            api_base = (
                os.environ.get("OPENAI_BASE_URL") or os.environ.get("OPENAI_API_BASE") or ""
            ).strip()
            api_base = api_base.rstrip("/") if api_base else None
            if api_base and not model.startswith("openai/"):
                model = "openai/" + model
        elif self.provider == "deepseek":
            # LiteLLM auto-reads DEEPSEEK_API_KEY; fall back to OPENAI_* so an
            # existing OpenAI-keyed DeepSeek .env keeps working after switching
            # LLM_PROVIDER to "deepseek". api_base defaults to api.deepseek.com.
            api_key = os.environ.get("DEEPSEEK_API_KEY") or os.environ.get("OPENAI_API_KEY")
            api_base = (
                os.environ.get("DEEPSEEK_API_BASE")
                or os.environ.get("OPENAI_BASE_URL")
                or os.environ.get("OPENAI_API_BASE")
                or ""
            ).strip()
            api_base = api_base.rstrip("/") if api_base else None
        elif self.provider == "gemini":
            # api_key is injected from the pool / single key below (parsed from
            # GEMINI_API_KEYS / comma-separated GEMINI_API_KEY, GOOGLE_API_KEY
            # fallback) — NOT left to LiteLLM's auto-read, whose precedence is
            # GOOGLE-first and would invert ours.
            api_base = (os.environ.get("GEMINI_API_BASE") or "").strip()
            api_base = api_base.rstrip("/") if api_base else None
        kwargs: dict[str, Any] = {
            "model": model,
            "messages": messages,
            "temperature": self.temperature if temperature is None else temperature,
            "max_tokens": self.max_tokens,
            "timeout": self.request_timeout,
        }
        if api_base:
            kwargs["api_base"] = api_base
        if api_key:
            kwargs["api_key"] = api_key
        if self.provider == "ollama" and self._is_ollama_cloud:
            kwargs["api_base"] = os.environ["OLLAMA_API_BASE"].rstrip("/")
        if self._key_pool is not None:
            pooled = self._key_pool.acquire()
            if pooled:
                kwargs["api_key"] = pooled
        elif self._single_key:
            kwargs["api_key"] = self._single_key
        if self.num_retries and self._key_pool is None:
            # LiteLLM retries RateLimitError / APIConnectionError / Timeout /
            # InternalServerError with exponential backoff and honors Retry-After.
            # When the pool is active our wrapper rotates keys instead, so we
            # disable LiteLLM's own retry to avoid hammering the exhausted key.
            kwargs["num_retries"] = self.num_retries
            kwargs["retry_strategy"] = "exponential_backoff_retry"
        # #149: guarantee a JSON envelope on OpenAI-compatible providers (json
        # mode). Dropped + disabled on the fly if the endpoint rejects it (see
        # _completion). Strict-schema field enforcement is deferred to Phase 3.
        if getattr(self, "_response_format_supported", True) and self.provider in (
            "openai",
            "deepseek",
        ):
            kwargs["response_format"] = {"type": "json_object"}
        kwargs.update(
            openai_compat_kwargs(
                provider=self.provider,
                model=model,
                api_base=api_base,
                stream=False,
            )
        )
        return kwargs

    # Ollama Cloud surfaces per-account *quota* exhaustion (not per-second
    # RPM) as APIConnectionError with one of these phrases in the body. RPM
    # rate-limits come through as RateLimitError and are handled separately.
    _OLLAMA_QUOTA_MARKERS = (
        "session usage limit",
        "upgrade for higher limits",
        "daily usage limit",
        "monthly usage limit",
    )
    # Daily-ish quotas don't reset in seconds — park the key long enough that
    # we don't keep retrying it within the same run.
    _OLLAMA_QUOTA_COOLDOWN_S = 6 * 3600

    @classmethod
    def _is_ollama_quota_error(cls, exc: Exception) -> bool:
        msg = str(exc).lower()
        return any(marker in msg for marker in cls._OLLAMA_QUOTA_MARKERS)

    def _completion(self, kwargs: dict) -> Any:
        """Dispatch to the key-rotating completion, transparently dropping an
        unsupported ``response_format`` (and disabling it for the session) when
        the endpoint rejects it — #149."""
        try:
            return self._completion_raw(kwargs)
        except litellm.BadRequestError as exc:
            if kwargs.get("response_format") and "response_format" in str(exc).lower():
                logger.warning(
                    "Endpoint rejected response_format; disabling it for this "
                    "session and retrying without it."
                )
                self._response_format_supported = False
                retry = dict(kwargs)
                retry.pop("response_format", None)
                return self._completion_raw(retry)
            raise

    def _completion_raw(self, kwargs: dict) -> Any:
        """Call ``litellm.completion``, rotating keys on 429/quota when a pool is active.

        Without a pool this is a pass-through and LiteLLM's own retry layer
        (``num_retries``, exponential backoff) handles transient errors.
        With a pool (Ollama Cloud or Gemini), LiteLLM retries are disabled in
        ``_build_completion_kwargs`` and we rotate to a fresh key after each
        ``RateLimitError`` (parked for ``Retry-After``, 60s fallback) or —
        Ollama only — per-account quota exhaustion surfaced as
        ``APIConnectionError`` (parked for several hours since quota resets
        don't happen in seconds). Other ``APIConnectionError``s are genuine
        network failures and propagate untouched.
        """
        if self._key_pool is None:
            return litellm.completion(**kwargs)

        max_attempts = max(len(self._key_pool), (self.num_retries or 0) + 1)
        last_err: Exception | None = None
        for _ in range(max_attempts):
            try:
                return litellm.completion(**kwargs)
            except litellm.RateLimitError as exc:
                key = kwargs.get("api_key")
                if key:
                    self._key_pool.cooldown(key, extract_retry_after(exc))
                last_err = exc
            except litellm.APIConnectionError as exc:
                if self.provider != "ollama" or not self._is_ollama_quota_error(exc):
                    raise
                key = kwargs.get("api_key")
                if key:
                    # cooldown() returns True only for the first parker — dedups
                    # warnings when concurrent workers both held the same key.
                    fresh = self._key_pool.cooldown(key, self._OLLAMA_QUOTA_COOLDOWN_S)
                    if fresh:
                        logger.warning(
                            "Ollama Cloud quota exhausted on key ending …%s; "
                            "parking for %ds and rotating.",
                            key[-4:],
                            int(self._OLLAMA_QUOTA_COOLDOWN_S),
                        )
                last_err = exc
            next_key = self._key_pool.acquire()
            if next_key:
                kwargs["api_key"] = next_key
        assert last_err is not None
        raise last_err

    def _complete_and_meter(
        self, messages: list[dict], temperature: float | None, max_tokens: int | None = None
    ) -> tuple[str, dict]:
        """Run one completion turn. Returns ``(raw_content, usage_delta)`` where
        ``usage_delta`` carries total/input/output/cached-input tokens and cost."""
        kwargs = self._build_completion_kwargs(messages, temperature=temperature)
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        response = self._completion(kwargs)
        if not response.choices:
            raise ValueError("LLM returned empty choices list")
        raw = response.choices[0].message.content or ""
        usage = getattr(response, "usage", None)
        delta = {
            "total_tokens": getattr(usage, "total_tokens", 0) or 0,
            "input_tokens": getattr(usage, "prompt_tokens", 0) or 0,
            "output_tokens": getattr(usage, "completion_tokens", 0) or 0,
            "cached_input_tokens": _extract_cached_input_tokens(usage),
            "cost_usd": 0.0,
        }
        try:
            delta["cost_usd"] = litellm.completion_cost(completion_response=response)
        except Exception:
            logger.debug("Could not compute completion cost", exc_info=True)
        return raw, delta

    def _complete_parse_retry(
        self, messages: list[dict], temperature: float | None
    ) -> tuple[str, dict, dict]:
        """Complete + parse; retry ONCE on a truncated/unparseable envelope before
        accepting the abstention (#149). A length truncation retries with a larger
        ``max_tokens``. Returns ``(raw, parsed, usage_delta)`` with usage summed
        across both attempts. Verdict-neutral on a healthy response (no retry)."""
        raw, delta = self._complete_and_meter(messages, temperature)
        parsed = self._parse_response(raw)
        if parsed.get("parse_failed"):
            retry_tokens = (
                min(self.max_tokens * 2, PROMPT_RETRY_MAX_TOKENS)
                if parsed.get("truncated")
                else None
            )
            logger.warning(
                "Verifier verdict envelope %s; retrying once%s.",
                "truncated" if parsed.get("truncated") else "unparseable",
                f" at max_tokens={retry_tokens}" if retry_tokens else "",
            )
            raw2, delta2 = self._complete_and_meter(messages, temperature, max_tokens=retry_tokens)
            for k in delta:
                delta[k] += delta2[k]
            parsed2 = self._parse_response(raw2)
            if not parsed2.get("parse_failed"):
                raw, parsed = raw2, parsed2
        return raw, parsed, delta

    def analyze(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
        context_provider: ContextProvider | None = None,
        max_iterations: int = 3,
        verbose: bool = False,
        log_file: Any | None = None,
        quiet: bool = False,
        force_decision: bool = True,
        prefetched_context: dict[str, str] | None = None,
        temperature: float | None = None,
        context_start_line: int = 1,
        decision_strategy: DecisionStrategy | None = None,
    ) -> Verdict:
        """
        Analyze a finding and return a verdict.

        Uses multi-turn conversation with context expansion (LLM mode).

        Args:
            finding: The static analysis finding to analyze
            context: Code context around the finding
            questions: Guided questions for the rule
            func_name: Name of the function containing the finding
            context_provider: Provider for additional context (multi-turn)
            max_iterations: Maximum conversation rounds
            verbose: Show detailed output
            log_file: Optional file to log conversations
            quiet: Suppress output
            force_decision: If True and final verdict is still Needs More Data,
                send a force-decision prompt asking the LLM to choose TP or FP.
                Defaults to True.
            prefetched_context: Pre-fetched context from additional_context hints.
                Appended to the initial prompt and marked as fulfilled.

        Returns:
            Verdict with the analysis result (includes confidence_score 0.0-1.0)
        """
        user_prompt = self.prompt_builder.build_user_prompt(finding, context, questions, func_name, context_start_line)

        # Append pre-fetched context to initial prompt
        if prefetched_context:
            prefetch_parts = []
            for req, code in prefetched_context.items():
                if "[No " not in code and "[Unknown" not in code:
                    prefetch_parts.append(f"### {req}\n```\n{code}\n```")
            if prefetch_parts:
                user_prompt += (
                    "\n\n## Pre-fetched Additional Context\n\n"
                    + "\n\n".join(prefetch_parts)
                )

        sys_prompt = self.prompt_builder.get_system_prompt(
            tool_name=finding.tool or "static analysis",
            lang=finding.lang,
        )
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
        ]

        # Print initial prompts in verbose mode
        if verbose:
            print("\n    === SYSTEM PROMPT ===")
            if len(sys_prompt) > 1000:
                print(f"    [System prompt: {len(sys_prompt)} chars, showing first 1000...]")
                print(f"    {sys_prompt[:1000]}...")
            else:
                print(f"    {sys_prompt}")
            print("    === END SYSTEM PROMPT ===\n")

        # Log initial prompt
        if log_file:
            log_file.write(f"## Finding: {finding.rule_id}\n\n")
            log_file.write(f"- **File**: `{finding.file}:{finding.start_line}`\n")
            log_file.write(f"- **Message**: {finding.message}\n")
            log_file.write(f"- **Function**: `{func_name}`\n\n")
            log_file.write(
                f"### System Prompt\n\n```\n{self.prompt_builder.system_prompt}\n```\n\n"
            )
            log_file.write(f"### User Prompt\n\n```\n{user_prompt}\n```\n\n")

        start_time = time.time()
        iterations = 0
        all_raw_responses: list[str] = []
        total_tokens_used: int = 0
        total_input_tokens: int = 0
        total_output_tokens: int = 0
        total_cached_input_tokens: int = 0
        total_cost_usd: float = 0.0
        fulfilled_context: set[str] = set()  # Track already-provided context requests
        # Mark pre-fetched context as already fulfilled
        if prefetched_context:
            for req, code in prefetched_context.items():
                if "[No " not in code and "[Unknown" not in code:
                    fulfilled_context.add(req)

        while iterations < max_iterations:
            iterations += 1

            if verbose:
                print(f"\n    [Iteration {iterations}/{max_iterations}] Sending request to LLM...")
                # Print the request being sent
                print("\n    === LLM REQUEST ===")
                last_user_msg = next(
                    (m["content"] for m in reversed(messages) if m["role"] == "user"), ""
                )
                # Show truncated version for readability
                if len(last_user_msg) > 2000:
                    print(f"    [User message: {len(last_user_msg)} chars, showing first 2000...]")
                    print(f"    {last_user_msg[:2000]}...")
                else:
                    print(f"    {last_user_msg}")
                print("    === END REQUEST ===\n")
            elif not quiet:
                print("    Calling LLM...", end="", flush=True)

            try:
                # #149: one turn, with a bounded retry on a truncated/unparseable
                # envelope so a length artifact can't silently become an abstention
                # that force-decision then launders into a verdict.
                raw_response, parsed, _delta = self._complete_parse_retry(
                    messages, temperature
                )
                all_raw_responses.append(raw_response)

                # Accumulate token usage (split + total) and cost.
                total_tokens_used += _delta["total_tokens"]
                total_input_tokens += _delta["input_tokens"]
                total_output_tokens += _delta["output_tokens"]
                total_cached_input_tokens += _delta["cached_input_tokens"]
                total_cost_usd += _delta["cost_usd"]

                if not verbose and not quiet:
                    print(f" done ({len(raw_response)} chars)")

                # Log response
                if log_file:
                    log_file.write(f"### LLM Response (Iteration {iterations})\n\n")
                    log_file.write(f"```json\n{raw_response}\n```\n\n")

                if verbose:
                    print(f"    === LLM RESPONSE ({len(raw_response)} chars) ===")
                    print(f"    {raw_response}")
                    print("    === END RESPONSE ===\n")

                verdict = parsed.get("verdict", "Needs More Data")
                context_needed = parsed.get("context_needed", [])

                if verbose:
                    print(
                        f"    Parsed: verdict={verdict}, confidence={parsed.get('confidence', 'Low')}"
                    )

                # Evidence-closure hook: when a decision strategy is supplied (the
                # policy path), it owns closure — retrieve / repair / finalize /
                # abstain — bypassing the legacy min-iterations, context-expansion
                # and force-decision control flow below.
                if decision_strategy is not None:
                    action = decision_strategy.evaluate(parsed, raw_response, iterations)
                    if isinstance(action, (Finalize, Abstain)):
                        v = action.verdict
                        v.raw_response = "\n---\n".join(all_raw_responses)
                        v.elapsed_seconds = time.time() - start_time
                        v.iterations = iterations
                        v.tokens_used = total_tokens_used
                        v.input_tokens = total_input_tokens
                        v.output_tokens = total_output_tokens
                        v.cached_input_tokens = total_cached_input_tokens
                        v.cost_usd = total_cost_usd
                        return v
                    follow_up = (
                        action.followup_prompt
                        if isinstance(action, Retrieve)
                        else action.repair_prompt
                    )
                    messages.append({"role": "assistant", "content": raw_response})
                    messages.append({"role": "user", "content": follow_up})
                    continue

                # min_iterations gate: for high-stakes rules (e.g., memory-safety CWEs)
                # the questions YAML can require multiple analysis rounds before allowing
                # a TP/FP verdict. Premature convergence is the documented failure mode
                # for CWE-416 etc. — see benchmarks/Conclusion.md.
                #
                # This gate fires regardless of whether a context_provider is
                # available — even when only "<unavailable>" can be served,
                # the second turn forces the LLM to re-examine its evidence
                # under explicit "context unavailable" framing, which the
                # 2026-05-15 benchmark showed materially flips wrong FPs.
                if (
                    iterations < questions.min_iterations
                    and verdict != "Needs More Data"
                ):
                    suggested = ", ".join(
                        f"'{t}:<name>'" for t in questions.additional_context[:3]
                    ) or "'caller:<func>', 'struct:<type>'"
                    if verbose:
                        print(
                            f"    [min_iterations={questions.min_iterations}] "
                            f"verdict={verdict} after iter {iterations} — "
                            f"requesting deeper analysis"
                        )
                    messages.append({"role": "assistant", "content": raw_response})
                    messages.append({
                        "role": "user",
                        "content": (
                            f"For this rule ({questions.rule_id}), at least "
                            f"{questions.min_iterations} rounds of analysis are required "
                            "before a TP/FP verdict. Premature convergence on this CWE "
                            "class has been a documented source of errors "
                            "(over-convicting on patterns visible in sibling functions, "
                            "dismissing real bugs without tracing cross-function lifetime).\n\n"
                            "DO NOT issue a final verdict yet. In your next response:\n"
                            f"1. Request additional context — try {suggested}.\n"
                            "2. Re-quote the EXACT flagged line and identify which "
                            "function it lives in.\n"
                            "3. Walk the relevant chain (e.g., alloc -> free -> use) "
                            "with concrete file:line references.\n\n"
                            "Set verdict to 'Needs More Data' in this turn and request "
                            "the context. Only after you have concrete evidence should "
                            "you commit to TP or FP."
                        ),
                    })
                    continue

                # Final verdict or no context expansion
                if verdict != "Needs More Data" or not context_needed or not context_provider:
                    # Force decision: if NMD and force_decision enabled, do one more turn
                    if verdict == "Needs More Data" and force_decision:
                        if verbose:
                            print("    [Force decision] Sending forced re-prompt...")
                        try:
                            messages.append({"role": "assistant", "content": raw_response})
                            (
                                parsed,
                                raw_response,
                                total_tokens_used,
                                total_cost_usd,
                                total_input_tokens,
                                total_output_tokens,
                                total_cached_input_tokens,
                            ) = self._force_decision_turn(
                                messages,
                                all_raw_responses,
                                total_tokens_used,
                                total_cost_usd,
                                total_input_tokens,
                                total_output_tokens,
                                total_cached_input_tokens,
                                temperature=temperature,
                            )
                            verdict = parsed.get("verdict", "False Positive")
                            iterations += 1
                        except Exception:
                            logger.debug("Force decision turn failed", exc_info=True)

                    elapsed = time.time() - start_time

                    if log_file:
                        self._log_final_verdict(log_file, parsed, iterations, elapsed)

                    return Verdict(
                        finding=finding,
                        verdict=verdict,
                        confidence=parsed.get("confidence", "Low"),
                        reasoning=parsed.get("reasoning", "Could not parse response"),
                        answers=parsed.get("answers", []),
                        raw_response="\n---\n".join(all_raw_responses),
                        model=self.model,
                        elapsed_seconds=elapsed,
                        context_needed=context_needed,
                        iterations=iterations,
                        tokens_used=total_tokens_used,
                        input_tokens=total_input_tokens,
                        output_tokens=total_output_tokens,
                        cached_input_tokens=total_cached_input_tokens,
                        cost_usd=total_cost_usd,
                        confidence_score=parsed.get("confidence_score", 0.3),
                        data_flow=parsed.get("data_flow", ""),
                    )

                # Deduplicate context requests against previously fulfilled ones
                new_requests = [r for r in context_needed if r not in fulfilled_context]
                if not new_requests:
                    if verbose:
                        print("    All requested context was already provided in previous turns.")
                    # Tell LLM that context was already provided
                    messages.append({"role": "assistant", "content": raw_response})
                    messages.append({
                        "role": "user",
                        "content": (
                            "All requested context was already provided in previous turns. "
                            "Please provide your verdict based on available information."
                        ),
                    })
                    continue

                if verbose:
                    print(f"    Fetching additional context: {new_requests}")

                additional = context_provider.get_additional_context(
                    repo_name=finding.repo_name,
                    lang=finding.lang,
                    context_requests=new_requests,
                )
                fulfilled_context.update(new_requests)

                if not additional:
                    elapsed = time.time() - start_time
                    return Verdict(
                        finding=finding,
                        verdict=verdict,
                        confidence=parsed.get("confidence", "Low"),
                        reasoning=parsed.get("reasoning", "")
                        + " [No additional context available]",
                        answers=parsed.get("answers", []),
                        raw_response="\n---\n".join(all_raw_responses),
                        model=self.model,
                        elapsed_seconds=elapsed,
                        context_needed=context_needed,
                        iterations=iterations,
                        tokens_used=total_tokens_used,
                        input_tokens=total_input_tokens,
                        output_tokens=total_output_tokens,
                        cached_input_tokens=total_cached_input_tokens,
                        cost_usd=total_cost_usd,
                        confidence_score=parsed.get("confidence_score", 0.3),
                    )

                # Build follow-up
                follow_up = self.prompt_builder.build_followup_prompt(additional)

                if log_file:
                    log_file.write(
                        f"### Follow-up Prompt (Iteration {iterations} -> {iterations + 1})\n\n"
                    )
                    log_file.write(f"```\n{follow_up}\n```\n\n")

                messages.append({"role": "assistant", "content": raw_response})
                messages.append({"role": "user", "content": follow_up})

            except Exception as e:
                elapsed = time.time() - start_time
                if verbose:
                    print(f"    ERROR: {e}")
                return Verdict(
                    finding=finding,
                    verdict="Error",
                    confidence="Low",
                    reasoning=f"LLM call failed: {e}",
                    answers=[],
                    raw_response=str(e),
                    model=self.model,
                    elapsed_seconds=elapsed,
                    iterations=iterations,
                    tokens_used=total_tokens_used,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    cached_input_tokens=total_cached_input_tokens,
                    cost_usd=total_cost_usd,
                    confidence_score=0.0,
                )

        # Max iterations reached — try force decision
        if force_decision:
            try:
                messages.append(
                    {
                        "role": "assistant",
                        "content": all_raw_responses[-1] if all_raw_responses else "",
                    }
                )
                (
                    parsed,
                    _,
                    total_tokens_used,
                    total_cost_usd,
                    total_input_tokens,
                    total_output_tokens,
                    total_cached_input_tokens,
                ) = self._force_decision_turn(
                    messages,
                    all_raw_responses,
                    total_tokens_used,
                    total_cost_usd,
                    total_input_tokens,
                    total_output_tokens,
                    total_cached_input_tokens,
                    temperature=temperature,
                )
                iterations += 1
                elapsed = time.time() - start_time
                return Verdict(
                    finding=finding,
                    verdict=parsed.get("verdict", "False Positive"),
                    confidence=parsed.get("confidence", "Low"),
                    reasoning=parsed.get("reasoning", "Forced decision after max iterations"),
                    answers=parsed.get("answers", []),
                    raw_response="\n---\n".join(all_raw_responses),
                    model=self.model,
                    elapsed_seconds=elapsed,
                    iterations=iterations,
                    tokens_used=total_tokens_used,
                    input_tokens=total_input_tokens,
                    output_tokens=total_output_tokens,
                    cached_input_tokens=total_cached_input_tokens,
                    cost_usd=total_cost_usd,
                    confidence_score=parsed.get("confidence_score", 0.3),
                )
            except Exception:
                logger.debug("Force decision after max iterations failed", exc_info=True)

        elapsed = time.time() - start_time
        return Verdict(
            finding=finding,
            verdict="Needs More Data",
            confidence="Low",
            reasoning=f"Max iterations ({max_iterations}) reached without final verdict",
            answers=[],
            raw_response="\n---\n".join(all_raw_responses),
            model=self.model,
            elapsed_seconds=elapsed,
            iterations=iterations,
            tokens_used=total_tokens_used,
            input_tokens=total_input_tokens,
            output_tokens=total_output_tokens,
            cached_input_tokens=total_cached_input_tokens,
            cost_usd=total_cost_usd,
            confidence_score=0.0,
        )

    def analyze_with_voting(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
        *,
        samples: int = 1,
        voting_temperature: float = 0.7,
        tie_break: str = "fp",
        context_provider: ContextProvider | None = None,
        max_iterations: int = 3,
        verbose: bool = False,
        log_file: Any | None = None,
        quiet: bool = False,
        force_decision: bool = True,
        prefetched_context: dict[str, str] | None = None,
        context_start_line: int = 1,
    ) -> Verdict:
        """Self-consistency (CISC-style) voting over N independent analyses.

        Runs ``analyze`` ``samples`` times at ``voting_temperature``, then
        returns a single Verdict reflecting confidence-weighted majority
        vote across runs. Tokens, costs, and elapsed time are summed.
        Iterations field is set to the maximum across runs. NMD votes
        weight zero — a verdict is required to win the vote.

        Args:
          samples: number of independent runs (>=1). With samples=1 this
              method is equivalent to ``analyze`` with the original
              temperature.
          voting_temperature: temperature used for each sampled run when
              ``samples > 1``. Ignored when ``samples == 1``.
          tie_break: ``"fp"`` (conservative — return False Positive) or
              ``"tp"``. Used when TP and FP receive equal vote weight.

        Returns:
          A single aggregated ``Verdict``. ``raw_response`` contains the
          concatenation of all sampled responses with ``=== SAMPLE k ===``
          dividers so reviewers can audit the vote.

        References:
          Wang et al. (2023) Self-Consistency Improves CoT Reasoning in
          Language Models; CISC (ACL 2025) Self-Consistency with
          Confidence for LLM-Based Code Review.
        """
        if samples < 1:
            raise ValueError(f"samples must be >= 1, got {samples}")
        if tie_break not in {"tp", "fp"}:
            raise ValueError(f"tie_break must be 'tp' or 'fp', got {tie_break!r}")

        if samples == 1:
            return self.analyze(
                finding=finding,
                context=context,
                questions=questions,
                func_name=func_name,
                context_provider=context_provider,
                max_iterations=max_iterations,
                verbose=verbose,
                log_file=log_file,
                quiet=quiet,
                force_decision=force_decision,
                prefetched_context=prefetched_context,
                context_start_line=context_start_line,
            )

        # Sample N runs at the elevated voting temperature. Threaded through
        # as a per-call kwarg so the client instance remains stateless w.r.t.
        # temperature, making concurrent callers safe.
        verdicts: list[Verdict] = []
        for k in range(samples):
            v = self.analyze(
                finding=finding,
                context=context,
                questions=questions,
                func_name=func_name,
                context_provider=context_provider,
                max_iterations=max_iterations,
                verbose=verbose,
                log_file=log_file,
                quiet=quiet,
                force_decision=force_decision,
                prefetched_context=prefetched_context,
                temperature=voting_temperature,
                context_start_line=context_start_line,
            )
            verdicts.append(v)

        return self._aggregate_votes(verdicts, tie_break=tie_break)

    @staticmethod
    def _aggregate_votes(verdicts: list[Verdict], tie_break: str = "fp") -> Verdict:
        """Confidence-weighted majority vote over a list of Verdicts."""
        if not verdicts:
            raise ValueError("Cannot aggregate empty verdict list")
        if len(verdicts) == 1:
            return verdicts[0]

        TP, FP, NMD = "True Positive", "False Positive", "Needs More Data"
        scores: dict[str, float] = {TP: 0.0, FP: 0.0}
        counts: dict[str, int] = {TP: 0, FP: 0, NMD: 0}
        for v in verdicts:
            counts[v.verdict] = counts.get(v.verdict, 0) + 1
            if v.verdict in scores:
                scores[v.verdict] += float(v.confidence_score or 0.0)
        # Pick winner. NMD votes do not contribute confidence weight — but a
        # sample set with NO True/False Positive votes at all must NOT collapse to
        # FP via the tie-break (the documented uncertainty-erasure defect). Decide
        # those degenerate cases honestly by count: all-NMD -> NMD, all-Error ->
        # Error. Only a genuine TP-vs-FP tie falls through to the tie-break.
        if counts.get(TP, 0) == 0 and counts.get(FP, 0) == 0:
            winner = NMD if counts.get(NMD, 0) > 0 else "Error"
        elif scores[TP] > scores[FP]:
            winner = TP
        elif scores[FP] > scores[TP]:
            winner = FP
        else:
            winner = TP if tie_break == "tp" else FP

        # Aggregate cost / latency / token / iteration accounting.
        total_tokens = sum(v.tokens_used for v in verdicts)
        total_input = sum(v.input_tokens for v in verdicts)
        total_output = sum(v.output_tokens for v in verdicts)
        total_cached_input = sum(v.cached_input_tokens for v in verdicts)
        total_cost = sum(v.cost_usd for v in verdicts)
        elapsed = sum(v.elapsed_seconds for v in verdicts)
        max_iters = max(v.iterations for v in verdicts)

        # Pick a representative (highest-confidence_score among winning votes)
        # to source reasoning, answers, data_flow, and context_needed.
        winners = [v for v in verdicts if v.verdict == winner]
        if winners:
            rep = max(winners, key=lambda v: float(v.confidence_score or 0.0))
        else:
            rep = max(verdicts, key=lambda v: float(v.confidence_score or 0.0))

        # Confidence label reflects vote agreement, not the rep's own label.
        n = len(verdicts)
        agree_frac = (counts.get(winner, 0) / n) if n else 0.0
        if agree_frac >= 0.8:
            agg_conf = "High"
            agg_score = 0.85
        elif agree_frac >= 0.6:
            agg_conf = "Medium"
            agg_score = 0.6
        else:
            agg_conf = "Low"
            agg_score = 0.3

        raw_concat = "\n\n=== SAMPLE DIVIDER ===\n\n".join(
            f"=== SAMPLE {i + 1}/{n} (verdict={v.verdict}, conf={v.confidence_score}) ===\n{v.raw_response}"
            for i, v in enumerate(verdicts)
        )

        reasoning = (
            f"Self-consistency vote over {n} samples: "
            f"TP={counts.get(TP, 0)} (score {scores[TP]:.2f}), "
            f"FP={counts.get(FP, 0)} (score {scores[FP]:.2f}), "
            f"NMD={counts.get(NMD, 0)}. "
            f"Winner: {winner} (agreement={agree_frac:.0%}). "
            f"Representative reasoning: {rep.reasoning}"
        )

        return Verdict(
            finding=rep.finding,
            verdict=winner,
            confidence=agg_conf,
            reasoning=reasoning,
            answers=rep.answers,
            raw_response=raw_concat,
            model=rep.model,
            elapsed_seconds=elapsed,
            context_needed=rep.context_needed,
            iterations=max_iters,
            tokens_used=total_tokens,
            input_tokens=total_input,
            output_tokens=total_output,
            cached_input_tokens=total_cached_input,
            cost_usd=total_cost,
            confidence_score=agg_score,
            data_flow=rep.data_flow,
        )

    # Challenges a single-turn high-confidence FP into re-enumerating the defense
    # it claimed. Provenance: the 2026-05-15 benchmark measured such one-iteration
    # high-confidence FPs wrong ~80% of the time on memory-safety / access-control
    # CWEs; the prompt keeps that method (enumerate the defense) but states the
    # tendency qualitatively rather than asserting a dated point-in-time figure.
    _SECOND_OPINION_PROMPT = (
        "Your previous verdict was 'False Positive' with high confidence, "
        "reached in a single turn without requesting additional context.\n\n"
        "A single-turn high-confidence FP on memory-safety and access-control "
        "CWEs is frequently wrong — usually because the LLM assumed a defense "
        "exists outside the snippet, inverted a missing-check finding "
        "(saw checks and concluded 'no bug'), or treated an empty/init "
        "function as inherently safe.\n\n"
        "Verify your verdict by enumerating, with line references:\n"
        "  (a) The SPECIFIC defense you observed (exact line, exact mechanism).\n"
        "  (b) Why that defense covers ALL reachable paths to the sink.\n"
        "  (c) Why the SAST tool flagged this finding — what does the rule "
        "      look for, and is the defense you cited actually checking that?\n\n"
        "If you cannot enumerate (a), (b), and (c) with concrete line references "
        "from the provided code, change your verdict to 'True Positive' "
        "(Low confidence) or 'Needs More Data'. Respond in the same strict JSON "
        "format."
    )

    # Counterpart to _SECOND_OPINION_PROMPT, but steering an over-eager TRUE
    # POSITIVE on a correctness / type-hygiene rule (integer-overflow,
    # multiplication-cast-to-wider, sign-conversion, truncation) back toward FP/
    # NMD when the overflow is not actually reachable. These rules fire on a
    # PATTERN, not a proven bug, and the model tends to confirm them by citing
    # the flagged line and the rule's severity rather than proving the operands
    # can overflow. See output/c/libjpeg-turbo/.../summary_*_20260611_215144.json
    # (17/20 TP, mostly bounded loop counters and test fixtures).
    _TP_CHALLENGE_PROMPT = (
        "Your previous verdict was 'True Positive' with high confidence, reached "
        "in a single turn. The flagged rule is a CORRECTNESS / TYPE-HYGIENE rule: "
        "it matches a code PATTERN (an arithmetic operation in a narrow type later "
        "widened) wherever that pattern appears — it does NOT prove the operation "
        "actually overflows or is reachable with attacker input.\n\n"
        "Re-verify by answering, with line references:\n"
        "  (a) The exact TYPE of each operand and the intermediate result type. "
        "What is the maximum value that intermediate type holds?\n"
        "  (b) Where do the operand VALUES come from — compile-time constants, "
        "fixed-bound loop counters, sizeof, or attacker-controlled input "
        "(file header, network, argv)? Quote the bound.\n"
        "  (c) Given those bounds, CAN the product actually exceed the intermediate "
        "type's max? Show the arithmetic (max_a * max_b vs TYPE_MAX).\n"
        "  (d) Is the widened result used dangerously (allocation / index / length / "
        "memcpy size), or merely stored / used in bounded arithmetic?\n"
        "  (e) Is this file a test, benchmark, fuzz harness, or vendored third-party "
        "copy where the operands are fixed fixtures rather than attacker input?\n\n"
        "If you CANNOT show, with concrete numbers, that the operands can reach "
        "values which overflow the intermediate type AND flow to a dangerous sink, "
        "change your verdict to 'False Positive' (the pattern is present but the "
        "overflow is not reachable) or 'Needs More Data'. Respond in the same strict "
        "JSON format."
    )

    _SIBLING_CONSISTENCY_CHALLENGE_PROMPT = (
        "Your previous verdict was 'False Positive'. However, this SAME rule "
        "flagged the SAME construct at OTHER lines of THIS file, and that "
        "identical construct — the same untrusted input reaching the same kind "
        "of sink — was confirmed 'True Positive' by this same analysis (see the "
        "sibling verdicts noted in the pre-fetched context). A confirmed sibling "
        "establishes that the attacker-reachable consequence is REAL in this file, "
        "which is exactly the concrete consequence a True Positive requires.\n\n"
        "Re-verify by answering, with line references:\n"
        "  (a) Is THIS line the same construct with the same untrusted input as "
        "the confirmed sibling(s), or does it differ materially?\n"
        "  (b) Does THIS line add REAL defense the sibling lacked — validation, "
        "sanitization, an allowlist, canonicalization, or a constant / "
        "non-attacker-controlled input — as opposed to only a different constant "
        "literal (e.g. a different filename suffix or path segment)?\n"
        "  (c) Is THIS sink genuinely unreachable where the sibling's is "
        "reachable?\n\n"
        "If THIS line is the same untrusted-input construct as a confirmed "
        "sibling and adds no real defense, change your verdict to 'True "
        "Positive' — the consequence proven at the sibling applies here too. "
        "Keep 'False Positive' ONLY if you can cite a concrete material "
        "difference at THIS line. Respond in the same strict JSON format."
    )

    @staticmethod
    def _second_opinion_marker(challenge_prompt: str | None) -> str:
        """Reasoning tag naming which second-opinion challenge produced a verdict.

        Distinguishes the sibling-consistency challenge (#122) from the
        correctness-rule TP challenge and the default 1-iter-FP re-prompt, so the
        reasoning text does not mislabel every non-None challenge as the latter.
        """
        if challenge_prompt is LLMClient._SIBLING_CONSISTENCY_CHALLENGE_PROMPT:
            return " [second-opinion pass: sibling-consistency challenge]"
        if challenge_prompt is not None:
            return " [second-opinion pass: TP challenge on correctness rule]"
        return " [second-opinion pass after 1-iter high-conf FP]"

    def request_second_opinion(
        self,
        finding: Finding,
        context: str,
        questions: GuidedQuestions,
        func_name: str,
        previous_verdict: Verdict,
        temperature: float | None = None,
        verbose: bool = False,
        quiet: bool = True,
        log_file: Any | None = None,
        prefetched_context: dict[str, str] | None = None,
        challenge_prompt: str | None = None,
        context_start_line: int = 1,
    ) -> Verdict:
        """One-shot re-prompt for a previously committed verdict.

        Used by VerificationEngine to challenge single-turn high-confidence
        FP verdicts (the 2026-05-15 benchmark's dominant failure mode).
        ``challenge_prompt`` overrides the default FP-oriented re-prompt; pass
        ``_TP_CHALLENGE_PROMPT`` to challenge an over-eager TP on a correctness
        rule instead. When omitted, behaviour is byte-for-byte unchanged.
        Returns a fresh Verdict whose iteration/token counts are added to the
        previous verdict by the caller. The previous verdict's reasoning is
        included as assistant context so the model can audit its own logic.
        ``prefetched_context`` MUST be passed through so the challenge turn sees
        the same sink/callee bodies as the original analysis — otherwise it
        re-decides on a thinner prompt and can overturn a correct verdict.
        """
        user_prompt = self.prompt_builder.build_user_prompt(
            finding, context, questions, func_name, context_start_line
        )
        if prefetched_context:
            prefetch_parts = [
                f"### {req}\n```\n{code}\n```"
                for req, code in prefetched_context.items()
                if "[No " not in code and "[Unknown" not in code
            ]
            if prefetch_parts:
                user_prompt += (
                    "\n\n## Pre-fetched Additional Context\n\n"
                    + "\n\n".join(prefetch_parts)
                )
        sys_prompt = self.prompt_builder.get_system_prompt(
            tool_name=finding.tool or "static analysis",
            lang=finding.lang,
        )
        messages = [
            {"role": "system", "content": sys_prompt},
            {"role": "user", "content": user_prompt},
            {
                "role": "assistant",
                "content": (
                    previous_verdict.raw_response
                    or json.dumps({
                        "verdict": previous_verdict.verdict,
                        "confidence": previous_verdict.confidence,
                        "reasoning": previous_verdict.reasoning,
                    })
                ),
            },
            {"role": "user", "content": challenge_prompt or self._SECOND_OPINION_PROMPT},
        ]
        start_time = time.time()
        try:
            kwargs = self._build_completion_kwargs(messages, temperature=temperature)
            response = self._completion(kwargs)
            raw = (
                response.choices[0].message.content or ""
                if response.choices
                else ""
            )
        except Exception as e:
            logger.debug("Second-opinion call failed", exc_info=True)
            return Verdict(
                finding=finding,
                verdict=previous_verdict.verdict,
                confidence=previous_verdict.confidence,
                reasoning=previous_verdict.reasoning + f" [second-opinion failed: {e}]",
                answers=previous_verdict.answers,
                raw_response=previous_verdict.raw_response,
                model=self.model,
                elapsed_seconds=previous_verdict.elapsed_seconds,
                iterations=previous_verdict.iterations,
                tokens_used=previous_verdict.tokens_used,
                input_tokens=previous_verdict.input_tokens,
                output_tokens=previous_verdict.output_tokens,
                cached_input_tokens=previous_verdict.cached_input_tokens,
                cost_usd=previous_verdict.cost_usd,
                confidence_score=previous_verdict.confidence_score,
            )

        _usage = getattr(response, "usage", None)
        delta_tokens = getattr(_usage, "total_tokens", 0) or 0
        delta_in = getattr(_usage, "prompt_tokens", 0) or 0
        delta_out = getattr(_usage, "completion_tokens", 0) or 0
        delta_cached = _extract_cached_input_tokens(_usage)
        try:
            delta_cost = litellm.completion_cost(completion_response=response)
        except Exception:
            delta_cost = 0.0

        parsed = self._parse_response(raw)
        elapsed = time.time() - start_time

        if log_file:
            log_file.write("### Second Opinion\n\n")
            log_file.write(f"```json\n{raw}\n```\n\n")

        marker = self._second_opinion_marker(challenge_prompt)
        return Verdict(
            finding=finding,
            verdict=parsed.get("verdict", previous_verdict.verdict),
            confidence=parsed.get("confidence", "Low"),
            reasoning=parsed.get("reasoning", "") + marker,
            answers=parsed.get("answers", previous_verdict.answers),
            raw_response=(
                previous_verdict.raw_response
                + "\n--- SECOND OPINION ---\n"
                + raw
            ),
            model=self.model,
            elapsed_seconds=previous_verdict.elapsed_seconds + elapsed,
            context_needed=parsed.get("context_needed", []),
            iterations=previous_verdict.iterations + 1,
            tokens_used=previous_verdict.tokens_used + delta_tokens,
            input_tokens=previous_verdict.input_tokens + delta_in,
            output_tokens=previous_verdict.output_tokens + delta_out,
            cached_input_tokens=previous_verdict.cached_input_tokens + delta_cached,
            cost_usd=previous_verdict.cost_usd + delta_cost,
            confidence_score=parsed.get("confidence_score", 0.3),
        )

    _FORCE_DECISION_PROMPT = (
        "This is your final analysis attempt. Based on ALL the evidence you have seen so far, "
        "which direction does the balance of evidence lean? You MUST choose True Positive or "
        "False Positive. Low confidence is acceptable. Needs More Data is NOT an acceptable "
        "final response.\n\n"
        "GUIDELINE (decide by CONSEQUENCE at the flagged sink, not by absence of a defense): "
        "choose True Positive only when you can name a concrete, attacker-reachable consequence "
        "at the flagged sink — a real exploit path with real impact (code/command execution, "
        "data disclosure, memory corruption, auth bypass). The mere ABSENCE of a visible "
        "sanitizer, guard, or framework protection is NOT sufficient for True Positive. Choose "
        "False Positive when a specific defense makes the path safe, OR when the flagged construct "
        "carries no real security consequence even though it matches the rule — e.g. a permissive "
        "header with nothing sensitive behind it, a loose comparison with no secret operand, a "
        "value that is only logged or printed, or an operator/CLI-controlled source with no trust "
        "boundary.\n\n"
        "EXCEPTION for correctness / type-hygiene rules (integer-overflow, "
        "multiplication-cast-to-wider, sign-conversion, truncation): the rule fires on a "
        "code PATTERN, not a proven bug. Here, choose True Positive ONLY if the operands can "
        "realistically reach values that overflow the intermediate type AND the result is used "
        "dangerously (allocation/index/length). If the operands are constants, fixed-bound loop "
        "counters, or otherwise provably below the overflow threshold — or the code is a "
        "test/benchmark fixture not driven by attacker input — choose False Positive.\n\n"
        "Provide your verdict in the same JSON format with reasoning."
    )

    def _force_decision_turn(
        self,
        messages: list[dict],
        all_raw_responses: list[str],
        total_tokens_used: int,
        total_cost_usd: float,
        total_input_tokens: int = 0,
        total_output_tokens: int = 0,
        total_cached_input_tokens: int = 0,
        temperature: float | None = None,
    ) -> tuple[dict[str, Any], str, int, float, int, int, int]:
        """Execute one forced-decision LLM turn.

        Returns (parsed, raw, total_tokens, total_cost, total_input, total_output, total_cached_input).
        """
        messages.append({"role": "user", "content": self._FORCE_DECISION_PROMPT})
        kwargs = self._build_completion_kwargs(messages, temperature=temperature)
        response = self._completion(kwargs)
        raw = response.choices[0].message.content or "" if response.choices else ""
        all_raw_responses.append(raw)
        _usage = getattr(response, "usage", None)
        _tokens = getattr(_usage, "total_tokens", 0) or 0
        _in = getattr(_usage, "prompt_tokens", 0) or 0
        _out = getattr(_usage, "completion_tokens", 0) or 0
        _cached_in = _extract_cached_input_tokens(_usage)
        total_tokens_used += _tokens
        total_input_tokens += _in
        total_output_tokens += _out
        total_cached_input_tokens += _cached_in
        try:
            total_cost_usd += litellm.completion_cost(completion_response=response)
        except Exception:
            logger.debug("Could not compute completion cost for force decision", exc_info=True)
        parsed = self._parse_response(raw)
        # The force-decision prompt already asked the model to commit to TP or
        # FP. Respect whatever it returns: a committed verdict, or — if it still
        # answers Needs More Data (or the response was unparseable) — the
        # abstention. We deliberately do NOT keyword-count the reasoning into a
        # verdict: promoting NMD to TP on taint vocabulary ("no validation",
        # "unsafe") systematically over-confirms findings the model could not
        # actually decide (#119).
        return (
            parsed,
            raw,
            total_tokens_used,
            total_cost_usd,
            total_input_tokens,
            total_output_tokens,
            total_cached_input_tokens,
        )

    _CONFIDENCE_SCORE_MAP = {"high": 0.85, "medium": 0.6, "low": 0.3}
    # Variants outside the {High, Medium, Low} vocabulary that we silently
    # remap. The LLM has historically emitted "Very High" / "VeryHigh" /
    # "Highly Confident" despite the prompt schema; rather than rejecting
    # them (which would lose signal), we collapse them to the nearest valid
    # bucket so calibration and CISC voting remain meaningful.
    _CONFIDENCE_ALIASES = {
        "veryhigh": "High",
        "very high": "High",
        "highly confident": "High",
        "extremely high": "High",
        "certain": "High",
        "high confidence": "High",
        "medium-high": "High",
        "mediumhigh": "High",
        "moderate": "Medium",
        "medium-low": "Low",
        "mediumlow": "Low",
        "very low": "Low",
        "verylow": "Low",
        "uncertain": "Low",
    }
    _VALID_CONFIDENCE = {"High", "Medium", "Low"}

    @classmethod
    def _normalize_confidence_label(cls, raw: Any) -> str:
        """Map any incoming confidence label to {High, Medium, Low}."""
        if not isinstance(raw, str):
            return "Low"
        key = raw.strip().casefold()
        if key in cls._CONFIDENCE_SCORE_MAP:
            return key.capitalize()
        if key in cls._CONFIDENCE_ALIASES:
            return cls._CONFIDENCE_ALIASES[key]
        return "Low"

    @classmethod
    def _ensure_confidence_score(cls, parsed: dict[str, Any]) -> dict[str, Any]:
        """Normalize confidence label and ensure a numeric confidence_score."""
        parsed["confidence"] = cls._normalize_confidence_label(parsed.get("confidence"))
        if not isinstance(parsed.get("confidence_score"), (int, float)):
            parsed["confidence_score"] = cls._CONFIDENCE_SCORE_MAP[
                parsed["confidence"].casefold()
            ]
        return parsed

    def _parse_response(self, raw: str) -> dict[str, Any]:
        """Parse JSON from LLM response."""
        # Try to extract JSON from markdown code block
        json_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", raw, re.DOTALL)
        if json_match:
            try:
                parsed = json.loads(json_match.group(1))
                if isinstance(parsed, dict):
                    return self._ensure_confidence_score(parsed)
            except json.JSONDecodeError:
                pass

        # Try direct JSON parse
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return self._ensure_confidence_score(parsed)
        except json.JSONDecodeError:
            pass

        # Try to find JSON object in response
        brace_match = re.search(r"\{.*\}", raw, re.DOTALL)
        if brace_match:
            try:
                parsed = json.loads(brace_match.group())
                if isinstance(parsed, dict):
                    return self._ensure_confidence_score(parsed)
            except json.JSONDecodeError:
                pass

        # Manual extraction as fallback. JSON parsing failed, so we cannot
        # trust the LLM's verdict label — force "Needs More Data" with no
        # confidence score so the downstream evaluator can count parse
        # failures as a distinct mode rather than as Low-confidence FP
        # (which previously polluted the Low bucket and broke calibration).
        # Detect a *truncated* response (more '{' than '}') so the telemetry
        # can attribute it correctly — this was the smoking gun for the
        # diversevul CWE-264 misses in 2026-05-15.
        open_braces = raw.count("{")
        close_braces = raw.count("}")
        truncated = open_braces > close_braces and open_braces > 0
        result: dict[str, Any] = {
            "answers": [],
            "verdict": "Needs More Data",
            "confidence": "Low",
            "reasoning": raw[:500],
            "parse_failed": True,
            "truncated": truncated,
            "confidence_score": 0.0,
        }
        return result

    def _log_final_verdict(
        self,
        log_file: Any,
        parsed: dict,
        iterations: int,
        elapsed: float,
    ) -> None:
        """Log final verdict to file."""
        log_file.write("### Final Verdict\n\n")
        log_file.write(f"- **Verdict**: {parsed.get('verdict', 'Unknown')}\n")
        log_file.write(f"- **Confidence**: {parsed.get('confidence', 'Low')}\n")
        log_file.write(f"- **Iterations**: {iterations}\n")
        log_file.write(f"- **Time**: {elapsed:.2f}s\n")
        log_file.write(f"- **Reasoning**: {parsed.get('reasoning', 'N/A')}\n\n")
        if parsed.get("answers"):
            log_file.write("**Answers:**\n")
            for ai, ans in enumerate(parsed.get("answers", []), 1):
                log_file.write(f"{ai}. {ans}\n")
            log_file.write("\n")
        log_file.write("---\n\n")
