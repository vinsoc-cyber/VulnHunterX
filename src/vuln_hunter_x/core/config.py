# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Configuration management for CodeQL + LLM verification."""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field, fields, replace
from pathlib import Path
from typing import Any

import yaml

from vuln_hunter_x.core.constants import (
    DEFAULT_LLM_MAX_TOKENS,
    DEFAULT_LLM_MODEL,
    DEFAULT_LLM_PROVIDER,
    DEFAULT_LLM_TEMPERATURE,
    DEFAULT_MAX_FIX_ITERATIONS,
    DEFAULT_MAX_ITERATIONS,
    DEFAULT_OLLAMA_BASE_URL,
)


def _load_ollama_api_keys() -> list[str]:
    """Parse OLLAMA_API_KEYS (comma-separated) as the Ollama Cloud bearer pool.

    Returns an empty list when unset. ``LLMClient`` only treats these as
    Ollama Cloud bearers when the configured endpoint resolves to cloud
    (``OLLAMA_API_BASE`` contains ``ollama.com`` or the model carries a
    ``:cloud`` / ``-cloud`` tag).
    """
    raw = os.environ.get("OLLAMA_API_KEYS", "")
    return [k.strip() for k in raw.split(",") if k.strip()]


@dataclass
class LLMConfig:
    """LLM provider configuration."""

    provider: str = DEFAULT_LLM_PROVIDER
    model: str = DEFAULT_LLM_MODEL
    temperature: float = DEFAULT_LLM_TEMPERATURE
    max_tokens: int = DEFAULT_LLM_MAX_TOKENS
    ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL
    num_retries: int = 1
    # Per-request LLM timeout (seconds) forwarded to litellm.completion so a
    # stuck call is bounded instead of hanging the whole run (#127). litellm
    # retries a Timeout up to num_retries times, so the worst-case wall-clock
    # per call-site is roughly request_timeout * (num_retries + 1).
    request_timeout: float = 180.0
    # Ollama Cloud key pool. When two or more keys are configured (via
    # OLLAMA_API_KEYS=k1,k2,k3) LLMClient round-robins across them and parks
    # any key that returns 429. A single key is used directly without rotation.
    ollama_api_keys: list[str] = field(default_factory=list)

    @property
    def is_openai(self) -> bool:
        return self.provider == "openai"

    @property
    def is_ollama(self) -> bool:
        return self.provider == "ollama"

    @property
    def is_anthropic(self) -> bool:
        return self.provider == "anthropic"


@dataclass
class VerificationConfig:
    """Verification configuration (LLM multi-turn only)."""

    max_iterations: int = DEFAULT_MAX_ITERATIONS
    force_decision: bool = True
    # Self-consistency voting (CISC, ACL 2025): when > 1, run N independent
    # analyses at ``self_consistency_temperature`` and take confidence-
    # weighted majority vote. ``self_consistency_tie_break`` is "fp" (the
    # safer default) or "tp".
    self_consistency_samples: int = 1
    self_consistency_temperature: float = 0.7
    self_consistency_tie_break: str = "fp"
    # Number of findings to verify concurrently (ThreadPoolExecutor workers).
    # 1 disables parallelism. Override per-call with VerificationEngine(jobs=...)
    # or the `verify -j N` CLI flag.
    jobs: int = 4


@dataclass
class FuzzConfig:
    """Fuzz pipeline configuration (Stages 5-8, C/C++ only)."""

    max_fix_iterations: int = DEFAULT_MAX_FIX_ITERATIONS
    extra_include_dirs: list[str] = field(default_factory=list)
    extra_lib_dirs: list[str] = field(default_factory=list)
    extra_link_libs: list[str] = field(default_factory=list)
    extra_cflags: list[str] = field(default_factory=list)
    extra_ldflags: list[str] = field(default_factory=list)


@dataclass
class RepoPaths:
    """Paths for a single repo under output/<lang>/<repo_name>/."""

    root: Path
    database: Path
    sarif_file: Path
    context: Path
    verification_results: Path
    sanitized_build: Path
    fuzz_targets: Path
    fuzz_results: Path


@dataclass
class PathsConfig:
    """Path configuration for project directories."""

    repos_dir: Path = field(default_factory=lambda: Path("repos"))
    output_dir: Path = field(default_factory=lambda: Path("output"))
    prompts_dir: Path = field(default_factory=lambda: Path("config/prompts"))
    queries_dir: Path = field(default_factory=lambda: Path("config/queries"))

    def resolve(self, base_path: Path) -> PathsConfig:
        """Resolve all paths relative to a base path."""
        return PathsConfig(
            repos_dir=base_path / self.repos_dir,
            output_dir=base_path / self.output_dir,
            prompts_dir=base_path / self.prompts_dir,
            queries_dir=base_path / self.queries_dir,
        )

    def repo_paths(self, lang: str, repo_name: str) -> RepoPaths:
        """Return paths for a single repo under output/<lang>/<repo_name>/."""
        root = self.output_dir / lang / repo_name
        return RepoPaths(
            root=root,
            database=root / "database",
            sarif_file=root / f"{repo_name}.sarif",
            context=root / "context",
            verification_results=root / "verification_results",
            sanitized_build=root / "sanitized_build",
            fuzz_targets=root / "fuzz_targets",
            fuzz_results=root / "fuzz_results",
        )


@dataclass
class OutputConfig:
    """Output and logging configuration."""

    verbosity: str = "normal"  # quiet, normal, verbose
    log_file: Path | None = None

    @property
    def is_quiet(self) -> bool:
        return self.verbosity == "quiet"

    @property
    def is_verbose(self) -> bool:
        return self.verbosity == "verbose"


@dataclass
class Config:
    """Main configuration for the CodeQL + LLM verification framework."""

    llm: LLMConfig = field(default_factory=LLMConfig)
    verification: VerificationConfig = field(default_factory=VerificationConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    fuzz: FuzzConfig = field(default_factory=FuzzConfig)

    # Processing limits
    limit: int = 0
    languages: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)

    # CodeQL settings
    codeql_path: str = "codeql"

    @classmethod
    def from_dict(cls, data: dict[str, Any], base_path: Path | None = None) -> Config:
        """Create config from dictionary."""
        # Ollama URL comes from environment only (not from YAML config)
        ollama_url = os.environ.get("OLLAMA_API_BASE", DEFAULT_OLLAMA_BASE_URL)

        llm = LLMConfig(
            provider=data.get("provider", DEFAULT_LLM_PROVIDER),
            model=data.get("model", DEFAULT_LLM_MODEL),
            temperature=data.get("temperature", DEFAULT_LLM_TEMPERATURE),
            max_tokens=data.get("max_tokens", DEFAULT_LLM_MAX_TOKENS),
            ollama_base_url=ollama_url,
            num_retries=int(data.get("num_retries", 1)),
            request_timeout=float(data.get("request_timeout", 180.0)),
            ollama_api_keys=_load_ollama_api_keys(),
        )

        verification = VerificationConfig(
            max_iterations=data.get("max_iterations", DEFAULT_MAX_ITERATIONS),
            force_decision=data.get("force_decision", True),
            self_consistency_samples=int(data.get("self_consistency_samples", 1)),
            self_consistency_temperature=float(
                data.get("self_consistency_temperature", 0.7)
            ),
            self_consistency_tie_break=str(
                data.get("self_consistency_tie_break", "fp")
            ),
            jobs=int(data.get("jobs", 4)),
        )

        # Paths: support both top-level keys and paths.* for backward compatibility
        def _path(key: str, default: str) -> Path:
            p = (data.get("paths") or {}).get(key) or data.get(key)
            return Path(p if p is not None else default)

        paths = PathsConfig(
            repos_dir=_path("repos_dir", "repos"),
            output_dir=_path("output_dir", "output"),
            prompts_dir=_path("prompts_dir", "config/prompts"),
            queries_dir=_path("queries_dir", "config/queries"),
        )

        if base_path:
            paths = paths.resolve(base_path)

        output = OutputConfig(
            verbosity=data.get("verbosity", "normal"),
            log_file=Path(data["log_file"]) if data.get("log_file") else None,
        )

        fuzz_data = data.get("fuzz") or {}
        fuzz = FuzzConfig(
            max_fix_iterations=fuzz_data.get("max_fix_iterations", DEFAULT_MAX_FIX_ITERATIONS),
            extra_include_dirs=fuzz_data.get("extra_include_dirs") or [],
            extra_lib_dirs=fuzz_data.get("extra_lib_dirs") or [],
            extra_link_libs=fuzz_data.get("extra_link_libs") or [],
            extra_cflags=fuzz_data.get("extra_cflags") or [],
            extra_ldflags=fuzz_data.get("extra_ldflags") or [],
        )

        return cls(
            llm=llm,
            verification=verification,
            paths=paths,
            output=output,
            fuzz=fuzz,
            limit=data.get("limit", 0),
            languages=data.get("languages", []),
            repositories=data.get("repositories", []),
            codeql_path=data.get("codeql_path", "codeql"),
        )

    @classmethod
    def from_file(cls, config_path: Path, base_path: Path | None = None) -> Config:
        """Load config from YAML file."""
        if not config_path.is_file():
            return cls()

        with open(config_path) as f:
            data = yaml.safe_load(f) or {}

        if base_path is None:
            base_path = config_path.parent.parent  # Assume config is in config/

        return cls.from_dict(data, base_path)

    @classmethod
    def from_env(cls, base_path: Path | None = None) -> Config:
        """Create config from environment variables only."""
        data = {
            "codeql_path": os.environ.get("CODEQL_PATH", "codeql"),
            # Note: ollama_base_url is read in from_dict via OLLAMA_API_BASE
        }
        return cls.from_dict(data, base_path)

    def merge_with_args(self, **kwargs) -> Config:
        """Merge config with command-line arguments.

        Copy every field of each sub-config, overlaying only the overrides
        actually passed. ``kwargs`` is a flat dict mixing keys for all
        sub-configs, so each ``replace`` is filtered to that sub-config's own
        field names — a blind ``replace(sub, **kwargs)`` raises TypeError on a
        foreign key, and hand-listing fields silently drops any not listed (the
        regression this replaced, #132). Field names don't currently collide
        across sub-configs; route by explicit key lists if that ever changes.
        """

        def _own(sub) -> dict[str, Any]:
            names = {f.name for f in fields(sub)}
            return {k: v for k, v in kwargs.items() if k in names}

        return Config(
            llm=replace(self.llm, **_own(self.llm)),
            verification=replace(self.verification, **_own(self.verification)),
            paths=self.paths,
            output=replace(self.output, **_own(self.output)),
            fuzz=replace(self.fuzz, **_own(self.fuzz)),
            limit=kwargs.get("limit", self.limit),
            languages=kwargs.get("languages", self.languages),
            repositories=kwargs.get("repositories", self.repositories),
            codeql_path=kwargs.get("codeql_path", self.codeql_path),
        )


def load_config(
    config_path: Path | None = None,
    base_path: Path | None = None,
) -> Config:
    """
    Load configuration from file and environment.

    Priority (highest to lowest):
    1. Environment variables (secrets + environment-specific)
    2. Config file (application settings)
    3. Defaults

    Environment variables:
    - OPENAI_API_KEY / ANTHROPIC_API_KEY / DEEPSEEK_API_KEY: provider keys (secrets)
    - GEMINI_API_KEY: Gemini (AI Studio) key; GOOGLE_API_KEY accepted as fallback
    - LLM_PROVIDER: LLM provider (openai, ollama, anthropic, deepseek, or gemini)
    - LLM_MODEL: LLM model name
    - OLLAMA_API_BASE: Ollama server URL (environment-specific)
    - CODEQL_PATH: CodeQL CLI path (environment-specific)
    - MAX_FIX_ITERATIONS: Max LLM fix attempts for fuzz harnesses
    """
    # Start with defaults
    config = Config()

    # Load from file if provided
    if config_path and config_path.is_file():
        config = Config.from_file(config_path, base_path)

    # Override with environment variables (environment-specific settings)
    env_codeql = os.environ.get("CODEQL_PATH")
    env_ollama = os.environ.get("OLLAMA_API_BASE")
    env_provider = os.environ.get("LLM_PROVIDER")
    env_model = os.environ.get("LLM_MODEL")

    if env_codeql:
        config.codeql_path = env_codeql
    if env_ollama:
        config.llm.ollama_base_url = env_ollama
    if env_provider:
        config.llm.provider = env_provider
    if env_model:
        config.llm.model = env_model

    # Fuzz environment overrides
    env_max_fix = os.environ.get("MAX_FIX_ITERATIONS")
    if env_max_fix:
        with contextlib.suppress(ValueError):
            config.fuzz.max_fix_iterations = int(env_max_fix)

    return config
