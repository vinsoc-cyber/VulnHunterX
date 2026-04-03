"""Configuration management for CodeQL + LLM verification."""

from __future__ import annotations

import contextlib
import os
from dataclasses import dataclass, field
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


@dataclass
class LLMConfig:
    """LLM provider configuration."""

    provider: str = DEFAULT_LLM_PROVIDER
    model: str = DEFAULT_LLM_MODEL
    temperature: float = DEFAULT_LLM_TEMPERATURE
    max_tokens: int = DEFAULT_LLM_MAX_TOKENS
    ollama_base_url: str = DEFAULT_OLLAMA_BASE_URL

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
        )

        verification = VerificationConfig(
            max_iterations=data.get("max_iterations", DEFAULT_MAX_ITERATIONS),
            force_decision=data.get("force_decision", True),
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
        """Merge config with command-line arguments."""
        # Create a copy with updated values
        llm = LLMConfig(
            provider=kwargs.get("provider", self.llm.provider),
            model=kwargs.get("model", self.llm.model),
            temperature=kwargs.get("temperature", self.llm.temperature),
            max_tokens=kwargs.get("max_tokens", self.llm.max_tokens),
            ollama_base_url=kwargs.get("ollama_base_url", self.llm.ollama_base_url),
        )

        verification = VerificationConfig(
            max_iterations=kwargs.get("max_iterations", self.verification.max_iterations),
            force_decision=kwargs.get("force_decision", self.verification.force_decision),
        )

        output = OutputConfig(
            verbosity=kwargs.get("verbosity", self.output.verbosity),
            log_file=kwargs.get("log_file", self.output.log_file),
        )

        fuzz = FuzzConfig(
            max_fix_iterations=kwargs.get("max_fix_iterations", self.fuzz.max_fix_iterations),
            extra_include_dirs=kwargs.get("extra_include_dirs", self.fuzz.extra_include_dirs),
            extra_lib_dirs=kwargs.get("extra_lib_dirs", self.fuzz.extra_lib_dirs),
            extra_link_libs=kwargs.get("extra_link_libs", self.fuzz.extra_link_libs),
            extra_cflags=kwargs.get("extra_cflags", self.fuzz.extra_cflags),
            extra_ldflags=kwargs.get("extra_ldflags", self.fuzz.extra_ldflags),
        )

        return Config(
            llm=llm,
            verification=verification,
            paths=self.paths,
            output=output,
            fuzz=fuzz,
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
    - OPENAI_API_KEY: OpenAI API key (secret)
    - LLM_PROVIDER: LLM provider (openai or ollama)
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
