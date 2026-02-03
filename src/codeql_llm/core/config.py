"""Configuration management for CodeQL + LLM verification."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: str = "openai"
    model: str = "gpt-4o"
    temperature: float = 0.2
    max_tokens: int = 1500
    ollama_base_url: str = "http://localhost:11434"
    
    @property
    def is_openai(self) -> bool:
        return self.provider == "openai"
    
    @property
    def is_ollama(self) -> bool:
        return self.provider == "ollama"


@dataclass
class VerificationConfig:
    """Verification mode configuration."""
    mode: str = "vulnhalla"
    max_iterations: int = 3
    
    @property
    def is_vulnhalla(self) -> bool:
        return self.mode == "vulnhalla"
    
    @property
    def is_simple(self) -> bool:
        return self.mode == "simple"


@dataclass
class PathsConfig:
    """Path configuration for project directories."""
    repos_dir: Path = field(default_factory=lambda: Path("repos"))
    databases_dir: Path = field(default_factory=lambda: Path("databases"))
    output_dir: Path = field(default_factory=lambda: Path("output"))
    context_dir: Path = field(default_factory=lambda: Path("config/context"))
    prompts_dir: Path = field(default_factory=lambda: Path("config/prompts"))
    queries_dir: Path = field(default_factory=lambda: Path("config/queries"))
    
    def resolve(self, base_path: Path) -> "PathsConfig":
        """Resolve all paths relative to a base path."""
        return PathsConfig(
            repos_dir=base_path / self.repos_dir,
            databases_dir=base_path / self.databases_dir,
            output_dir=base_path / self.output_dir,
            context_dir=base_path / self.context_dir,
            prompts_dir=base_path / self.prompts_dir,
            queries_dir=base_path / self.queries_dir,
        )


@dataclass
class OutputConfig:
    """Output and logging configuration."""
    verbosity: str = "normal"  # quiet, normal, verbose
    log_file: Optional[Path] = None
    
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
    
    # Processing limits
    limit: int = 0
    languages: list[str] = field(default_factory=list)
    repositories: list[str] = field(default_factory=list)
    
    # CodeQL settings
    codeql_path: str = "codeql"
    
    @classmethod
    def from_dict(cls, data: dict[str, Any], base_path: Optional[Path] = None) -> "Config":
        """Create config from dictionary."""
        # Ollama URL comes from environment only (not from YAML config)
        ollama_url = os.environ.get("OLLAMA_API_BASE", "http://localhost:11434")
        
        llm = LLMConfig(
            provider=data.get("provider", "openai"),
            model=data.get("model", "gpt-4o"),
            temperature=data.get("temperature", 0.2),
            max_tokens=data.get("max_tokens", 1500),
            ollama_base_url=ollama_url,
        )
        
        verification = VerificationConfig(
            mode=data.get("mode", "vulnhalla"),
            max_iterations=data.get("max_iterations", 3),
        )
        
        paths = PathsConfig(
            repos_dir=Path(data.get("repos_dir", "repos")),
            databases_dir=Path(data.get("databases_dir", "databases")),
            output_dir=Path(data.get("output_dir", "output")),
            context_dir=Path(data.get("context_dir", "config/context")),
            prompts_dir=Path(data.get("prompts_dir", "config/prompts")),
            queries_dir=Path(data.get("queries_dir", "config/queries")),
        )
        
        if base_path:
            paths = paths.resolve(base_path)
        
        output = OutputConfig(
            verbosity=data.get("verbosity", "normal"),
            log_file=Path(data["log_file"]) if data.get("log_file") else None,
        )
        
        return cls(
            llm=llm,
            verification=verification,
            paths=paths,
            output=output,
            limit=data.get("limit", 0),
            languages=data.get("languages", []),
            repositories=data.get("repositories", []),
            codeql_path=data.get("codeql_path", "codeql"),
        )
    
    @classmethod
    def from_file(cls, config_path: Path, base_path: Optional[Path] = None) -> "Config":
        """Load config from YAML file."""
        if not config_path.is_file():
            return cls()
        
        with open(config_path) as f:
            data = yaml.safe_load(f) or {}
        
        if base_path is None:
            base_path = config_path.parent.parent  # Assume config is in config/
        
        return cls.from_dict(data, base_path)
    
    @classmethod
    def from_env(cls, base_path: Optional[Path] = None) -> "Config":
        """Create config from environment variables only."""
        data = {
            "codeql_path": os.environ.get("CODEQL_PATH", "codeql"),
            # Note: ollama_base_url is read in from_dict via OLLAMA_API_BASE
        }
        return cls.from_dict(data, base_path)
    
    def merge_with_args(self, **kwargs) -> "Config":
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
            mode=kwargs.get("mode", self.verification.mode),
            max_iterations=kwargs.get("max_iterations", self.verification.max_iterations),
        )
        
        output = OutputConfig(
            verbosity=kwargs.get("verbosity", self.output.verbosity),
            log_file=kwargs.get("log_file", self.output.log_file),
        )
        
        return Config(
            llm=llm,
            verification=verification,
            paths=self.paths,
            output=output,
            limit=kwargs.get("limit", self.limit),
            languages=kwargs.get("languages", self.languages),
            repositories=kwargs.get("repositories", self.repositories),
            codeql_path=kwargs.get("codeql_path", self.codeql_path),
        )


def load_config(
    config_path: Optional[Path] = None,
    base_path: Optional[Path] = None,
) -> Config:
    """
    Load configuration from file and environment.
    
    Priority (highest to lowest):
    1. Environment variables (secrets + environment-specific)
    2. Config file (application settings)
    3. Defaults
    
    Environment variables:
    - OPENAI_API_KEY: OpenAI API key (secret)
    - OLLAMA_API_BASE: Ollama server URL (environment-specific)
    - CODEQL_PATH: CodeQL CLI path (environment-specific)
    """
    # Start with defaults
    config = Config()
    
    # Load from file if provided
    if config_path and config_path.is_file():
        config = Config.from_file(config_path, base_path)
    
    # Override with environment variables (environment-specific settings)
    env_codeql = os.environ.get("CODEQL_PATH")
    env_ollama = os.environ.get("OLLAMA_API_BASE")
    
    if env_codeql:
        config.codeql_path = env_codeql
    if env_ollama:
        config.llm.ollama_base_url = env_ollama
    
    return config
