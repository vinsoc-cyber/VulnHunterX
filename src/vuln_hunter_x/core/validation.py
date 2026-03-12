"""Input validation utilities for security-sensitive parameters."""

from __future__ import annotations

import os
import re
from pathlib import Path


# Repo names: alphanumeric, hyphens, underscores, dots (common in GitHub repos)
_REPO_NAME_RE = re.compile(r"^[\w\-\.]+$")


def validate_repo_name(name: str) -> str:
    """Validate that a repository name is safe for use in file paths.

    Raises ValueError if the name contains path traversal characters or
    other unsafe patterns.
    """
    if not name or not _REPO_NAME_RE.match(name):
        raise ValueError(
            f"Invalid repository name: {name!r}. "
            "Only alphanumeric characters, hyphens, underscores, and dots are allowed."
        )
    # Block names that are special path components
    if name in (".", "..") or name.startswith("."):
        raise ValueError(f"Repository name must not start with a dot: {name!r}")
    return name


def validate_file_path(path: Path, base: Path) -> Path:
    """Validate that a resolved path is within the expected base directory.

    Args:
        path: The path to validate (will be resolved).
        base: The base directory that the path must be within.

    Returns:
        The resolved path.

    Raises:
        ValueError: If the path escapes the base directory.
    """
    resolved = path.resolve()
    base_resolved = base.resolve()
    if not resolved.is_relative_to(base_resolved):
        raise ValueError(
            f"Path traversal blocked: {path} resolves outside {base_resolved}"
        )
    return resolved


def normalize_ollama_model(model: str) -> str:
    """Ensure Ollama model names have the 'ollama/' prefix."""
    if not model.startswith("ollama/"):
        return f"ollama/{model}"
    return model


def openai_compat_kwargs(
    *,
    provider: str,
    model: str,
    api_base: str | None = None,
    stream: bool = False,
) -> dict[str, bool]:
    """Build extra kwargs for OpenAI-compatible non-streaming completions.

    Some OpenAI-compatible backends require `enable_thinking=false` for
    non-streaming calls. Default to False, with optional env override.
    """
    if stream:
        return {}

    is_openai_compat = provider == "openai" or model.startswith("openai/") or bool(api_base)
    if not is_openai_compat:
        return {}

    raw = os.environ.get("OPENAI_ENABLE_THINKING", "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        enable_thinking = True
    elif raw in {"0", "false", "no", "off"}:
        enable_thinking = False
    else:
        enable_thinking = False

    return {"enable_thinking": enable_thinking}
