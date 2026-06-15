# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

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
        raise ValueError(f"Path traversal blocked: {path} resolves outside {base_resolved}")
    return resolved


def normalize_ollama_model(model: str) -> str:
    """Ensure Ollama model names have the 'ollama/' prefix.

    Leaves 'ollama_chat/' prefixes alone — that's the chat-completions
    route used for Ollama Cloud.
    """
    if model.startswith(("ollama/", "ollama_chat/")):
        return model
    return f"ollama/{model}"


def openai_compat_kwargs(
    *,
    provider: str,
    model: str,
    api_base: str | None = None,
    stream: bool = False,
) -> dict[str, bool]:
    """Build extra kwargs for OpenAI-compatible non-streaming completions.

    Some third-party OpenAI-compatible backends (e.g. Alibaba DashScope /
    Qwen, vLLM with thinking-mode models) require ``enable_thinking=false``
    for non-streaming calls. The official OpenAI API rejects this kwarg
    (``Unrecognized request argument supplied: enable_thinking``), so we
    only emit it when an ``api_base`` is set and clearly does NOT point at
    OpenAI itself. ``OPENAI_ENABLE_THINKING`` overrides the default.
    """
    if stream:
        return {}

    is_openai_compat = provider == "openai" or model.startswith("openai/") or bool(api_base)
    if not is_openai_compat:
        return {}

    raw = os.environ.get("OPENAI_ENABLE_THINKING", "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return {"enable_thinking": True}
    if raw in {"0", "false", "no", "off"}:
        return {"enable_thinking": False}

    # No explicit override. Only send the kwarg to non-OpenAI compatible
    # endpoints — i.e. when the caller has pointed us at a custom api_base
    # that isn't api.openai.com. This keeps the official OpenAI API path
    # clean while still defaulting third-party endpoints to thinking=off.
    if not api_base:
        return {}
    if "api.openai.com" in api_base:
        return {}
    return {"enable_thinking": False}
