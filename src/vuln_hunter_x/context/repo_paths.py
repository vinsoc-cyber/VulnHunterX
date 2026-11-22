# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Copyright (c) 2026 VinSOC Cyber

"""Fail-closed, repo-scoped source path resolution.

Every per-finding source lookup must stay inside the finding's own repository
(``repos/<lang>/<repo_name>/``). Scanning sibling repos for a matching relative
path can hand the verifier code from the wrong repository. These helpers
resolve strictly within the named repo and fail closed (``None``) otherwise;
they never inspect sibling repos.
"""

from __future__ import annotations

import logging
from pathlib import Path

from vuln_hunter_x.core.validation import validate_repo_name

logger = logging.getLogger(__name__)


def resolve_repo_root(repos_root: Path, lang: str, repo_name: str) -> Path | None:
    """Return the on-disk source root for a repo, or ``None`` (fail-closed).

    Empty ``repo_name`` or a missing root -> ``None``. Symlinked roots
    (``repos/<lang>/<repo>`` -> a checkout) are accepted via ``exists()``.
    """
    try:
        validate_repo_name(repo_name)
        validate_repo_name(lang)
        if (repos_root / lang).is_symlink():
            return None
    except ValueError:
        return None
    root = repos_root / lang / repo_name
    return root if root.is_dir() else None


def resolve_repo_file(repos_root: Path, lang: str, repo_name: str, file_path: str) -> Path | None:
    """Resolve ``file_path`` strictly within ``repos/<lang>/<repo_name>``, or ``None``.

    Fail-closed: empty ``repo_name``, a path escaping the repo root, or a
    missing file all return ``None``. Never scans sibling repos. Symlinked repo
    roots are allowed: containment is checked against the resolved root.
    """
    root = resolve_repo_root(repos_root, lang, repo_name)
    if root is None:
        return None
    return resolve_source_file(root, file_path)


def resolve_source_file(root: Path, file_path: str | Path) -> Path | None:
    """Return a regular file inside the selected checkout, including internal links."""
    candidate = root / file_path
    try:
        resolved_root = root.resolve()
        resolved = candidate.resolve()
    except (OSError, RuntimeError, ValueError):
        return None
    if not resolved.is_relative_to(resolved_root):
        logger.warning("Path traversal blocked: %r escapes %s", file_path, root)
        return None
    return resolved if resolved.is_file() else None
