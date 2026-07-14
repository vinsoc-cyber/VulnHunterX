# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Fail-closed, repo-scoped source path resolution.

Every per-finding source lookup must stay inside the finding's own repository
(``repos/<lang>/<repo_name>/``). Scanning sibling repos for a matching relative
path can hand the verifier code from the wrong repository (#156). These helpers
resolve strictly within the named repo and fail closed (``None``) otherwise;
they never inspect sibling repos.
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_repo_root(repos_root: Path, lang: str, repo_name: str) -> Path | None:
    """Return the on-disk source root for a repo, or ``None`` (fail-closed).

    Empty ``repo_name`` or a missing root -> ``None``. Symlinked roots
    (``repos/<lang>/<repo>`` -> a checkout) are accepted via ``exists()``.
    """
    if not repo_name:
        return None
    root = repos_root / lang / repo_name
    return root if root.exists() else None


def resolve_repo_file(
    repos_root: Path, lang: str, repo_name: str, file_path: str
) -> Path | None:
    """Resolve ``file_path`` strictly within ``repos/<lang>/<repo_name>``, or ``None``.

    Fail-closed: empty ``repo_name``, a path escaping the repo root, or a
    missing file all return ``None``. Never scans sibling repos. Symlinked repo
    roots are allowed: containment is checked against the resolved root.
    """
    root = resolve_repo_root(repos_root, lang, repo_name)
    if root is None:
        return None
    candidate = root / file_path
    try:
        resolved_root = root.resolve()
        resolved = candidate.resolve()
    except OSError:
        return None
    if not resolved.is_relative_to(resolved_root):
        logger.warning("Path traversal blocked: %r escapes %s/%s", file_path, lang, repo_name)
        return None
    return candidate if candidate.is_file() else None
