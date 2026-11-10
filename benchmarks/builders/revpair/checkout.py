# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""Commit-exact checkouts for revision pairs.

``vuln_hunter_x.codeql.repository.clone_repo`` is shallow (``--depth 1``) and
no-ops on an existing ``.git``, so it cannot materialise arbitrary historical
commits. This module keeps one bare mirror per upstream under a cache directory
(``git clone --mirror``; later ``git fetch`` only when a needed commit is
missing) and materialises each revision as a detached ``git worktree``.

Safety:
    * Only ``https://`` / ``git://`` URLs are accepted (plus absolute local
      paths when ``allow_local=True``, for synthetic test repositories).
    * SHAs must be 7–40 lowercase/uppercase hex characters and are always
      resolved to the full commit id before use.
    * Every git call uses an argument list (no shell), a timeout,
      ``GIT_TERMINAL_PROMPT=0`` and ``core.hooksPath=/dev/null`` so neither a
      credential prompt nor a repository hook can run.
    * All operations are idempotent: an existing mirror/worktree is reused
      when it is at the requested commit and rejected when it is not.
"""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

from benchmarks.builders.revpair.hunks import DiffIndex, parse_unified_diff

logger = logging.getLogger(__name__)

SHA_RE = re.compile(r"^[0-9a-fA-F]{7,40}$")
_URL_RE = re.compile(r"^(?:https|git)://[A-Za-z0-9.-]+(?::\d+)?/[A-Za-z0-9._~/+-]+$")
_SAFE_COMPONENT_RE = re.compile(r"[^A-Za-z0-9._-]+")

GIT_TIMEOUT_LOCAL = 120
GIT_TIMEOUT_NETWORK = 1800


class CheckoutError(RuntimeError):
    """A git operation failed or an input was rejected."""


def validate_sha(sha: str) -> str:
    """Return ``sha`` lower-cased, or raise :class:`ValueError` if not hex."""
    if not isinstance(sha, str) or not SHA_RE.match(sha):
        raise ValueError(f"Invalid commit SHA: {sha!r} (expected 7-40 hex characters)")
    return sha.lower()


def validate_repo_url(url: str, *, allow_local: bool = False) -> str:
    """Validate an upstream URL.

    Accepts ``https://host/path`` and ``git://host/path`` (no credentials, no
    query strings, no option-like values). An absolute local directory is only
    accepted with ``allow_local=True``.
    """
    if not isinstance(url, str) or not url or url.startswith("-"):
        raise ValueError(f"Invalid repository URL: {url!r}")
    if _URL_RE.match(url) and ".." not in url.split("://", 1)[1]:
        return url
    if allow_local:
        p = Path(url)
        if p.is_absolute() and p.is_dir():
            return str(p.resolve())
    raise ValueError(f"Invalid repository URL: {url!r} (only https:// or git:// URLs are accepted)")


def repo_slug(url: str) -> str:
    """Filesystem/CodeQL-safe repository name derived from a URL or path.

    ``https://github.com/owner/proj.git`` → ``owner_proj``. The result
    satisfies ``vuln_hunter_x.core.validation.validate_repo_name``.
    """
    path = url.split("://", 1)[-1].rstrip("/")
    if path.endswith(".git"):
        path = path[: -len(".git")]
    parts = [p for p in path.split("/") if p][-2:]
    slug = _SAFE_COMPONENT_RE.sub("-", "_".join(parts)).strip("._-")
    return slug or "repo"


def revision_name(repo: str, sha: str) -> str:
    """Workspace name of one revision: ``<repo>__<sha8>`` (validated)."""
    from vuln_hunter_x.core.validation import validate_repo_name

    return validate_repo_name(f"{repo}__{validate_sha(sha)[:8]}")


def _git_env() -> dict[str, str]:
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "/bin/true"
    env.setdefault("LC_ALL", "C")
    return env


def run_git(
    args: list[str],
    *,
    cwd: Path | None = None,
    timeout: int = GIT_TIMEOUT_LOCAL,
) -> str:
    """Run ``git <args>`` safely and return stdout; raise :class:`CheckoutError`."""
    cmd = ["git", "-c", "core.hooksPath=/dev/null", "-c", "core.quotePath=false", *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            env=_git_env(),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CheckoutError(f"git {args[0]} timed out after {timeout}s") from exc
    except OSError as exc:
        raise CheckoutError(f"git not runnable: {exc}") from exc
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        raise CheckoutError(f"git {args[0]} failed ({proc.returncode}): {err[:500]}")
    return proc.stdout


@dataclass
class RevisionPair:
    """Both checked-out revisions of one fix plus its diff."""

    repo: str
    repo_url: str
    mirror: Path
    parent_sha: str
    fix_sha: str
    vuln_dir: Path
    fix_dir: Path
    diff_text: str

    @property
    def vuln_name(self) -> str:
        return revision_name(self.repo, self.parent_sha)

    @property
    def fix_name(self) -> str:
        return revision_name(self.repo, self.fix_sha)

    def diff(self) -> DiffIndex:
        return parse_unified_diff(self.diff_text)


class RevisionCheckout:
    """Mirror cache + detached worktrees under ``cache_dir``.

    Layout::

        <cache_dir>/mirrors/<slug>-<urlhash8>.git
        <cache_dir>/worktrees/<slug>/<slug>__<sha8>
    """

    def __init__(
        self,
        cache_dir: Path,
        *,
        allow_local: bool = False,
        network_timeout: int = GIT_TIMEOUT_NETWORK,
        local_timeout: int = GIT_TIMEOUT_LOCAL,
    ) -> None:
        self.cache_dir = Path(cache_dir).resolve()
        self.allow_local = allow_local
        self.network_timeout = network_timeout
        self.local_timeout = local_timeout

    # ── mirror ────────────────────────────────────────────────────────────

    def mirror_path(self, url: str) -> Path:
        digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:8]
        return self.cache_dir / "mirrors" / f"{repo_slug(url)}-{digest}.git"

    def ensure_mirror(self, url: str, needed: list[str] | None = None) -> Path:
        """Create the bare mirror, or fetch only if a ``needed`` commit is missing."""
        url = validate_repo_url(url, allow_local=self.allow_local)
        mirror = self.mirror_path(url)
        if not (mirror / "HEAD").is_file():
            mirror.parent.mkdir(parents=True, exist_ok=True)
            run_git(
                ["clone", "--mirror", "--no-local", "--", url, str(mirror)],
                timeout=self.network_timeout,
            )
            return mirror
        if needed and all(self._has_commit(mirror, s) for s in needed):
            return mirror
        run_git(
            ["--git-dir", str(mirror), "fetch", "--prune", "--tags", "origin"],
            timeout=self.network_timeout,
        )
        return mirror

    def _has_commit(self, mirror: Path, sha: str) -> bool:
        try:
            self.resolve_commit(mirror, sha)
            return True
        except CheckoutError:
            return False

    def resolve_commit(self, mirror: Path, sha: str) -> str:
        """Resolve a (possibly abbreviated) SHA to the full commit id."""
        sha = validate_sha(sha)
        out = run_git(
            ["--git-dir", str(mirror), "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}"],
            timeout=self.local_timeout,
        ).strip()
        return validate_sha(out)

    def resolve_parent(self, mirror: Path, fix_sha: str, parent_sha: str | None = None) -> str:
        """Return the full parent SHA.

        Without an explicit ``parent_sha`` the fix must have exactly one parent:
        a merge commit (ambiguous vulnerable side) or a root commit is rejected.
        """
        fix_full = self.resolve_commit(mirror, fix_sha)
        if parent_sha:
            return self.resolve_commit(mirror, parent_sha)
        line = run_git(
            ["--git-dir", str(mirror), "rev-list", "--parents", "-n", "1", fix_full],
            timeout=self.local_timeout,
        ).split()
        parents = line[1:]
        if len(parents) != 1:
            kind = "root commit" if not parents else f"merge commit ({len(parents)} parents)"
            raise CheckoutError(
                f"{fix_full[:12]} is a {kind}; pass parent_sha explicitly to choose the "
                "vulnerable revision"
            )
        return validate_sha(parents[0])

    # ── worktrees ─────────────────────────────────────────────────────────

    def worktree_path(self, repo: str, sha: str) -> Path:
        return self.cache_dir / "worktrees" / repo / revision_name(repo, sha)

    def add_worktree(self, mirror: Path, repo: str, sha: str) -> Path:
        """Materialise ``sha`` as a detached worktree; reuse it if already there."""
        sha = validate_sha(sha)
        dest = self.worktree_path(repo, sha)
        if dest.exists():
            try:
                head = run_git(["rev-parse", "HEAD"], cwd=dest, timeout=self.local_timeout)
            except CheckoutError as exc:
                raise CheckoutError(f"{dest} exists but is not a git worktree") from exc
            if head.strip().lower() != sha:
                raise CheckoutError(
                    f"{dest} is at {head.strip()[:12]}, expected {sha[:12]}; remove it first"
                )
            return dest
        dest.parent.mkdir(parents=True, exist_ok=True)
        # Prune stale registrations (e.g. a worktree dir deleted by hand).
        run_git(["--git-dir", str(mirror), "worktree", "prune"], timeout=self.local_timeout)
        run_git(
            ["--git-dir", str(mirror), "worktree", "add", "--detach", "--", str(dest), sha],
            timeout=self.local_timeout,
        )
        return dest

    def diff(self, mirror: Path, parent_sha: str, fix_sha: str) -> str:
        """Raw ``git diff -U0 -M`` between the two commits (no textconv/ext-diff)."""
        return run_git(
            [
                "--git-dir",
                str(mirror),
                "diff",
                "-U0",
                "-M",
                "--no-color",
                "--no-ext-diff",
                "--no-textconv",
                "--src-prefix=a/",
                "--dst-prefix=b/",
                validate_sha(parent_sha),
                validate_sha(fix_sha),
            ],
            timeout=self.local_timeout,
        )

    def prepare(
        self,
        repo_url: str,
        fix_sha: str,
        parent_sha: str | None = None,
        *,
        repo: str | None = None,
    ) -> RevisionPair:
        """Mirror, resolve, check out both revisions and compute the diff."""
        url = validate_repo_url(repo_url, allow_local=self.allow_local)
        validate_sha(fix_sha)
        needed = [fix_sha] + ([parent_sha] if parent_sha else [])
        mirror = self.ensure_mirror(url, needed=needed)
        fix_full = self.resolve_commit(mirror, fix_sha)
        parent_full = self.resolve_parent(mirror, fix_full, parent_sha)
        name = repo or repo_slug(url)
        vuln_dir = self.add_worktree(mirror, name, parent_full)
        fix_dir = self.add_worktree(mirror, name, fix_full)
        return RevisionPair(
            repo=name,
            repo_url=url,
            mirror=mirror,
            parent_sha=parent_full,
            fix_sha=fix_full,
            vuln_dir=vuln_dir,
            fix_dir=fix_dir,
            diff_text=self.diff(mirror, parent_full, fix_full),
        )
