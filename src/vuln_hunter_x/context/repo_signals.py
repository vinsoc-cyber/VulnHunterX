# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Repository-level signals fed to the verifier as extra context.

Two signals address triage-quality defects observed on the dvpwa run:

* **Framework detection** (P2.1) — the model guessed "FastAPI/Django" for an
  aiohttp app because nothing told it the real framework, then built
  exploitability arguments on the wrong one. Detecting the framework from the
  dependency manifests and surfacing it stops the guessing.
* **Commented-out / unwired references** (P2.2) — a finding inside a security
  control that is *defined but never wired in* (dvpwa's ``csrf_middleware`` is
  commented out in ``app.py``) was confirmed as a live, reachable bug. Flagging
  that the enclosing symbol appears only in commented-out code lets the model
  weight reachability correctly.

Both are best-effort, read-only, and cached per repository root so the cost is
paid once per scan rather than per finding.
"""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

# Files that mark a repository root, in priority order.
_ROOT_MARKERS = (
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
    "Pipfile", "go.mod", "package.json", "composer.json", "pom.xml",
    ".git",
)

# Directories never worth scanning (vendored / build / VCS).
_SKIP_DIRS = frozenset({
    ".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env",
    "__pycache__", "dist", "build", ".tox", ".mypy_cache", "site-packages",
    "vendor", "third_party",
})

# Known web frameworks keyed by an identifying package/import token.
_PY_FRAMEWORKS = {
    "aiohttp": "aiohttp",
    "aiohttp_jinja2": "aiohttp",
    "aiohttp-jinja2": "aiohttp",
    "fastapi": "FastAPI",
    "starlette": "Starlette",
    "flask": "Flask",
    "django": "Django",
    "tornado": "Tornado",
    "sanic": "Sanic",
    "bottle": "Bottle",
    "pyramid": "Pyramid",
    "falcon": "Falcon",
    "quart": "Quart",
}

# Cap how much of the tree we read so a giant monorepo can't stall a scan.
_MAX_FILES_SCANNED = 4000


def find_repo_root(file_path: str | Path) -> Path | None:
    """Walk up from *file_path* to the nearest directory holding a root marker."""
    try:
        p = Path(file_path).resolve()
    except (OSError, RuntimeError):
        return None
    start = p.parent if p.is_file() or p.suffix else p
    for d in [start, *start.parents]:
        try:
            if any((d / m).exists() for m in _ROOT_MARKERS):
                return d
        except OSError:
            continue
    return None


@lru_cache(maxsize=64)
def detect_frameworks(repo_root: str, lang: str) -> tuple[str, ...]:
    """Return the web frameworks the repo at *repo_root* depends on.

    Python only for now (other languages return ``()`` — a safe no-op). Reads
    dependency manifests first; falls back to scanning ``import`` lines.
    """
    if (lang or "").lower() != "python":
        return ()
    root = Path(repo_root)
    if not root.is_dir():
        return ()

    found: set[str] = set()
    tokens = "|".join(re.escape(k) for k in _PY_FRAMEWORKS)
    manifest_re = re.compile(rf"(?<![\w.-])({tokens})(?![\w.-])", re.IGNORECASE)
    import_re = re.compile(rf"^\s*(?:from|import)\s+({tokens})\b", re.IGNORECASE)

    # 1. Dependency manifests (authoritative, cheap).
    for name in ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg"):
        f = root / name
        if not f.is_file():
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        for m in manifest_re.finditer(text):
            key = m.group(1).lower().replace("-", "_")
            if key in _PY_FRAMEWORKS:
                found.add(_PY_FRAMEWORKS[key])

    # 2. Fallback: scan import statements in the source tree.
    if not found:
        scanned = 0
        for py in root.rglob("*.py"):
            if any(part in _SKIP_DIRS for part in py.parts):
                continue
            scanned += 1
            if scanned > _MAX_FILES_SCANNED:
                break
            try:
                for line in py.read_text(encoding="utf-8", errors="ignore").splitlines():
                    m = import_re.match(line)
                    if m:
                        key = m.group(1).lower().replace("-", "_")
                        if key in _PY_FRAMEWORKS:
                            found.add(_PY_FRAMEWORKS[key])
            except OSError:
                continue

    return tuple(sorted(found))


def detect_frameworks_for(file_path: str | Path, lang: str) -> tuple[str, ...]:
    """File-based convenience over :func:`detect_frameworks`.

    Resolves the repo root from *file_path* then delegates to the cached
    root-keyed detector. Returns ``()`` when no root is found.
    """
    root = find_repo_root(file_path)
    if root is None:
        return ()
    return detect_frameworks(str(root), lang or "")


@lru_cache(maxsize=256)
def _commented_identifier_index(repo_root: str, lang: str) -> frozenset[str]:
    """Identifiers that appear on a COMMENTED-OUT source line anywhere in the repo.

    A bare-name commented reference (``# csrf_middleware,``) is the fingerprint
    of a control that was wired up and then disabled. We index identifiers found
    on comment lines once per repo so per-finding lookups are O(1).
    """
    root = Path(repo_root)
    if not root.is_dir():
        return frozenset()

    lang = (lang or "").lower()
    # (line-comment prefix, glob) per language.
    specs = {
        "python": ("#", "*.py"),
        "javascript": ("//", "*.js"),
        "typescript": ("//", "*.ts"),
        "go": ("//", "*.go"),
        "java": ("//", "*.java"),
        "php": ("//", "*.php"),
    }
    prefix, glob = specs.get(lang, ("#", "*.py"))
    # Only harvest identifiers that sit in COMMENTED-OUT CODE, i.e. adjacent to
    # code punctuation (``# csrf_middleware,`` / ``# foo()`` / ``# x.bar``). A
    # prose comment like ``# create connection to the database`` must NOT
    # contribute "create" — that false signal previously downgraded a real
    # SQLi whose method happened to be named ``create``.
    code_ident_re = re.compile(
        r"\.([A-Za-z_]\w{2,})"            # attribute use:  .bar
        r"|([A-Za-z_]\w{2,})\s*[(\[]"     # call / index:   foo( / foo[
        r"|([A-Za-z_]\w{2,})\s*[,=:]"     # list elem / kw: foo, / foo= / foo:
    )
    idents: set[str] = set()
    scanned = 0
    for src in root.rglob(glob):
        if any(part in _SKIP_DIRS for part in src.parts):
            continue
        scanned += 1
        if scanned > _MAX_FILES_SCANNED:
            break
        try:
            for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                # Only whole-line comments — avoids harvesting trailing-comment
                # prose and keeps the signal to genuinely disabled code lines.
                if stripped.startswith(prefix):
                    body = stripped[len(prefix):]
                    for m in code_ident_re.finditer(body):
                        idents.add(next(g for g in m.groups() if g))
        except OSError:
            continue
    return frozenset(idents)


@lru_cache(maxsize=256)
def _live_called_index(repo_root: str, lang: str) -> frozenset[str]:
    """Identifiers that are actually CALLED in live (non-comment) code.

    A symbol invoked somewhere — ``Student.create(...)`` — is wired in, so it
    must never be reported as "unwired" even if its name also appears in a
    commented-out line elsewhere. Definition lines (``def``/``class``/``func``)
    are skipped so a symbol that is only *defined* (e.g. a middleware that was
    removed from the chain) is correctly absent from this set.
    """
    root = Path(repo_root)
    if not root.is_dir():
        return frozenset()
    lang = (lang or "").lower()
    glob = {
        "python": "*.py", "javascript": "*.js", "typescript": "*.ts",
        "go": "*.go", "java": "*.java", "php": "*.php",
    }.get(lang, "*.py")
    prefix = "//" if lang in ("javascript", "typescript", "go", "java", "php") else "#"
    def_re = re.compile(r"^\s*(?:async\s+)?(?:def|class|func|function)\b")
    call_re = re.compile(r"(?:\.|\b)([A-Za-z_]\w{2,})\s*\(")
    called: set[str] = set()
    scanned = 0
    for src in root.rglob(glob):
        if any(part in _SKIP_DIRS for part in src.parts):
            continue
        scanned += 1
        if scanned > _MAX_FILES_SCANNED:
            break
        try:
            for line in src.read_text(encoding="utf-8", errors="ignore").splitlines():
                stripped = line.strip()
                if stripped.startswith(prefix) or def_re.match(line):
                    continue  # skip comments and definition headers
                called.update(call_re.findall(line))
        except OSError:
            continue
    return frozenset(called)


def commented_out_symbol(file_path: str | Path, symbol: str, lang: str) -> bool:
    """True if *symbol* looks defined-but-unwired (disabled) in the repo.

    Fires only when *symbol* appears in COMMENTED-OUT CODE somewhere **and** is
    not actually called anywhere in live code. Both conditions are required so
    common method names that merely show up in a prose comment (e.g. ``create``
    in ``# create connection``) are not mistaken for dead code. Returns False
    for empty/anonymous symbols and when the repo root cannot be located.
    """
    if not symbol or symbol.startswith("<"):
        return False
    root = find_repo_root(file_path)
    if root is None:
        return False
    root_s = str(root)
    if symbol not in _commented_identifier_index(root_s, lang or ""):
        return False
    return symbol not in _live_called_index(root_s, lang or "")
