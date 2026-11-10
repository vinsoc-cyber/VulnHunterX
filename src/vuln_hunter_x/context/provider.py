# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""CSV-based context provider for on-demand context expansion."""

from __future__ import annotations

import csv
import logging
import os
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path

from vuln_hunter_x.context.evidence import (
    ArtifactState,
    CallerRef,
    Capability,
    EvidenceKind,
    EvidenceRequest,
    EvidenceResult,
    EvidenceScope,
    EvidenceStatus,
    RecordedCallersResult,
    ReferenceScanResult,
    SourceRef,
    SymbolRef,
    SymbolResolution,
    inspect_capability,
    struct_csv_name,
)
from vuln_hunter_x.context.repo_paths import resolve_repo_file, resolve_repo_root

logger = logging.getLogger(__name__)


def _safe_repo_rel(path: str) -> str | None:
    """Normalize a repo-relative path, rejecting escapes; no existence check.

    Returns a forward-slash, dot-collapsed relative path, or ``None`` for an
    empty, absolute, or ``..``-escaping path. Used to classify recorded caller
    paths (only their basename matters) without forcing every caller file to
    exist on disk.
    """
    n = (path or "").replace("\\", "/").strip()
    if not n or n.startswith("/"):
        return None
    parts: list[str] = []
    for seg in n.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            return None
        parts.append(seg)
    return "/".join(parts) if parts else None

# Directories never worth walking when grepping a repo for framework config —
# pruned in os.walk so a node_modules tree doesn't dominate the scan.
_SKIP_DIRS = frozenset(
    {"node_modules", "dist", "build", "coverage", ".git", ".next", "out", "vendor"}
)

# Route-registration shapes (#121). An Express-style handler is MOUNTED, not
# called — `app.post('/contributions', auth, h.handleContributionsUpdate)`
# produces no caller row in callers.csv, so the deciding attacker path sits one
# file away from the handler and caller resolution used to concede with
# "[No callers found]". Line-level heuristic: a route-registration call token
# plus a word-bounded reference to the handler on the same line.
_JS_ROUTE_REGISTRATION_RE = re.compile(
    r"\b(?:app|router|server|api)\s*\.\s*(?:get|post|put|delete|patch|all|use|route)\s*\(",
    re.IGNORECASE,
)
_JS_SOURCE_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".tsx")


@dataclass(frozen=True)
class TestScanConvention:
    """Per-language conventions the test-only reachability scan needs (#162).

    ``source_exts`` bounds the reference scan; ``decl_patterns`` locate the
    declaration token to exclude from it (each pattern's group 1 is the token,
    and the union must match exactly once or the scan abstains); ``is_test_file``
    classifies a *basename*.

    Deliberately conservative in both directions. Under-recognising a test file
    only stops the gate firing (the caller check requires *every* caller to be
    in a test file), whereas over-recognising one would suppress a real finding
    — so the predicates match established, unambiguous conventions only.
    """

    source_exts: tuple[str, ...]
    decl_patterns: tuple[str, ...]
    test_file_pattern: str = ""

    def is_test_file(self, path_or_basename: str) -> bool:
        """True when the *basename* follows this language's test-file convention.

        Matched with an anchored regex rather than a bare suffix so a separator
        is always required: a naive ``endswith("test.php")`` would also classify
        ``latest.php`` as a test file, and over-recognition here silently
        suppresses real findings.
        """
        if not self.test_file_pattern:
            return False
        name = path_or_basename.replace("\\", "/").rsplit("/", 1)[-1]
        return bool(re.search(self.test_file_pattern, name))


# Languages whose function declarations start with an unambiguous keyword, so a
# single declaration token can be located precisely. java/csharp/c/cpp are
# deliberately ABSENT: their declarations lead with modifiers and a return type
# rather than a keyword, so no precise single-token match is reliable and the
# gate must keep abstaining for them (see _downgrade_test_only_reachability).
TEST_SCAN_CONVENTIONS: dict[str, TestScanConvention] = {
    "go": TestScanConvention(
        source_exts=(".go",),
        decl_patterns=(r"\bfunc\b\s+(?:\([^)]*\)\s*)?({name})\b",),
        # Go's own convention: the _test.go suffix is what `go test` recognises.
        test_file_pattern=r"_test\.go$",
    ),
    "python": TestScanConvention(
        source_exts=(".py",),
        decl_patterns=(r"\b(?:async\s+)?def\s+({name})\b",),
        # pytest/unittest discovery: test_*.py or *_test.py.
        test_file_pattern=r"(?:^test_.*\.py$|_test\.py$)",
    ),
    "javascript": TestScanConvention(
        source_exts=_JS_SOURCE_EXTS,
        decl_patterns=(
            r"\bfunction\s*\*?\s+({name})\b",
            r"\b(?:const|let|var)\s+({name})\s*=",
        ),
        # jest/vitest/mocha: foo.test.ts, foo.spec.tsx, foo.test.mjs ...
        test_file_pattern=r"\.(?:test|spec)\.(?:[cm]?jsx?|[cm]?tsx?)$",
    ),
    "php": TestScanConvention(
        source_exts=(".php",),
        decl_patterns=(r"\bfunction\s+&?\s*({name})\b",),
        # PHPUnit: CamelCase FooTest.php (case-sensitive, so latest.php is not a
        # test), plus the snake_case foo_test.php variant.
        test_file_pattern=r"(?:Test\.php$|_test\.php$)",
    ),
}
# TypeScript shares the JavaScript convention (the ext set already covers .ts/.tsx).
TEST_SCAN_CONVENTIONS["typescript"] = TEST_SCAN_CONVENTIONS["javascript"]


def scan_convention_for(lang: str | None) -> TestScanConvention | None:
    """Convention for *lang*, or ``None`` when the gate must abstain."""
    return TEST_SCAN_CONVENTIONS.get((lang or "").lower())


@dataclass
class _GrepBounds:
    """Whether a repo grep stopped early. A bound-out search is incomplete and
    must not read as 'marker absent' (P2a)."""

    hit_max_files: bool = False
    hit_max_hits: bool = False


class ContextProvider:
    """
    Provides additional context on-demand using pre-extracted CSV files.

    Context CSVs live under output/<lang>/<repo_name>/context/.
    Supports:
    - caller:function_name - Get the calling function's code
    - function:name - Get the body of a named function/method (the sink/callee
      implementation). Aliases: method:, func:
    - struct:type_name - Get struct/class definition
    - global:var_name - Get global variable definition
    - macro:MACRO_NAME - Get macro definition
    - callees:function_name - Get list of functions called by function_name
    - callee_bodies:function_name - Get the BODIES of functions called by
      function_name (the sink helpers), not just their names
    - all_callers:function_name - Get ALL callers of a function (up to 10)
    - typedef:type_name - Get typedef or type alias definition
    - enum:enum_name - Get enum definition with enumerator values
    - free_sites:pointer_name - Get every free()/delete/destructor call site for
      a pointer expression across the whole repo (C/C++ only)
    - destructor:type_name - Get destructor / cleanup-method body for a class
      or struct (C/C++ only) — useful for RAII / lifetime rules
    - field_writes:Type.field - Get every write site for a struct/class field
      (C/C++ only) — catches shared-state UAF / TOCTOU patterns
    - framework_sanitizers:* - Grep the repo for a global input-validation
      boundary (e.g. NestJS useGlobalPipes(new ValidationPipe({whitelist,
      forbidNonWhitelisted}))). The decisive context for DTO/request-sourced
      taint — whether dangerous keys are stripped/rejected before the sink.
    - framework_guards:* - Grep the repo for global/route auth guards
      (NestJS APP_GUARD, useGlobalGuards, @UseGuards, @Public). The decisive
      context for "missing authentication" findings on guard-protected routes.
    """

    def __init__(self, output_dir: Path, repos_dir: Path):
        """Initialize the context provider.

        Args:
            output_dir: Base output directory containing pre-extracted CSV context files.
            repos_dir: Base directory containing cloned repository source code.
        """
        self.output_dir = Path(output_dir)
        self.repos_dir = Path(repos_dir)
        self._cache: dict[str, list[dict]] = {}
        self._cache_lock = threading.Lock()
        # Small LRU of source files split into lines: caller/callee/function
        # lookups for one finding usually hit the same few files repeatedly.
        self._lines_cache: OrderedDict[Path, list[str]] = OrderedDict()
        self._lines_cache_lock = threading.Lock()

    def _context_dir(self, lang: str, repo_name: str) -> Path:
        """Return context directory for a repo: output/<lang>/<repo_name>/context."""
        return self.output_dir / lang / repo_name / "context"

    _LINES_CACHE_MAX = 128

    def clear_cache(self) -> None:
        """Clear the CSV and source-line caches."""
        with self._cache_lock:
            self._cache.clear()
        with self._lines_cache_lock:
            self._lines_cache.clear()

    def _file_lines(self, full_path: Path) -> list[str]:
        """Return ``full_path`` split into lines, via a bounded LRU cache."""
        with self._lines_cache_lock:
            cached = self._lines_cache.get(full_path)
            if cached is not None:
                self._lines_cache.move_to_end(full_path)
                return cached
        lines = full_path.read_text(errors="replace").splitlines()
        with self._lines_cache_lock:
            self._lines_cache[full_path] = lines
            self._lines_cache.move_to_end(full_path)
            while len(self._lines_cache) > self._LINES_CACHE_MAX:
                self._lines_cache.popitem(last=False)
        return lines

    def get_additional_context(
        self,
        repo_name: str,
        lang: str,
        context_requests: list[str],
    ) -> dict[str, str]:
        """
        Fetch additional context based on LLM requests.

        Args:
            repo_name: Name of the repository
            lang: Language (c, cpp, python, javascript)
            context_requests: List of "type:name" strings

        Returns:
            Dict mapping request to code context
        """
        results: dict[str, str] = {}

        for request in context_requests:
            if ":" not in request:
                continue

            ctx_type, name = request.split(":", 1)
            ctx_type = ctx_type.lower().strip()
            name = name.strip()

            if ctx_type == "caller":
                code = self._get_caller_context(repo_name, lang, name)
            elif ctx_type in ("function", "method", "func"):
                code = self._get_function_context(repo_name, lang, name)
            elif ctx_type == "callee_bodies":
                code = self._get_callee_bodies_context(repo_name, lang, name)
            elif ctx_type in ("struct", "class", "classes"):
                code = self._get_struct_context(repo_name, lang, name)
            elif ctx_type == "global":
                code = self._get_global_context(repo_name, lang, name)
            elif ctx_type == "macro":
                code = self._get_macro_context(repo_name, lang, name)
            elif ctx_type == "callees":
                code = self._get_callees_context(repo_name, lang, name)
            elif ctx_type == "all_callers":
                code = self._get_all_callers_context(repo_name, lang, name)
            elif ctx_type == "typedef":
                code = self._get_typedef_context(repo_name, lang, name)
            elif ctx_type == "enum":
                code = self._get_enum_context(repo_name, lang, name)
            elif ctx_type in ("free_sites", "free_site"):
                code = self._get_free_sites_context(repo_name, lang, name)
            elif ctx_type in ("destructor", "destructors"):
                code = self._get_destructor_context(repo_name, lang, name)
            elif ctx_type in ("field_writes", "field_write"):
                code = self._get_field_writes_context(repo_name, lang, name)
            elif ctx_type in ("framework_sanitizers", "framework_validation"):
                code = self._get_framework_sanitizers(repo_name, lang)
            elif ctx_type in ("framework_guards", "framework_auth"):
                code = self._get_framework_guards(repo_name, lang)
            else:
                code = f"[Unknown context type: {ctx_type}]"

            results[request] = code

        return results

    def resolve_evidence(
        self,
        repo_name: str,
        lang: str,
        requests: list[EvidenceRequest],
    ) -> dict[str, EvidenceResult]:
        """Typed retrieval entrypoint (P2a), keyed by ``request_key``.

        ``get_additional_context`` is the legacy string adapter over the same
        ``_resolve_*`` handlers; this returns the full typed result (status /
        scope / exhaustive / provenance) for the P2b policy gate to consume.
        ``request_key`` equals ``raw_request`` for an unqualified request, so
        two target-qualified requests sharing a ``raw_request`` do not collide.
        """
        return {
            req.request_key: self._dispatch_resolve(req, repo_name, lang)
            for req in requests
        }

    def _dispatch_resolve(
        self, req: EvidenceRequest, repo_name: str, lang: str
    ) -> EvidenceResult:
        kind = req.kind
        if kind is EvidenceKind.CALLER:
            return self._resolve_caller(req, repo_name, lang)
        if kind is EvidenceKind.ALL_CALLERS:
            return self._resolve_all_callers(req, repo_name, lang)
        if kind is EvidenceKind.CALLEES:
            return self._resolve_callees(req, repo_name, lang)
        if kind is EvidenceKind.CALLEE_BODIES:
            return self._resolve_callee_bodies(req, repo_name, lang)
        if kind is EvidenceKind.FUNCTION:
            return self._resolve_function(req, repo_name, lang)
        if kind is EvidenceKind.STRUCT:
            return self._resolve_struct(req, repo_name, lang)
        if kind is EvidenceKind.GLOBAL:
            return self._resolve_global(req, repo_name, lang)
        if kind is EvidenceKind.MACRO:
            return self._resolve_macro(req, repo_name, lang)
        if kind is EvidenceKind.TYPEDEF:
            return self._resolve_typedef(req, repo_name, lang)
        if kind is EvidenceKind.ENUM:
            return self._resolve_enum(req, repo_name, lang)
        if kind is EvidenceKind.FREE_SITES:
            return self._resolve_free_sites(req, repo_name, lang)
        if kind is EvidenceKind.DESTRUCTOR:
            return self._resolve_destructor(req, repo_name, lang)
        if kind is EvidenceKind.FIELD_WRITES:
            return self._resolve_field_writes(req, repo_name, lang)
        if kind is EvidenceKind.FRAMEWORK_SANITIZERS:
            return self._resolve_framework_sanitizers(req, repo_name, lang)
        if kind is EvidenceKind.FRAMEWORK_GUARDS:
            return self._resolve_framework_guards(req, repo_name, lang)
        # Unknown context type — mirror get_additional_context's message exactly.
        ctx_type = (
            req.raw_request.split(":", 1)[0].lower().strip()
            if ":" in req.raw_request
            else req.raw_request
        )
        content = f"[Unknown context type: {ctx_type}]"
        return EvidenceResult(
            req, EvidenceStatus.UNSUPPORTED, content, EvidenceScope.REPOSITORY_INDEX
        )

    def has_context_for_repo(self, repo_name: str, lang: str) -> bool:
        """Check if context CSV files exist for a repository."""
        repo_context_dir = self._context_dir(lang, repo_name)
        return repo_context_dir.is_dir()

    def _load_csv(self, repo_name: str, lang: str, csv_name: str) -> list[dict]:
        """Load a CSV file from the context directory."""
        cache_key = f"{lang}/{repo_name}/{csv_name}"
        with self._cache_lock:
            cached = self._cache.get(cache_key)
            if cached is not None:
                return cached

            csv_path = self._context_dir(lang, repo_name) / f"{csv_name}.csv"
            if not csv_path.is_file():
                return []

            try:
                with open(csv_path, newline="", encoding="utf-8") as f:
                    reader = csv.DictReader(f)
                    rows = list(reader)
                self._cache[cache_key] = rows
                return rows
            except Exception:
                logger.warning(
                    "Failed to load CSV %s for %s/%s", csv_name, lang, repo_name, exc_info=True
                )
                return []

    def _absence_status(self, cap: Capability) -> EvidenceStatus:
        """Map a not-found lookup to an honest status given backend capability.

        Verdict-inert in P2a. Symbol indexes are non-authoritative here, so a
        present-but-missing lookup is INCOMPLETE_INDEX, never NOT_FOUND_COMPLETE.
        """
        if cap.artifact_state is ArtifactState.MISSING:
            return (
                EvidenceStatus.INCOMPLETE_INDEX
                if cap.supported
                else EvidenceStatus.UNSUPPORTED
            )
        if cap.artifact_state is ArtifactState.INVALID:
            return EvidenceStatus.INCOMPLETE_INDEX
        return (
            EvidenceStatus.NOT_FOUND_COMPLETE
            if cap.authoritative_for_absence
            else EvidenceStatus.INCOMPLETE_INDEX
        )

    def _read_lines(
        self,
        repo_name: str,
        lang: str,
        file_path: str,
        start: int,
        end: int,
    ) -> str:
        """Read specific lines from a source file."""
        full_path = resolve_repo_file(self.repos_dir, lang, repo_name, file_path)
        if full_path is None:
            return f"[File not found: {file_path}]"

        try:
            lines = self._file_lines(full_path)
            start_idx = max(0, start - 1)
            end_idx = min(len(lines), end)
            return "\n".join(lines[start_idx:end_idx])
        except Exception as e:
            return f"[Error reading file: {e}]"

    @staticmethod
    def _definitions_result(
        req: EvidenceRequest,
        parts: list[str],
        provs: list[SourceRef],
        total: int,
        scope: EvidenceScope,
        label: str,
    ) -> EvidenceResult:
        """Package one-or-more rendered definitions of a symbol.

        A single definition is ``FOUND`` with exactly the legacy content. Several
        distinct definitions (``#ifdef`` platform variants, the same class name in
        two modules) are all shown, capped, and reported ``AMBIGUOUS``: returning
        only the first row as ``FOUND`` let the model reason over an arbitrary
        variant as if it were the only one.
        """
        shown = len(parts)
        truncated = total > shown
        if truncated:
            parts = [
                *parts,
                f"// ... and {total - shown} more definition(s) of {label} (truncated)",
            ]
        status = EvidenceStatus.AMBIGUOUS if total > 1 else EvidenceStatus.FOUND
        return EvidenceResult(
            req,
            status,
            "\n\n".join(parts),
            scope,
            exhaustive=not truncated,
            provenance=tuple(provs),
        )

    def _qualified_scope(
        self, req: EvidenceRequest, repo_name: str, lang: str
    ) -> tuple[str | None, EvidenceResult | None]:
        """For a target-qualified caller request, resolve the exact callee file.

        Returns ``(callee_file_filter, short_circuit_result)``. A name-only
        request (``target is None``) yields ``(None, None)`` — behaviour is
        unchanged. A qualified request is disambiguated against ``functions.csv``
        and FAILS CLOSED: ``AMBIGUOUS`` when the ``(name, file)`` definition is
        not unique (same-file overloads), ``INCOMPLETE_INDEX`` when it is not
        found. It never falls back to a name-only (homonym-merging) lookup.
        """
        if req.target is None:
            return None, None
        callee_file = req.target.source_ref.file if req.target.source_ref else None
        defs = 0
        if callee_file is not None:
            defs = sum(
                1
                for r in self._load_csv(repo_name, lang, "functions")
                if r.get("name") == req.subject and r.get("file") == callee_file
            )
        if defs == 1:
            return callee_file, None
        if defs > 1:
            content = (
                f"[Ambiguous symbol: {req.subject} is defined more than once in "
                f"{callee_file}; cannot bind callers to a single definition.]"
            )
            return None, EvidenceResult(
                req, EvidenceStatus.AMBIGUOUS, content, EvidenceScope.REPOSITORY_INDEX
            )
        content = f"[No unique definition of {req.subject} in {callee_file}.]"
        return None, EvidenceResult(
            req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_INDEX
        )

    def resolve_repo_unique_enclosing_function(
        self, repo_name: str, lang: str, file_path: str, line: int
    ) -> SymbolResolution:
        """Resolve ``(file_path, line)`` to its enclosing function IFF that
        function's name is unique repository-wide (P5b).

        The reachability gate needs an exact, homonym-free symbol to bind caller
        evidence to: the tree-sitter caller producer stamps one file per bare
        name, so a repeated name cannot be trusted. Fail-closed — a path escaping
        the repo, no containing function, or a name defined more than once
        anywhere in ``functions.csv`` all return a non-FOUND status with
        ``symbol=None``.
        """
        abs_file = resolve_repo_file(self.repos_dir, lang, repo_name, file_path)
        root = resolve_repo_root(self.repos_dir, lang, repo_name)
        if abs_file is None or root is None:
            return SymbolResolution(EvidenceStatus.INCOMPLETE_INDEX, detail="file not in repo")
        try:
            canonical = abs_file.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            return SymbolResolution(EvidenceStatus.INCOMPLETE_INDEX, detail="uncanonicalizable path")
        rows = self._load_csv(repo_name, lang, "functions")
        best: tuple[int, dict] | None = None
        for r in rows:
            if (r.get("file") or "").replace("\\", "/").strip() != canonical:
                continue
            try:
                start = int(r.get("start_line", 0))
                end = int(r.get("end_line", 0))
            except (TypeError, ValueError):
                continue
            if start <= line <= end and (best is None or end - start < best[0]):
                best = (end - start, r)
        if best is None:
            return SymbolResolution(EvidenceStatus.INCOMPLETE_INDEX, detail="no containing function")
        name = (best[1].get("name") or "").strip()
        if not name:
            return SymbolResolution(EvidenceStatus.INCOMPLETE_INDEX, detail="unnamed function")
        defs = sum(1 for r in rows if (r.get("name") or "").strip() == name)
        if defs != 1:
            return SymbolResolution(
                EvidenceStatus.AMBIGUOUS, detail=f"{name} defined {defs}x repository-wide"
            )
        start, end = int(best[1]["start_line"]), int(best[1]["end_line"])
        return SymbolResolution(
            EvidenceStatus.FOUND,
            SymbolRef(name, "function", SourceRef(repo_name, lang, canonical, start, end)),
        )

    def resolve_all_recorded_callers(
        self, repo_name: str, lang: str, target: SymbolRef
    ) -> RecordedCallersResult:
        """Enumerate EVERY recorded caller of ``target``, file-qualified via the
        P5a binding, with NO cap (P5b).

        Unlike the prompt-facing ``_resolve_all_callers`` (capped at 10, always
        non-exhaustive), this is the reachability signal's complete-over-recorded
        -rows enumeration. Fail-closed: an ambiguous callee scope, a malformed
        row, or a caller path escaping the repo → ``enumerated_all_rows=False``.
        An empty result is ``INCOMPLETE_INDEX`` with ``enumerated_all_rows=True``.
        """
        req = EvidenceRequest(
            EvidenceKind.ALL_CALLERS, target.name, f"all_callers:{target.name}", target=target
        )
        callee_file, short = self._qualified_scope(req, repo_name, lang)
        if short is not None:
            return RecordedCallersResult(short.status, target, detail="ambiguous callee scope")
        callers: list[CallerRef] = []
        seen: set[tuple] = set()
        for row in self._load_csv(repo_name, lang, "callers"):
            if row.get("callee_name") != target.name:
                continue
            if callee_file is not None and row.get("callee_file") != callee_file:
                continue
            rel = _safe_repo_rel(row.get("caller_file", ""))
            if rel is None:
                return RecordedCallersResult(
                    EvidenceStatus.INCOMPLETE_INDEX, target, detail="invalid caller path"
                )
            try:
                start = int(row.get("caller_start_line", ""))
                end = int(row.get("caller_end_line", ""))
            except (TypeError, ValueError):
                return RecordedCallersResult(
                    EvidenceStatus.INCOMPLETE_INDEX, target, detail="malformed caller row"
                )
            key = (rel, start, end, row.get("caller_name", ""))
            if key in seen:
                continue
            seen.add(key)
            callers.append(
                CallerRef(
                    row.get("caller_name", "") or "unknown",
                    SourceRef(repo_name, lang, rel, start, end),
                )
            )
        callers.sort(key=lambda c: (c.source_ref.file, c.source_ref.start, c.source_ref.end, c.name))
        if not callers:
            return RecordedCallersResult(
                EvidenceStatus.INCOMPLETE_INDEX, target, (), enumerated_all_rows=True,
                detail="no recorded callers",
            )
        return RecordedCallersResult(
            EvidenceStatus.FOUND, target, tuple(callers), enumerated_all_rows=True
        )

    def _locate_decl_token(
        self,
        resolved_root: Path,
        decl_file_rel: str,
        name: str,
        start_line: int,
        conv: TestScanConvention,
    ) -> tuple[str, int, int] | None:
        """Locate the single declaration-name token of ``name`` on its declaration
        line, returning ``(decl_file_rel, line, col)`` — or ``None`` if it cannot
        be uniquely located (so the scan abstains rather than mis-exclude).

        Uniqueness is required across the union of the language's declaration
        patterns: two distinct columns (or none) mean the token is ambiguous.
        """
        decl_path = resolved_root / decl_file_rel
        try:
            if not decl_path.is_file():
                return None
            lines = decl_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return None
        if start_line < 1 or start_line > len(lines):
            return None
        line = lines[start_line - 1]
        cols = {
            m.start(1)
            for pattern in conv.decl_patterns
            for m in re.finditer(pattern.format(name=re.escape(name)), line)
        }
        if len(cols) != 1:
            return None
        return (decl_file_rel, start_line, cols.pop())

    def scan_non_test_name_occurrences(
        self, repo_name: str, target: SymbolRef, lang: str | None = None
    ) -> ReferenceScanResult:
        """Scan every non-test source file of *lang* for occurrences of
        ``target.name``, excluding exactly the declaration token (P5b negative
        veto, generalized across languages for #162).

        Conservative by construction: a word-boundary textual match over-includes
        comments/strings (safe suppression) but never under-suppresses a real
        call / function-value / registration reference. Scans ALL source of the
        language's extensions (including ``vendor/``, ``tests/``, generated,
        demo, mock) — only basenames matching the language's test convention are
        excluded. ``NOT_FOUND_COMPLETE`` only after a complete zero-occurrence
        scan; an unsupported language or any read/walk/decl-location failure →
        ``INCOMPLETE_INDEX``, which makes the caller abstain.
        """
        sr = target.source_ref
        if sr is None:
            return ReferenceScanResult(EvidenceStatus.INCOMPLETE_INDEX, target, detail="no symbol ref")
        conv = scan_convention_for(lang or sr.lang)
        if conv is None:
            return ReferenceScanResult(
                EvidenceStatus.INCOMPLETE_INDEX, target, detail="unsupported language"
            )
        root = resolve_repo_root(self.repos_dir, sr.lang, repo_name)
        if root is None:
            return ReferenceScanResult(EvidenceStatus.INCOMPLETE_INDEX, target, detail="no repo root")
        try:
            resolved_root = root.resolve()
        except OSError:
            return ReferenceScanResult(EvidenceStatus.INCOMPLETE_INDEX, target, detail="unresolvable root")
        decl_pos = self._locate_decl_token(resolved_root, sr.file, target.name, sr.start, conv)
        if decl_pos is None:
            return ReferenceScanResult(
                EvidenceStatus.INCOMPLETE_INDEX, target, detail="declaration token not located"
            )
        pat = re.compile(r"(?<!\w)" + re.escape(target.name) + r"(?!\w)")
        matches: list[SourceRef] = []
        try:
            for path in sorted(resolved_root.rglob("*")):
                if not path.is_file():
                    continue
                if path.suffix.lower() not in conv.source_exts:
                    continue
                if conv.is_test_file(path.name):
                    continue
                rel = path.resolve().relative_to(resolved_root).as_posix()
                for i, line in enumerate(
                    path.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
                ):
                    for m in pat.finditer(line):
                        if (rel, i, m.start()) == decl_pos:
                            continue
                        matches.append(SourceRef(repo_name, sr.lang, rel, i, i))
        except (OSError, ValueError):
            return ReferenceScanResult(EvidenceStatus.INCOMPLETE_INDEX, target, detail="scan read error")
        if matches:
            return ReferenceScanResult(EvidenceStatus.FOUND, target, tuple(matches), scan_complete=True)
        return ReferenceScanResult(
            EvidenceStatus.NOT_FOUND_COMPLETE, target, (), scan_complete=True
        )

    def scan_non_test_go_name_occurrences(
        self, repo_name: str, target: SymbolRef
    ) -> ReferenceScanResult:
        """Go-specific wrapper retained for callers predating #162."""
        return self.scan_non_test_name_occurrences(repo_name, target, "go")

    def scan_js_route_bindings(
        self, repo_name: str, lang: str, handler_name: str, limit: int = 5
    ) -> list[tuple[SourceRef, str]]:
        """Find Express-style route registrations that mount ``handler_name``
        (#121). Returns up to ``limit`` ``(SourceRef, stripped_line)`` pairs.

        Line-level and conservative: a match needs both a route-registration
        token (``app.post(`` / ``router.use(`` ...) and a word-bounded
        reference to the handler on the same line. ``_SKIP_DIRS``
        (node_modules, vendor, dist, ...) are excluded; any walk/read failure
        returns what was found so far or ``[]`` — this is a best-effort
        retrieval aid, never an authority for absence.
        """
        if not handler_name:
            return []
        root = resolve_repo_root(self.repos_dir, lang, repo_name)
        if root is None:
            return []
        try:
            resolved_root = root.resolve()
        except OSError:
            return []
        name_pat = re.compile(r"(?<!\w)" + re.escape(handler_name) + r"(?!\w)")
        out: list[tuple[SourceRef, str]] = []
        try:
            for path in sorted(resolved_root.rglob("*")):
                if len(out) >= limit:
                    break
                if not path.is_file() or path.suffix.lower() not in _JS_SOURCE_EXTS:
                    continue
                rel_parts = path.relative_to(resolved_root).parts
                if any(p in _SKIP_DIRS for p in rel_parts[:-1]):
                    continue
                rel = path.relative_to(resolved_root).as_posix()
                for i, line in enumerate(
                    path.read_text(encoding="utf-8", errors="replace").splitlines(),
                    start=1,
                ):
                    if name_pat.search(line) and _JS_ROUTE_REGISTRATION_RE.search(line):
                        out.append((SourceRef(repo_name, lang, rel, i, i), line.strip()))
                        if len(out) >= limit:
                            break
        except (OSError, ValueError):
            return out
        return out

    def _resolve_caller(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
    ) -> EvidenceResult:
        """Resolve the first caller function for the given callee."""
        callee_name = req.subject
        callee_file, short = self._qualified_scope(req, repo_name, lang)
        if short is not None:
            return short
        rows = self._load_csv(repo_name, lang, "callers")
        for row in rows:
            if row.get("callee_name") == callee_name:
                if callee_file is not None and row.get("callee_file") != callee_file:
                    continue
                caller_file = row.get("caller_file", "")
                try:
                    start = int(row.get("caller_start_line", 0))
                    end = int(row.get("caller_end_line", 0))
                except ValueError:
                    continue
                if start > 0 and end >= start:
                    code = self._read_lines(repo_name, lang, caller_file, start, end)
                    caller_name = row.get("caller_name", "unknown")
                    content = f"// Caller function: {caller_name}\n// File: {caller_file}\n{code}"
                    return EvidenceResult(
                        req,
                        EvidenceStatus.FOUND,
                        content,
                        EvidenceScope.REPOSITORY_INDEX,
                        exhaustive=False,
                        provenance=(SourceRef(repo_name, lang, caller_file, start, end),),
                    )

        # Route-binding fallback (#121): before conceding "no callers", check
        # whether the handler is mounted as an HTTP route in a sibling file —
        # that IS the production caller the verifier keeps hedging on.
        if (lang or "").lower() in ("javascript", "typescript"):
            bindings = self.scan_js_route_bindings(repo_name, lang, callee_name)
            if bindings:
                shown = "\n".join(
                    f"//   {ref.file}:{ref.start}: {text}" for ref, text in bindings
                )
                content = (
                    f"// Route bindings found for: {callee_name} — the function is "
                    "mounted as an HTTP route handler. Requests to the route(s) "
                    "below reach it with an attacker-controlled request object:\n"
                    f"{shown}"
                )
                return EvidenceResult(
                    req,
                    EvidenceStatus.FOUND,
                    content,
                    EvidenceScope.REPOSITORY_INDEX,
                    exhaustive=False,
                    provenance=tuple(ref for ref, _ in bindings),
                )

        # Diagnostic: check if function exists but has no callers. A best-effort
        # call graph never proves "no callers", so both cases are INCOMPLETE.
        func_rows = self._load_csv(repo_name, lang, "functions")
        func_exists = any(r.get("name") == callee_name for r in func_rows)
        if func_exists:
            content = (
                f"[No callers found for: {callee_name} — function exists but has no "
                f"recorded callers in the analyzed codebase. It may be called via "
                f"function pointers, callbacks, or from code outside the analysis scope.]"
            )
        else:
            content = (
                f"[No caller found for: {callee_name} — function not found in the "
                f"analysis scope. It may be defined in an external library or header.]"
            )
        return EvidenceResult(
            req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_INDEX
        )

    def _get_caller_context(
        self,
        repo_name: str,
        lang: str,
        callee_name: str,
    ) -> str:
        return self._resolve_caller(
            EvidenceRequest(EvidenceKind.CALLER, callee_name, f"caller:{callee_name}"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_function(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_matches: int = 3,
    ) -> EvidenceResult:
        """Resolve a named function/method body (the sink/callee implementation).

        Looks up ``functions.csv`` by name and reads each match's line range. A
        name may resolve to several definitions (overloads, same method name on
        different classes); up to ``max_matches`` are returned, disambiguated by
        file in the header comment.
        """
        func_name = req.subject
        rows = self._load_csv(repo_name, lang, "functions")
        matches = [r for r in rows if r.get("name") == func_name]
        if not matches:
            content = (
                f"[Function not found: {func_name} — no definition in the analysis "
                f"scope. It may be an external library, a built-in, or a dynamically "
                f"assigned method.]"
            )
            cap = inspect_capability(
                self._context_dir(lang, repo_name), lang, EvidenceKind.FUNCTION
            )
            return EvidenceResult(
                req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
            )

        parts: list[str] = []
        provs: list[SourceRef] = []
        for row in matches[:max_matches]:
            file_path = row.get("file", "")
            try:
                start = int(row.get("start_line", 0))
                end = int(row.get("end_line", 0))
            except ValueError:
                continue
            if start > 0 and end >= start:
                code = self._read_lines(repo_name, lang, file_path, start, end)
                parts.append(f"// Function: {func_name}\n// File: {file_path}\n{code}")
                provs.append(SourceRef(repo_name, lang, file_path, start, end))

        if not parts:
            content = f"[Function metadata present for {func_name} but body could not be read.]"
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.FILE
            )
        truncated = len(matches) > max_matches
        if truncated:
            parts.append(
                f"// ... and {len(matches) - max_matches} more definition(s) of "
                f"{func_name} (truncated)"
            )
        content = "\n\n".join(parts)
        status = EvidenceStatus.AMBIGUOUS if len(matches) > 1 else EvidenceStatus.FOUND
        return EvidenceResult(
            req,
            status,
            content,
            EvidenceScope.FILE,
            exhaustive=not truncated,
            provenance=tuple(provs),
        )

    def _get_function_context(
        self,
        repo_name: str,
        lang: str,
        func_name: str,
        max_matches: int = 3,
    ) -> str:
        return self._resolve_function(
            EvidenceRequest(EvidenceKind.FUNCTION, func_name, f"function:{func_name}"),
            repo_name,
            lang,
            max_matches,
        ).prompt_content

    def _resolve_callee_bodies(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_callees: int = 5,
    ) -> EvidenceResult:
        """Resolve the BODIES of functions called by func_name (the sink helpers).

        Unlike ``callees:`` (names only), this resolves each distinct callee
        through ``functions.csv`` and returns its source. Callees with no
        definition in scope (framework/builtin calls like ``JSON.stringify`` or
        ``this.client.set``) are skipped — only locally defined helpers are
        returned, which is what matters for sink-implementation analysis.
        """
        func_name = req.subject
        rows = self._load_csv(repo_name, lang, "callers")
        seen: set[str] = set()
        callees: list[str] = []
        for row in rows:
            if row.get("caller_name") == func_name:
                callee = row.get("callee_name", "")
                if callee and callee not in seen:
                    seen.add(callee)
                    callees.append(callee)

        if not callees:
            content = f"[No callees found for: {func_name}]"
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_INDEX
            )

        func_rows = self._load_csv(repo_name, lang, "functions")
        defined = {r.get("name") for r in func_rows}

        parts: list[str] = []
        skipped: list[str] = []
        provs: list[SourceRef] = []
        for callee in callees:
            if callee not in defined:
                skipped.append(callee)
                continue
            if len(parts) >= max_callees:
                break
            child = self._resolve_function(
                EvidenceRequest(EvidenceKind.FUNCTION, callee, f"function:{callee}"),
                repo_name,
                lang,
            )
            parts.append(child.prompt_content)
            provs.extend(p for p in child.provenance if isinstance(p, SourceRef))

        if not parts:
            joined = ", ".join(skipped)
            content = (
                f"[No locally defined callees for {func_name}. Calls go to "
                f"external/builtin functions: {joined}]"
            )
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_INDEX
            )
        if skipped:
            parts.append(f"// (skipped external/builtin callees: {', '.join(skipped)})")
        content = "\n\n".join(parts)
        return EvidenceResult(
            req,
            EvidenceStatus.FOUND,
            content,
            EvidenceScope.REPOSITORY_INDEX,
            exhaustive=False,
            provenance=tuple(provs),
        )

    def _get_callee_bodies_context(
        self,
        repo_name: str,
        lang: str,
        func_name: str,
        max_callees: int = 5,
    ) -> str:
        return self._resolve_callee_bodies(
            EvidenceRequest(EvidenceKind.CALLEE_BODIES, func_name, f"callee_bodies:{func_name}"),
            repo_name,
            lang,
            max_callees,
        ).prompt_content

    def _resolve_struct(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_defs: int = 3,
    ) -> EvidenceResult:
        """Resolve a struct/class definition."""
        struct_name = req.subject
        csv_name = struct_csv_name(lang)
        rows = self._load_csv(repo_name, lang, csv_name)
        saw_name = False
        # structs.csv carries one row per MEMBER, so dedupe on the definition span.
        spans: list[tuple[str, int, int]] = []
        for row in rows:
            if row.get("name") == struct_name:
                saw_name = True
                file_path = row.get("file", "")
                try:
                    start = int(row.get("start_line", 0))
                    end = int(row.get("end_line", 0))
                except ValueError:
                    continue
                if start > 0 and end >= start and (file_path, start, end) not in spans:
                    spans.append((file_path, start, end))
        if spans:
            parts: list[str] = []
            provs: list[SourceRef] = []
            for file_path, start, end in spans[:max_defs]:
                code = self._read_lines(repo_name, lang, file_path, start, end)
                parts.append(f"// Struct/Class: {struct_name}\n// File: {file_path}\n{code}")
                provs.append(SourceRef(repo_name, lang, file_path, start, end))
            return self._definitions_result(
                req, parts, provs, len(spans), EvidenceScope.FILE, struct_name
            )

        content = (
            f"[Struct/Class not found: {struct_name} — it may be a typedef alias. "
            f"Try typedef:{struct_name} to resolve the underlying type.]"
        )
        if saw_name:
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.FILE
            )
        cap = inspect_capability(
            self._context_dir(lang, repo_name), lang, EvidenceKind.STRUCT
        )
        return EvidenceResult(
            req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
        )

    def _get_struct_context(
        self,
        repo_name: str,
        lang: str,
        struct_name: str,
    ) -> str:
        return self._resolve_struct(
            EvidenceRequest(EvidenceKind.STRUCT, struct_name, f"struct:{struct_name}"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_global(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_defs: int = 3,
    ) -> EvidenceResult:
        """Resolve a global variable definition."""
        var_name = req.subject
        rows = self._load_csv(repo_name, lang, "globals")
        defs: list[tuple[str, int, int, str]] = []
        for row in rows:
            if row.get("name") == var_name:
                file_path = row.get("file", "")
                try:
                    start = int(row.get("start_line", 0))
                    end = int(row.get("end_line", start))
                except ValueError:
                    continue
                key = (file_path, start, end, row.get("type", "unknown"))
                if key not in defs:
                    defs.append(key)
        if defs:
            parts: list[str] = []
            provs: list[SourceRef] = []
            for file_path, start, end, var_type in defs[:max_defs]:
                code = self._read_lines(repo_name, lang, file_path, start, end)
                parts.append(
                    f"// Global: {var_name} (type: {var_type})\n// File: {file_path}\n{code}"
                )
                provs.append(SourceRef(repo_name, lang, file_path, start, end))
            return self._definitions_result(
                req, parts, provs, len(defs), EvidenceScope.FILE, var_name
            )

        content = f"[Global variable not found: {var_name}]"
        cap = inspect_capability(
            self._context_dir(lang, repo_name), lang, EvidenceKind.GLOBAL
        )
        return EvidenceResult(
            req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
        )

    def _get_global_context(
        self,
        repo_name: str,
        lang: str,
        var_name: str,
    ) -> str:
        return self._resolve_global(
            EvidenceRequest(EvidenceKind.GLOBAL, var_name, f"global:{var_name}"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_macro(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_defs: int = 3,
    ) -> EvidenceResult:
        """Resolve a macro definition."""
        macro_name = req.subject
        rows = self._load_csv(repo_name, lang, "macros")
        defs: list[tuple[str, str, str]] = []
        for row in rows:
            if row.get("name") == macro_name:
                key = (row.get("file", ""), row.get("line", "?"), row.get("body", ""))
                if key not in defs:
                    defs.append(key)
        if defs:
            parts = [
                f"// Macro: {macro_name}\n// File: {file_path}:{line}\n#define {macro_name} {body}"
                for file_path, line, body in defs[:max_defs]
            ]
            return self._definitions_result(
                req, parts, [], len(defs), EvidenceScope.FILE, macro_name
            )

        content = f"[Macro not found: {macro_name}]"
        cap = inspect_capability(
            self._context_dir(lang, repo_name), lang, EvidenceKind.MACRO
        )
        return EvidenceResult(
            req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
        )

    def _get_macro_context(
        self,
        repo_name: str,
        lang: str,
        macro_name: str,
    ) -> str:
        return self._resolve_macro(
            EvidenceRequest(EvidenceKind.MACRO, macro_name, f"macro:{macro_name}"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_callees(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
    ) -> EvidenceResult:
        """Resolve the list of unique functions called by func_name."""
        func_name = req.subject
        rows = self._load_csv(repo_name, lang, "callers")
        seen: set[str] = set()
        callees: list[str] = []
        for row in rows:
            if row.get("caller_name") == func_name:
                callee = row.get("callee_name", "")
                if callee and callee not in seen:
                    seen.add(callee)
                    callees.append(callee)

        if not callees:
            content = f"[No callees found for: {func_name}]"
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_INDEX
            )
        content = f"// Functions called by {func_name}:\n" + "\n".join(
            f"  - {c}" for c in callees
        )
        return EvidenceResult(
            req,
            EvidenceStatus.FOUND,
            content,
            EvidenceScope.REPOSITORY_INDEX,
            exhaustive=False,
        )

    def _get_callees_context(
        self,
        repo_name: str,
        lang: str,
        func_name: str,
    ) -> str:
        return self._resolve_callees(
            EvidenceRequest(EvidenceKind.CALLEES, func_name, f"callees:{func_name}"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_all_callers(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_callers: int = 10,
    ) -> EvidenceResult:
        """Resolve source code for ALL callers of callee_name (up to max_callers)."""
        callee_name = req.subject
        callee_file, short = self._qualified_scope(req, repo_name, lang)
        if short is not None:
            return short
        rows = self._load_csv(repo_name, lang, "callers")
        # Deduplicate by (caller_name, caller_file, caller_start_line)
        seen: set[tuple] = set()
        caller_rows: list[dict] = []
        for row in rows:
            if row.get("callee_name") != callee_name:
                continue
            if callee_file is not None and row.get("callee_file") != callee_file:
                continue
            key = (row.get("caller_name"), row.get("caller_file"), row.get("caller_start_line"))
            if key not in seen:
                seen.add(key)
                caller_rows.append(row)
            if len(caller_rows) >= max_callers:
                break

        if not caller_rows:
            content = f"[No callers found for: {callee_name}]"
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_INDEX
            )

        parts: list[str] = []
        provs: list[SourceRef] = []
        for row in caller_rows:
            caller_file = row.get("caller_file", "")
            caller_name = row.get("caller_name", "unknown")
            try:
                start = int(row.get("caller_start_line", 0))
                end = int(row.get("caller_end_line", 0))
            except ValueError:
                continue
            if start > 0 and end >= start:
                code = self._read_lines(repo_name, lang, caller_file, start, end)
                parts.append(f"// Caller: {caller_name}\n// File: {caller_file}\n{code}")
                provs.append(SourceRef(repo_name, lang, caller_file, start, end))

        if not parts:
            content = f"[Could not read source for callers of: {callee_name}]"
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_INDEX
            )
        content = "\n\n".join(parts)
        return EvidenceResult(
            req,
            EvidenceStatus.FOUND,
            content,
            EvidenceScope.REPOSITORY_INDEX,
            exhaustive=False,
            provenance=tuple(provs),
        )

    def _get_all_callers_context(
        self,
        repo_name: str,
        lang: str,
        callee_name: str,
        max_callers: int = 10,
    ) -> str:
        return self._resolve_all_callers(
            EvidenceRequest(EvidenceKind.ALL_CALLERS, callee_name, f"all_callers:{callee_name}"),
            repo_name,
            lang,
            max_callers,
        ).prompt_content

    def _resolve_typedef(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_defs: int = 3,
    ) -> EvidenceResult:
        """Resolve a typedef/type alias definition."""
        type_name = req.subject
        rows = self._load_csv(repo_name, lang, "typedefs")
        defs: list[tuple[str, str, str]] = []
        for row in rows:
            if row.get("name") == type_name:
                key = (row.get("file", ""), row.get("line", "?"), row.get("underlying_type", ""))
                if key not in defs:
                    defs.append(key)
        if defs:
            parts = [
                f"// Typedef: {type_name} = {underlying}\n// File: {file_path}:{line}"
                for file_path, line, underlying in defs[:max_defs]
            ]
            return self._definitions_result(
                req, parts, [], len(defs), EvidenceScope.FILE, type_name
            )

        content = f"[Typedef not found: {type_name}]"
        cap = inspect_capability(
            self._context_dir(lang, repo_name), lang, EvidenceKind.TYPEDEF
        )
        return EvidenceResult(
            req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
        )

    def _get_typedef_context(
        self,
        repo_name: str,
        lang: str,
        type_name: str,
    ) -> str:
        return self._resolve_typedef(
            EvidenceRequest(EvidenceKind.TYPEDEF, type_name, f"typedef:{type_name}"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_enum(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
    ) -> EvidenceResult:
        """Resolve an enum definition with enumerator values."""
        enum_name = req.subject
        rows = self._load_csv(repo_name, lang, "enums")
        matches = [r for r in rows if r.get("name") == enum_name]
        if not matches:
            content = f"[Enum not found: {enum_name}]"
            cap = inspect_capability(
                self._context_dir(lang, repo_name), lang, EvidenceKind.ENUM
            )
            return EvidenceResult(
                req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
            )

        parts: list[str] = []
        file_path = matches[0].get("file", "")
        parts.append(f"// Enum: {enum_name}")
        parts.append(f"// File: {file_path}")
        for row in matches:
            member = row.get("member", "")
            value = row.get("value", "")
            if member:
                parts.append(f"  {member} = {value}" if value else f"  {member}")

        content = "\n".join(parts)
        return EvidenceResult(req, EvidenceStatus.FOUND, content, EvidenceScope.FILE)

    def _get_enum_context(
        self,
        repo_name: str,
        lang: str,
        enum_name: str,
    ) -> str:
        return self._resolve_enum(
            EvidenceRequest(EvidenceKind.ENUM, enum_name, f"enum:{enum_name}"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_free_sites(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_sites: int = 20,
    ) -> EvidenceResult:
        """Resolve every free/delete/destructor call site for a pointer expression.

        Loaded from `free_sites.csv` (extracted by config/queries/tools/cpp/free_sites.ql).
        Match is exact on `pointer_name`, with a fallback to substring match — useful
        for cases like the LLM asking for `obj->p` when the CSV row says `p`.
        """
        pointer_name = req.subject
        rows = self._load_csv(repo_name, lang, "free_sites")
        if not rows:
            content = (
                "[No free_sites data for repo (free_sites.csv missing). "
                "Run `vuln-hunter-x prepare --skip-clone --force` to extract.]"
            )
            cap = inspect_capability(
                self._context_dir(lang, repo_name), lang, EvidenceKind.FREE_SITES
            )
            return EvidenceResult(
                req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
            )

        # Exact match first
        exact = [r for r in rows if r.get("pointer_name", "") == pointer_name]
        used_fallback = False
        # Fallback: substring (handles `obj->p` vs `p`, `&buf` vs `buf`)
        if not exact:
            needle = pointer_name.strip().lstrip("&*")
            exact = [r for r in rows if needle and needle in r.get("pointer_name", "")]
            used_fallback = bool(exact)

        if not exact:
            content = f"[No free/delete sites found for pointer: {pointer_name!r}]"
            cap = inspect_capability(
                self._context_dir(lang, repo_name), lang, EvidenceKind.FREE_SITES
            )
            return EvidenceResult(
                req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
            )

        parts: list[str] = [f"// Free/delete sites for: {pointer_name}"]
        for row in exact[:max_sites]:
            kind = row.get("free_kind", "free")
            in_func = row.get("in_function", "?")
            file_ = row.get("file", "?")
            line = row.get("line", "?")
            ptr = row.get("pointer_name", pointer_name)
            parts.append(f"  {file_}:{line}  in {in_func}()  -- {kind}({ptr})")

        truncated = len(exact) > max_sites
        if truncated:
            parts.append(f"  ... and {len(exact) - max_sites} more (truncated)")

        content = "\n".join(parts)
        status = EvidenceStatus.AMBIGUOUS if used_fallback else EvidenceStatus.FOUND
        return EvidenceResult(
            req, status, content, EvidenceScope.REPOSITORY_INDEX, exhaustive=not truncated
        )

    def _get_free_sites_context(
        self,
        repo_name: str,
        lang: str,
        pointer_name: str,
        max_sites: int = 20,
    ) -> str:
        return self._resolve_free_sites(
            EvidenceRequest(EvidenceKind.FREE_SITES, pointer_name, f"free_sites:{pointer_name}"),
            repo_name,
            lang,
            max_sites,
        ).prompt_content

    def _resolve_destructor(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
    ) -> EvidenceResult:
        """Resolve destructor / cleanup-method bodies for a class or struct.

        Loaded from `destructors.csv` (extracted by destructors.ql). One type
        may have multiple cleanup methods (~T plus a custom .release()); all
        are returned, separated by a blank line.
        """
        type_name = req.subject
        rows = self._load_csv(repo_name, lang, "destructors")
        if not rows:
            content = (
                "[No destructors data for repo (destructors.csv missing). "
                "Run `vuln-hunter-x prepare --skip-clone --force` to extract.]"
            )
            cap = inspect_capability(
                self._context_dir(lang, repo_name), lang, EvidenceKind.DESTRUCTOR
            )
            return EvidenceResult(
                req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
            )

        matches = [r for r in rows if r.get("type_name", "") == type_name]
        if not matches:
            content = f"[No destructor / cleanup method found for type: {type_name!r}]"
            cap = inspect_capability(
                self._context_dir(lang, repo_name), lang, EvidenceKind.DESTRUCTOR
            )
            return EvidenceResult(
                req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
            )

        parts: list[str] = []
        provs: list[SourceRef] = []
        for row in matches:
            method = row.get("method_name", "?")
            file_ = row.get("file", "")
            try:
                start = int(row.get("start_line", 0))
                end = int(row.get("end_line", 0))
            except ValueError:
                continue
            if start <= 0 or end < start:
                continue
            body = self._read_lines(repo_name, lang, file_, start, end)
            parts.append(
                f"// Destructor / cleanup: {type_name}::{method}\n// File: {file_}\n{body}"
            )
            provs.append(SourceRef(repo_name, lang, file_, start, end))

        if parts:
            content = "\n\n".join(parts)
            return EvidenceResult(
                req,
                EvidenceStatus.FOUND,
                content,
                EvidenceScope.FILE,
                provenance=tuple(provs),
            )
        content = f"[Destructor metadata present for {type_name} but bodies could not be read.]"
        return EvidenceResult(
            req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.FILE
        )

    def _get_destructor_context(
        self,
        repo_name: str,
        lang: str,
        type_name: str,
    ) -> str:
        return self._resolve_destructor(
            EvidenceRequest(EvidenceKind.DESTRUCTOR, type_name, f"destructor:{type_name}"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_field_writes(
        self,
        req: EvidenceRequest,
        repo_name: str,
        lang: str,
        max_sites: int = 20,
    ) -> EvidenceResult:
        """Resolve every write site for a struct/class field expression.

        Argument format is `Type.field` (e.g. `Connection.handle`). Falls back
        to a substring match if the exact key is not found, so the LLM can
        ask `field_writes:handle` and still get useful results.
        """
        type_field = req.subject
        rows = self._load_csv(repo_name, lang, "field_writes")
        if not rows:
            content = (
                "[No field_writes data for repo (field_writes.csv missing). "
                "Run `vuln-hunter-x prepare --skip-clone --force` to extract.]"
            )
            cap = inspect_capability(
                self._context_dir(lang, repo_name), lang, EvidenceKind.FIELD_WRITES
            )
            return EvidenceResult(
                req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
            )

        exact = [r for r in rows if r.get("type_field", "") == type_field]
        used_fallback = False
        if not exact:
            needle = type_field.strip()
            exact = [r for r in rows if needle and needle in r.get("type_field", "")]
            used_fallback = bool(exact)

        if not exact:
            content = f"[No write sites found for field: {type_field!r}]"
            cap = inspect_capability(
                self._context_dir(lang, repo_name), lang, EvidenceKind.FIELD_WRITES
            )
            return EvidenceResult(
                req, self._absence_status(cap), content, EvidenceScope.REPOSITORY_INDEX
            )

        parts: list[str] = [f"// Write sites for: {type_field}"]
        for row in exact[:max_sites]:
            in_func = row.get("in_function", "?")
            file_ = row.get("file", "?")
            line = row.get("line", "?")
            tf = row.get("type_field", type_field)
            parts.append(f"  {file_}:{line}  in {in_func}()  -- write to {tf}")

        truncated = len(exact) > max_sites
        if truncated:
            parts.append(f"  ... and {len(exact) - max_sites} more (truncated)")

        content = "\n".join(parts)
        status = EvidenceStatus.AMBIGUOUS if used_fallback else EvidenceStatus.FOUND
        return EvidenceResult(
            req, status, content, EvidenceScope.REPOSITORY_INDEX, exhaustive=not truncated
        )

    def _get_field_writes_context(
        self,
        repo_name: str,
        lang: str,
        type_field: str,
        max_sites: int = 20,
    ) -> str:
        return self._resolve_field_writes(
            EvidenceRequest(EvidenceKind.FIELD_WRITES, type_field, f"field_writes:{type_field}"),
            repo_name,
            lang,
            max_sites,
        ).prompt_content

    def _repo_root(self, lang: str, repo_name: str) -> Path | None:
        """Resolve the on-disk source root for a repo (symlink-tolerant).

        Fail-closed and repo-scoped (#156): never falls back to a sibling repo.
        """
        return resolve_repo_root(self.repos_dir, lang, repo_name)

    def _grep_repo(
        self,
        root: Path,
        markers: tuple[str, ...],
        exts: tuple[str, ...],
        max_hits: int = 3,
        window: int = 8,
        max_files: int = 6000,
    ) -> tuple[list[str], _GrepBounds]:
        """Return windowed snippets around the first marker hit per matching file.

        Walks ``root`` with os.walk so heavy directories (node_modules, dist)
        are pruned rather than iterated. Bounded by ``max_files`` scanned and
        ``max_hits`` returned so a large repo can't stall verification. Also
        reports whether a bound stopped the search early (P2a) — a bound-out
        search is incomplete and must not read as "marker absent".
        """
        results: list[str] = []
        scanned = 0
        bounds = _GrepBounds()
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
            for fname in filenames:
                if len(results) >= max_hits:
                    bounds.hit_max_hits = True
                    return results, bounds
                if scanned >= max_files:
                    bounds.hit_max_files = True
                    return results, bounds
                if not fname.endswith(exts):
                    continue
                fpath = Path(dirpath) / fname
                scanned += 1
                try:
                    text = fpath.read_text(errors="replace")
                except OSError:
                    continue
                if not any(m in text for m in markers):
                    continue
                lines = text.splitlines()
                for i, line in enumerate(lines):
                    if any(m in line for m in markers):
                        s = max(0, i - window)
                        e = min(len(lines), i + window + 1)
                        try:
                            rel = fpath.relative_to(root)
                        except ValueError:
                            rel = fpath.name
                        snippet = "\n".join(lines[s:e])
                        results.append(f"// File: {rel}:{i + 1}\n{snippet}")
                        break  # one window per file is enough
        return results, bounds

    def _resolve_framework_sanitizers(
        self, req: EvidenceRequest, repo_name: str, lang: str
    ) -> EvidenceResult:
        """Grep the repo for a global input-validation boundary.

        For DTO/request-sourced taint (prototype pollution, mass-assignment),
        the verdict hinges on whether a framework pipe strips or rejects
        dangerous keys before the value reaches the sink. The dominant case is
        NestJS ``app.useGlobalPipes(new ValidationPipe({ whitelist: true,
        forbidNonWhitelisted: true }))`` in the bootstrap, which is upstream of
        every service and therefore never visible in the sink's function body.
        """
        root = self._repo_root(lang, repo_name)
        if root is None:
            content = "[Repo source not available for framework-sanitizer lookup]"
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_SOURCE
            )
        markers = ("useGlobalPipes", "ValidationPipe", "forbidNonWhitelisted")
        hits, bounds = self._grep_repo(root, markers, exts=(".ts", ".js", ".mjs"))
        if not hits:
            content = (
                "[No global input-validation pipe found (e.g. NestJS "
                "useGlobalPipes(new ValidationPipe(...))). Request input may be "
                "unsanitized at the framework boundary — judge the sink on its "
                "own merits.]"
            )
            # A complete-under-bounds miss is resolving (markers absent); a
            # bound-out search proves nothing.
            status = (
                EvidenceStatus.INCOMPLETE_INDEX
                if bounds.hit_max_files
                else EvidenceStatus.NOT_FOUND_COMPLETE
            )
            return EvidenceResult(req, status, content, EvidenceScope.REPOSITORY_SOURCE)
        content = (
            "// Framework input-validation boundary (upstream sanitizer).\n"
            "// If whitelist/forbidNonWhitelisted is enabled, undeclared keys "
            "like __proto__/constructor are stripped or rejected before the "
            "sink runs.\n\n" + "\n\n".join(hits)
        )
        return EvidenceResult(
            req,
            EvidenceStatus.FOUND,
            content,
            EvidenceScope.REPOSITORY_SOURCE,
            exhaustive=not bounds.hit_max_hits,
        )

    def _get_framework_sanitizers(self, repo_name: str, lang: str) -> str:
        return self._resolve_framework_sanitizers(
            EvidenceRequest(EvidenceKind.FRAMEWORK_SANITIZERS, "", "framework_sanitizers:"),
            repo_name,
            lang,
        ).prompt_content

    def _resolve_framework_guards(
        self, req: EvidenceRequest, repo_name: str, lang: str
    ) -> EvidenceResult:
        """Grep the repo for global/route authentication guards.

        For "missing authentication" findings the decisive context is whether
        the route is covered by a guard — a global ``APP_GUARD`` provider,
        ``app.useGlobalGuards(...)``, a class/method ``@UseGuards(...)``, or an
        explicit ``@Public()`` opt-out. None of these live in the flagged
        handler body, so the verifier otherwise assumes the route is open.
        """
        root = self._repo_root(lang, repo_name)
        if root is None:
            content = "[Repo source not available for framework-guard lookup]"
            return EvidenceResult(
                req, EvidenceStatus.INCOMPLETE_INDEX, content, EvidenceScope.REPOSITORY_SOURCE
            )
        markers = ("APP_GUARD", "useGlobalGuards", "@UseGuards", "@Public")
        hits, bounds = self._grep_repo(root, markers, exts=(".ts", ".js", ".mjs"), max_hits=6)
        if not hits:
            content = (
                "[No global or route auth guards found (e.g. NestJS APP_GUARD, "
                "useGlobalGuards, @UseGuards, @Public). The route may genuinely "
                "be unauthenticated.]"
            )
            status = (
                EvidenceStatus.INCOMPLETE_INDEX
                if bounds.hit_max_files
                else EvidenceStatus.NOT_FOUND_COMPLETE
            )
            return EvidenceResult(req, status, content, EvidenceScope.REPOSITORY_SOURCE)
        content = (
            "// Framework authentication guards. A global APP_GUARD/useGlobalGuards "
            "protects ALL routes unless they carry @Public(); @UseGuards protects "
            "the decorated controller/handler.\n\n" + "\n\n".join(hits)
        )
        return EvidenceResult(
            req,
            EvidenceStatus.FOUND,
            content,
            EvidenceScope.REPOSITORY_SOURCE,
            exhaustive=not bounds.hit_max_hits,
        )

    def _get_framework_guards(self, repo_name: str, lang: str) -> str:
        return self._resolve_framework_guards(
            EvidenceRequest(EvidenceKind.FRAMEWORK_GUARDS, "", "framework_guards:"),
            repo_name,
            lang,
        ).prompt_content
