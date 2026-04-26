# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""CSV-based context provider for on-demand context expansion."""

from __future__ import annotations

import csv
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


class ContextProvider:
    """
    Provides additional context on-demand using pre-extracted CSV files.

    Context CSVs live under output/<lang>/<repo_name>/context/.
    Supports:
    - caller:function_name - Get the calling function's code
    - struct:type_name - Get struct/class definition
    - global:var_name - Get global variable definition
    - macro:MACRO_NAME - Get macro definition
    - callees:function_name - Get list of functions called by function_name
    - all_callers:function_name - Get ALL callers of a function (up to 10)
    - typedef:type_name - Get typedef or type alias definition
    - enum:enum_name - Get enum definition with enumerator values
    - free_sites:pointer_name - Get every free()/delete/destructor call site for
      a pointer expression across the whole repo (C/C++ only)
    - destructor:type_name - Get destructor / cleanup-method body for a class
      or struct (C/C++ only) — useful for RAII / lifetime rules
    - field_writes:Type.field - Get every write site for a struct/class field
      (C/C++ only) — catches shared-state UAF / TOCTOU patterns
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

    def _context_dir(self, lang: str, repo_name: str) -> Path:
        """Return context directory for a repo: output/<lang>/<repo_name>/context."""
        return self.output_dir / lang / repo_name / "context"

    def clear_cache(self) -> None:
        """Clear the CSV cache."""
        self._cache.clear()

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
            else:
                code = f"[Unknown context type: {ctx_type}]"

            results[request] = code

        return results

    def has_context_for_repo(self, repo_name: str, lang: str) -> bool:
        """Check if context CSV files exist for a repository."""
        repo_context_dir = self._context_dir(lang, repo_name)
        return repo_context_dir.is_dir()

    def _load_csv(self, repo_name: str, lang: str, csv_name: str) -> list[dict]:
        """Load a CSV file from the context directory."""
        cache_key = f"{lang}/{repo_name}/{csv_name}"
        if cache_key in self._cache:
            return self._cache[cache_key]

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

    def _read_lines(
        self,
        repo_name: str,
        lang: str,
        file_path: str,
        start: int,
        end: int,
    ) -> str:
        """Read specific lines from a source file."""
        base_dir = (self.repos_dir / lang).resolve()
        full_path = self.repos_dir / lang / repo_name / file_path
        if not full_path.is_file():
            # Try without repo_name in path
            lang_dir = self.repos_dir / lang
            if lang_dir.is_dir():
                for repo_dir in lang_dir.iterdir():
                    candidate = repo_dir / file_path
                    if candidate.is_file():
                        full_path = candidate
                        break

        # Guard against path traversal
        try:
            resolved = full_path.resolve()
            if not resolved.is_relative_to(base_dir):
                logger.warning("Path traversal blocked: %s escapes %s", file_path, base_dir)
                return f"[Access denied: {file_path}]"
        except (ValueError, OSError):
            return f"[Invalid path: {file_path}]"

        if not full_path.is_file():
            return f"[File not found: {file_path}]"

        try:
            lines = full_path.read_text(errors="replace").splitlines()
            start_idx = max(0, start - 1)
            end_idx = min(len(lines), end)
            return "\n".join(lines[start_idx:end_idx])
        except Exception as e:
            return f"[Error reading file: {e}]"

    def _get_caller_context(
        self,
        repo_name: str,
        lang: str,
        callee_name: str,
    ) -> str:
        """Get the first caller function for the given callee."""
        rows = self._load_csv(repo_name, lang, "callers")
        for row in rows:
            if row.get("callee_name") == callee_name:
                caller_file = row.get("caller_file", "")
                try:
                    start = int(row.get("caller_start_line", 0))
                    end = int(row.get("caller_end_line", 0))
                except ValueError:
                    continue
                if start > 0 and end >= start:
                    code = self._read_lines(repo_name, lang, caller_file, start, end)
                    caller_name = row.get("caller_name", "unknown")
                    return f"// Caller function: {caller_name}\n// File: {caller_file}\n{code}"

        # Diagnostic: check if function exists but has no callers
        func_rows = self._load_csv(repo_name, lang, "functions")
        func_exists = any(r.get("name") == callee_name for r in func_rows)
        if func_exists:
            return (
                f"[No callers found for: {callee_name} — function exists but has no "
                f"recorded callers in the analyzed codebase. It may be called via "
                f"function pointers, callbacks, or from code outside the analysis scope.]"
            )
        return (
            f"[No caller found for: {callee_name} — function not found in the "
            f"analysis scope. It may be defined in an external library or header.]"
        )

    def _get_struct_context(
        self,
        repo_name: str,
        lang: str,
        struct_name: str,
    ) -> str:
        """Get struct/class definition."""
        csv_name = "classes" if lang in ("python", "javascript") else "structs"
        rows = self._load_csv(repo_name, lang, csv_name)
        for row in rows:
            if row.get("name") == struct_name:
                file_path = row.get("file", "")
                try:
                    start = int(row.get("start_line", 0))
                    end = int(row.get("end_line", 0))
                except ValueError:
                    continue
                if start > 0 and end >= start:
                    code = self._read_lines(repo_name, lang, file_path, start, end)
                    return f"// Struct/Class: {struct_name}\n// File: {file_path}\n{code}"

        return (
            f"[Struct/Class not found: {struct_name} — it may be a typedef alias. "
            f"Try typedef:{struct_name} to resolve the underlying type.]"
        )

    def _get_global_context(
        self,
        repo_name: str,
        lang: str,
        var_name: str,
    ) -> str:
        """Get global variable definition."""
        rows = self._load_csv(repo_name, lang, "globals")
        for row in rows:
            if row.get("name") == var_name:
                file_path = row.get("file", "")
                try:
                    start = int(row.get("start_line", 0))
                    end = int(row.get("end_line", start))
                except ValueError:
                    continue
                var_type = row.get("type", "unknown")
                code = self._read_lines(repo_name, lang, file_path, start, end)
                return f"// Global: {var_name} (type: {var_type})\n// File: {file_path}\n{code}"

        return f"[Global variable not found: {var_name}]"

    def _get_macro_context(
        self,
        repo_name: str,
        lang: str,
        macro_name: str,
    ) -> str:
        """Get macro definition."""
        rows = self._load_csv(repo_name, lang, "macros")
        for row in rows:
            if row.get("name") == macro_name:
                file_path = row.get("file", "")
                line = row.get("line", "?")
                body = row.get("body", "")
                return f"// Macro: {macro_name}\n// File: {file_path}:{line}\n#define {macro_name} {body}"

        return f"[Macro not found: {macro_name}]"

    def _get_callees_context(
        self,
        repo_name: str,
        lang: str,
        func_name: str,
    ) -> str:
        """Get the list of unique functions called by func_name."""
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
            return f"[No callees found for: {func_name}]"
        return f"// Functions called by {func_name}:\n" + "\n".join(f"  - {c}" for c in callees)

    def _get_all_callers_context(
        self,
        repo_name: str,
        lang: str,
        callee_name: str,
        max_callers: int = 10,
    ) -> str:
        """Get source code for ALL callers of callee_name (up to max_callers)."""
        rows = self._load_csv(repo_name, lang, "callers")
        # Deduplicate by (caller_name, caller_file, caller_start_line)
        seen: set[tuple] = set()
        caller_rows: list[dict] = []
        for row in rows:
            if row.get("callee_name") != callee_name:
                continue
            key = (row.get("caller_name"), row.get("caller_file"), row.get("caller_start_line"))
            if key not in seen:
                seen.add(key)
                caller_rows.append(row)
            if len(caller_rows) >= max_callers:
                break

        if not caller_rows:
            return f"[No callers found for: {callee_name}]"

        parts: list[str] = []
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

        if not parts:
            return f"[Could not read source for callers of: {callee_name}]"
        return "\n\n".join(parts)

    def _get_typedef_context(
        self,
        repo_name: str,
        lang: str,
        type_name: str,
    ) -> str:
        """Get typedef/type alias definition."""
        rows = self._load_csv(repo_name, lang, "typedefs")
        for row in rows:
            if row.get("name") == type_name:
                file_path = row.get("file", "")
                line = row.get("line", "?")
                underlying = row.get("underlying_type", "")
                return (
                    f"// Typedef: {type_name} = {underlying}\n"
                    f"// File: {file_path}:{line}"
                )

        return f"[Typedef not found: {type_name}]"

    def _get_enum_context(
        self,
        repo_name: str,
        lang: str,
        enum_name: str,
    ) -> str:
        """Get enum definition with enumerator values."""
        rows = self._load_csv(repo_name, lang, "enums")
        matches = [r for r in rows if r.get("name") == enum_name]
        if not matches:
            return f"[Enum not found: {enum_name}]"

        parts: list[str] = []
        file_path = matches[0].get("file", "")
        parts.append(f"// Enum: {enum_name}")
        parts.append(f"// File: {file_path}")
        for row in matches:
            member = row.get("member", "")
            value = row.get("value", "")
            if member:
                parts.append(f"  {member} = {value}" if value else f"  {member}")

        return "\n".join(parts)

    def _get_free_sites_context(
        self,
        repo_name: str,
        lang: str,
        pointer_name: str,
        max_sites: int = 20,
    ) -> str:
        """Get every free/delete/destructor call site for a pointer expression.

        Loaded from `free_sites.csv` (extracted by config/queries/tools/cpp/free_sites.ql).
        Match is exact on `pointer_name`, with a fallback to substring match — useful
        for cases like the LLM asking for `obj->p` when the CSV row says `p`.
        """
        rows = self._load_csv(repo_name, lang, "free_sites")
        if not rows:
            return (
                f"[No free_sites data for repo (free_sites.csv missing). "
                f"Run `vuln-hunter-x prepare --skip-clone --force` to extract.]"
            )

        # Exact match first
        exact = [r for r in rows if r.get("pointer_name", "") == pointer_name]
        # Fallback: substring (handles `obj->p` vs `p`, `&buf` vs `buf`)
        if not exact:
            needle = pointer_name.strip().lstrip("&*")
            exact = [r for r in rows if needle and needle in r.get("pointer_name", "")]

        if not exact:
            return f"[No free/delete sites found for pointer: {pointer_name!r}]"

        parts: list[str] = [f"// Free/delete sites for: {pointer_name}"]
        for row in exact[:max_sites]:
            kind = row.get("free_kind", "free")
            in_func = row.get("in_function", "?")
            file_ = row.get("file", "?")
            line = row.get("line", "?")
            ptr = row.get("pointer_name", pointer_name)
            parts.append(f"  {file_}:{line}  in {in_func}()  -- {kind}({ptr})")

        if len(exact) > max_sites:
            parts.append(f"  ... and {len(exact) - max_sites} more (truncated)")

        return "\n".join(parts)

    def _get_destructor_context(
        self,
        repo_name: str,
        lang: str,
        type_name: str,
    ) -> str:
        """Get destructor / cleanup-method bodies for a class or struct.

        Loaded from `destructors.csv` (extracted by destructors.ql). One type
        may have multiple cleanup methods (~T plus a custom .release()); all
        are returned, separated by a blank line.
        """
        rows = self._load_csv(repo_name, lang, "destructors")
        if not rows:
            return (
                f"[No destructors data for repo (destructors.csv missing). "
                f"Run `vuln-hunter-x prepare --skip-clone --force` to extract.]"
            )

        matches = [r for r in rows if r.get("type_name", "") == type_name]
        if not matches:
            return f"[No destructor / cleanup method found for type: {type_name!r}]"

        parts: list[str] = []
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

        return "\n\n".join(parts) if parts else (
            f"[Destructor metadata present for {type_name} but bodies could not be read.]"
        )

    def _get_field_writes_context(
        self,
        repo_name: str,
        lang: str,
        type_field: str,
        max_sites: int = 20,
    ) -> str:
        """Get every write site for a struct/class field expression.

        Argument format is `Type.field` (e.g. `Connection.handle`). Falls back
        to a substring match if the exact key is not found, so the LLM can
        ask `field_writes:handle` and still get useful results.
        """
        rows = self._load_csv(repo_name, lang, "field_writes")
        if not rows:
            return (
                f"[No field_writes data for repo (field_writes.csv missing). "
                f"Run `vuln-hunter-x prepare --skip-clone --force` to extract.]"
            )

        exact = [r for r in rows if r.get("type_field", "") == type_field]
        if not exact:
            needle = type_field.strip()
            exact = [r for r in rows if needle and needle in r.get("type_field", "")]

        if not exact:
            return f"[No write sites found for field: {type_field!r}]"

        parts: list[str] = [f"// Write sites for: {type_field}"]
        for row in exact[:max_sites]:
            in_func = row.get("in_function", "?")
            file_ = row.get("file", "?")
            line = row.get("line", "?")
            tf = row.get("type_field", type_field)
            parts.append(f"  {file_}:{line}  in {in_func}()  -- write to {tf}")

        if len(exact) > max_sites:
            parts.append(f"  ... and {len(exact) - max_sites} more (truncated)")

        return "\n".join(parts)
