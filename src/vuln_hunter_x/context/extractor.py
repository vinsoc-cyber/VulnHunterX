# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Heuristic-based code context extraction."""

from __future__ import annotations

import re
from pathlib import Path

from vuln_hunter_x.core.types import CodeContext, Finding


class ContextExtractor:
    """
    Extracts function/scope context from source files using heuristics.

    Uses pattern matching and bracket counting to find enclosing function
    boundaries. Includes caching for improved performance.
    """

    # Patterns for function definitions by language
    _FUNCTION_PATTERNS: dict[str, list[re.Pattern]] = {
        "c": [
            re.compile(r"^[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{?\s*$", re.MULTILINE),
        ],
        "cpp": [
            re.compile(
                r"^[\w\s\*:&<>]+\s+(\w+)\s*\([^)]*\)\s*(?:const|override|final)?\s*\{?\s*$",
                re.MULTILINE,
            ),
        ],
        "python": [
            re.compile(r"^\s*def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*$", re.MULTILINE),
            re.compile(r"^\s*async\s+def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*$", re.MULTILINE),
        ],
        "javascript": [
            re.compile(r"^\s*(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{?\s*$", re.MULTILINE),
            re.compile(
                r"^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>", re.MULTILINE
            ),
            re.compile(r"^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{", re.MULTILINE),
        ],
        "java": [
            re.compile(
                r"^\s*(?:public|private|protected|static|final|abstract|synchronized|native|\s)*"
                r"[\w<>\[\],\s]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{?\s*$",
                re.MULTILINE,
            ),
        ],
        "go": [
            re.compile(r"^\s*func\s+(?:\(\w+\s+\*?\w+\)\s+)?(\w+)\s*\(", re.MULTILINE),
        ],
    }

    def __init__(self, repos_base: Path, output_dir: Path | None = None):
        self.repos_base = Path(repos_base)
        self.output_dir = Path(output_dir) if output_dir is not None else None
        self._file_cache: dict[str, list[str]] = {}
        self._path_cache: dict[tuple[str, str], Path | None] = {}

    def clear_cache(self) -> None:
        """Clear all caches."""
        self._file_cache.clear()
        self._path_cache.clear()

    def get_context(
        self,
        file_path: str,
        line: int,
        lang: str,
        context_lines: int = 50,
        repo_name: str = "",
    ) -> CodeContext:
        """
        Extract function context around the given line.

        Args:
            file_path: Path to the source file
            line: Line number of the finding
            lang: Programming language
            context_lines: Fallback context size
            repo_name: Repository name (used for CSV lookup)

        Returns:
            CodeContext with the extracted code
        """
        full_path = self._resolve_path(file_path, lang)
        if not full_path or not full_path.is_file():
            return self._fallback_context(file_path, line, context_lines)

        lines = self._get_file_lines(full_path)
        if not lines:
            return self._fallback_context(file_path, line, context_lines)

        # Find enclosing function
        func_start, func_end, func_name = self._find_function_bounds(
            lines,
            line - 1,
            lang,
            repo_name=repo_name,
            file_path=file_path,
        )

        if func_start is not None and func_end is not None:
            code = "\n".join(lines[func_start : func_end + 1])
            return CodeContext(
                code=code,
                function_name=func_name or "<anonymous>",
                start_line=func_start + 1,
                end_line=func_end + 1,
                file_path=file_path,
            )

        # Fallback: context_lines before and after
        start = max(0, line - context_lines - 1)
        end = min(len(lines), line + context_lines)
        code = "\n".join(lines[start:end])

        return CodeContext(
            code=code,
            function_name="<unknown>",
            start_line=start + 1,
            end_line=end,
            file_path=file_path,
        )

    def _get_file_lines(self, full_path: Path) -> list[str]:
        """Get file lines with caching."""
        cache_key = str(full_path)
        if cache_key in self._file_cache:
            return self._file_cache[cache_key]

        try:
            lines = full_path.read_text(errors="replace").splitlines()
            self._file_cache[cache_key] = lines
            return lines
        except (OSError, UnicodeDecodeError):
            return []

    def _resolve_path(self, file_path: str, lang: str) -> Path | None:
        """Resolve file path to actual location in repos/."""
        cache_key = (file_path, lang)
        if cache_key in self._path_cache:
            return self._path_cache[cache_key]

        lang_dir = self.repos_base / lang
        if lang_dir.is_dir():
            for repo_dir in lang_dir.iterdir():
                candidate = repo_dir / file_path
                if candidate.is_file():
                    self._path_cache[cache_key] = candidate
                    return candidate

        self._path_cache[cache_key] = None
        return None

    def _fallback_context(
        self,
        file_path: str,
        line: int,
        context_lines: int,
    ) -> CodeContext:
        """Return a placeholder when file can't be read."""
        return CodeContext(
            code=f"[Could not read file: {file_path}]\n[Line {line} flagged]",
            function_name="<unknown>",
            start_line=max(1, line - context_lines),
            end_line=line + context_lines,
            file_path=file_path,
        )

    def _find_function_bounds(
        self,
        lines: list[str],
        target_line: int,
        lang: str,
        repo_name: str = "",
        file_path: str = "",
    ) -> tuple[int | None, int | None, str | None]:
        """Find the enclosing function boundaries for a target line."""
        # 1. CSV lookup — primary: uses AST-derived data, no false positives from control flow
        if self.output_dir and repo_name and file_path:
            csv_path = self.output_dir / lang / repo_name / "context" / "functions.csv"
            if csv_path.is_file():
                try:
                    import csv

                    with open(csv_path, newline="", encoding="utf-8") as f:
                        for row in csv.DictReader(f):
                            if row.get("file", "") != file_path:
                                continue
                            try:
                                start = int(row["start_line"])
                                end = int(row["end_line"])
                            except (KeyError, ValueError):
                                continue
                            if start <= target_line + 1 <= end:  # target_line is 0-indexed
                                return start - 1, end - 1, row.get("name")
                except OSError:
                    pass  # fallback to regex

        # 2. Regex fallback
        patterns = self._FUNCTION_PATTERNS.get(lang, self._FUNCTION_PATTERNS.get("c", []))

        # Search backward for function start
        func_start: int | None = None
        func_name: str | None = None

        for i in range(target_line, -1, -1):
            line = lines[i]
            for pattern in patterns:
                match = pattern.match(line)
                if match:
                    func_start = i
                    func_name = match.group(1) if match.lastindex else None
                    break
            if func_start is not None:
                break

        if func_start is None:
            return None, None, None

        # Search forward for function end (matching braces)
        brace_depth = 0
        in_function = False
        func_end: int | None = None

        for i in range(func_start, len(lines)):
            line = lines[i]
            brace_depth += line.count("{") - line.count("}")

            if "{" in line:
                in_function = True

            if in_function and brace_depth <= 0:
                func_end = i
                break

        # For Python, use indentation
        if lang == "python" and func_end is None:
            base_indent = len(lines[func_start]) - len(lines[func_start].lstrip())
            for i in range(func_start + 1, len(lines)):
                stripped = lines[i].lstrip()
                if stripped and not stripped.startswith("#"):
                    indent = len(lines[i]) - len(stripped)
                    if indent <= base_indent:
                        func_end = i - 1
                        break
            if func_end is None:
                func_end = len(lines) - 1

        return func_start, func_end, func_name


class SlicedContextExtractor:
    """Extract a minimal code slice relevant to a finding.

    Uses SARIF dataflow paths when available, otherwise falls back to
    regex-based variable tracking around the flagged line.
    """

    # Patterns to extract variable names from SARIF messages
    _VAR_PATTERNS = [
        re.compile(r"variable\s+'(\w+)'"),
        re.compile(r"buffer\s+'(\w+)'"),
        re.compile(r"pointer\s+'(\w+)'"),
        re.compile(r"'(\w+)'\s+is\s+"),
        re.compile(r"of\s+'(\w+)'"),
    ]

    def __init__(self, code: str, target_line: int, message: str, window: int = 5) -> None:
        self._code = code
        self._target_line = target_line
        self._message = message
        self._window = window

    @staticmethod
    def _extract_key_variable(message: str) -> str | None:
        """Extract the key variable name from a SARIF finding message."""
        for pattern in SlicedContextExtractor._VAR_PATTERNS:
            m = pattern.search(message)
            if m:
                return m.group(1)
        return None

    def extract(self, finding: Finding) -> CodeContext:
        """Extract a sliced code context for the finding."""
        lines = self._code.splitlines()

        # If dataflow_path is available, use those lines directly
        if finding.dataflow_path:
            slice_text = "\n".join(f"// {step}" for step in finding.dataflow_path)
            # Also include window around target line
            t = self._target_line - 1  # 0-indexed
            start = max(0, t - self._window)
            end = min(len(lines), t + self._window + 1)
            code_window = "\n".join(lines[start:end])
            full_slice = f"// Dataflow path:\n{slice_text}\n\n// Code around flagged line {self._target_line}:\n{code_window}"
            return CodeContext(
                code=full_slice,
                function_name="<sliced>",
                start_line=start + 1,
                end_line=end,
            )

        # Regex-based slicing: find lines referencing the key variable
        var_name = self._extract_key_variable(self._message or finding.message)
        if not var_name:
            # No variable target — slicing only helps when we know which variable to track.
            # Return the full code so the LLM has complete context.
            return CodeContext(
                code="\n".join(lines),
                function_name="<sliced>",
                start_line=1,
                end_line=len(lines),
            )

        # Collect line indices that reference the variable + window around target
        relevant: set[int] = set()
        t = self._target_line - 1
        for i in range(max(0, t - self._window), min(len(lines), t + self._window + 1)):
            relevant.add(i)

        var_pat = re.compile(r"\b" + re.escape(var_name) + r"\b")
        for i, line in enumerate(lines):
            if var_pat.search(line):
                for j in range(max(0, i - 1), min(len(lines), i + 2)):
                    relevant.add(j)

        sorted_lines = sorted(relevant)
        slice_lines = [lines[i] for i in sorted_lines]
        return CodeContext(
            code="\n".join(slice_lines),
            function_name="<sliced>",
            start_line=sorted_lines[0] + 1 if sorted_lines else 1,
            end_line=sorted_lines[-1] + 1 if sorted_lines else 1,
        )
