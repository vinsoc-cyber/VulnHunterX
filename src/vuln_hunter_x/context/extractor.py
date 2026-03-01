"""Heuristic-based code context extraction."""

from __future__ import annotations

import re
from pathlib import Path

from vuln_hunter_x.core.types import CodeContext


class ContextExtractor:
    """
    Extracts function/scope context from source files using heuristics.
    
    Uses pattern matching and bracket counting to find enclosing function
    boundaries. Includes caching for improved performance.
    """
    
    # Patterns for function definitions by language
    _FUNCTION_PATTERNS: dict[str, list[re.Pattern]] = {
        "c": [
            re.compile(r'^[\w\s\*]+\s+(\w+)\s*\([^)]*\)\s*\{?\s*$', re.MULTILINE),
        ],
        "cpp": [
            re.compile(
                r'^[\w\s\*:&<>]+\s+(\w+)\s*\([^)]*\)\s*(?:const|override|final)?\s*\{?\s*$',
                re.MULTILINE
            ),
        ],
        "python": [
            re.compile(r'^\s*def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*$', re.MULTILINE),
            re.compile(r'^\s*async\s+def\s+(\w+)\s*\([^)]*\)\s*(?:->.*?)?\s*:\s*$', re.MULTILINE),
        ],
        "javascript": [
            re.compile(r'^\s*(?:async\s+)?function\s+(\w+)\s*\([^)]*\)\s*\{?\s*$', re.MULTILINE),
            re.compile(r'^\s*(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\([^)]*\)\s*=>', re.MULTILINE),
            re.compile(r'^\s*(?:async\s+)?(\w+)\s*\([^)]*\)\s*\{', re.MULTILINE),
        ],
        "java": [
            re.compile(
                r'^\s*(?:public|private|protected|static|final|abstract|synchronized|native|\s)*'
                r'[\w<>\[\],\s]+\s+(\w+)\s*\([^)]*\)\s*(?:throws\s+[\w\s,]+)?\s*\{?\s*$',
                re.MULTILINE,
            ),
        ],
    }
    
    def __init__(self, repos_base: Path):
        self.repos_base = Path(repos_base)
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
    ) -> CodeContext:
        """
        Extract function context around the given line.
        
        Args:
            file_path: Path to the source file
            line: Line number of the finding
            lang: Programming language
            context_lines: Fallback context size
            
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
            lines, line - 1, lang  # 0-indexed
        )
        
        if func_start is not None and func_end is not None:
            code = "\n".join(lines[func_start:func_end + 1])
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
    ) -> tuple[int | None, int | None, str | None]:
        """Find the enclosing function boundaries for a target line."""
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
            brace_depth += line.count('{') - line.count('}')
            
            if '{' in line:
                in_function = True
            
            if in_function and brace_depth <= 0:
                func_end = i
                break
        
        # For Python, use indentation
        if lang == "python" and func_end is None:
            base_indent = len(lines[func_start]) - len(lines[func_start].lstrip())
            for i in range(func_start + 1, len(lines)):
                stripped = lines[i].lstrip()
                if stripped and not stripped.startswith('#'):
                    indent = len(lines[i]) - len(stripped)
                    if indent <= base_indent:
                        func_end = i - 1
                        break
            if func_end is None:
                func_end = len(lines) - 1
        
        return func_start, func_end, func_name
