"""CSV-based context provider for on-demand context expansion."""

from __future__ import annotations

import csv
from pathlib import Path


class ContextProvider:
    """
    Provides additional context on-demand using pre-extracted CSV files.
    
    Context CSVs live under output/<lang>/<repo_name>/context/.
    Supports:
    - caller:function_name - Get the calling function's code
    - struct:type_name - Get struct/class definition
    - global:var_name - Get global variable definition
    - macro:MACRO_NAME - Get macro definition
    """
    
    def __init__(self, output_dir: Path, repos_dir: Path):
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
            elif ctx_type in ("struct", "class"):
                code = self._get_struct_context(repo_name, lang, name)
            elif ctx_type == "global":
                code = self._get_global_context(repo_name, lang, name)
            elif ctx_type == "macro":
                code = self._get_macro_context(repo_name, lang, name)
            elif ctx_type == "callees":
                code = self._get_callees_context(repo_name, lang, name)
            elif ctx_type == "all_callers":
                code = self._get_all_callers_context(repo_name, lang, name)
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
            with open(csv_path, newline='', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                rows = list(reader)
            self._cache[cache_key] = rows
            return rows
        except Exception:
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
        full_path = self.repos_dir / lang / repo_name / file_path
        if not full_path.is_file():
            # Try without repo_name in path
            for repo_dir in (self.repos_dir / lang).iterdir():
                candidate = repo_dir / file_path
                if candidate.is_file():
                    full_path = candidate
                    break
        
        if not full_path.is_file():
            return f"[File not found: {file_path}]"
        
        try:
            lines = full_path.read_text(errors='replace').splitlines()
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
        
        return f"[No caller found for: {callee_name}]"
    
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
        
        return f"[Struct/Class not found: {struct_name}]"
    
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
                parts.append(
                    f"// Caller: {caller_name}\n// File: {caller_file}\n{code}"
                )

        if not parts:
            return f"[Could not read source for callers of: {callee_name}]"
        return "\n\n".join(parts)
