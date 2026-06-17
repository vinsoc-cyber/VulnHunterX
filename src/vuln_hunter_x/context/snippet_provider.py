# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""ContextProvider fallback that serves snippet-derived context.

Used when the CSV-based ContextProvider has no data for a finding (e.g.
benchmark mode with no CodeQL DB, or production runs that skipped Stage 3
context extraction). Instead of returning empty results — which historically
caused the multi-turn loop to silently give up and the LLM to default to
False Positive — this provider returns answers derived from the snippet
itself, with an explicit "<unavailable: out-of-snippet>" sentinel when a
request genuinely cannot be served.

Backed by lightweight regex scans over the snippet text. No tree-sitter or
clang dep, which keeps this usable in the benchmark hot path.
"""

from __future__ import annotations

import re

# Compiled once. C/C++-flavoured but works well enough for Python/Java/JS too
# because we're scanning for human-readable identifiers, not parsing types.
_FREE_KIND_RE = re.compile(
    r"\b(free|delete\s*(?:\[\s*\])?|kfree|vfree|g_free|sk_free|"
    r"close|fclose|release|destroy|cleanup|dispose|drop|reset)\s*\(",
    re.IGNORECASE,
)


def _line_of_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


class SnippetContextProvider:
    """A ContextProvider implementation that derives context from a single
    code snippet held in memory.

    Implements the same ``get_additional_context`` contract as the CSV-backed
    ``ContextProvider`` so it is drop-in compatible. Unknown / out-of-scope
    requests return an ``<unavailable: ...>`` token; the LLM is then free to
    legitimately answer "Needs More Data" rather than guessing.
    """

    UNAVAILABLE_PREFIX = "<unavailable: out-of-snippet>"

    def __init__(self, snippet: str, function_name: str = "") -> None:
        self._snippet = snippet or ""
        self._func_name = function_name or ""

    # ---- ContextProvider interface ----

    def get_additional_context(
        self,
        repo_name: str,
        lang: str,
        context_requests: list[str],
    ) -> dict[str, str]:
        results: dict[str, str] = {}
        for request in context_requests:
            if ":" not in request:
                results[request] = self._unavailable(request, "malformed request")
                continue
            ctx_type, name = request.split(":", 1)
            ctx_type = ctx_type.lower().strip()
            name = name.strip()
            results[request] = self._dispatch(ctx_type, name, lang)
        return results

    def has_context_for_repo(self, repo_name: str, lang: str) -> bool:
        # Always True — we always have *some* snippet-derived answer
        # (possibly an unavailable sentinel).
        return True

    def clear_cache(self) -> None:
        return None

    # ---- Dispatch ----

    def _dispatch(self, ctx_type: str, name: str, lang: str) -> str:
        if ctx_type in ("free_sites", "free_site"):
            return self._free_sites(name)
        if ctx_type in ("callees",):
            return self._callees(name)
        if ctx_type in ("struct", "class", "classes"):
            return self._struct(name, lang)
        if ctx_type == "macro":
            return self._macro(name)
        if ctx_type == "enum":
            return self._enum(name)
        if ctx_type == "typedef":
            return self._typedef(name)
        if ctx_type in ("caller", "all_callers"):
            return self._unavailable(
                f"{ctx_type}:{name}",
                "caller relationships require cross-function analysis "
                "not available from a single snippet",
            )
        if ctx_type == "global":
            return self._unavailable(
                f"{ctx_type}:{name}",
                "global declarations require whole-module visibility",
            )
        if ctx_type in ("destructor", "destructors", "field_writes", "field_write"):
            return self._unavailable(
                f"{ctx_type}:{name}",
                "requires cross-file analysis (only the flagged function is "
                "available in this provider)",
            )
        return self._unavailable(f"{ctx_type}:{name}", f"unknown context type {ctx_type!r}")

    # ---- Per-type implementations ----

    def _free_sites(self, pointer_name: str) -> str:
        """List every free()/delete/release call referencing ``pointer_name``."""
        if not pointer_name:
            return self._unavailable("free_sites:", "empty pointer name")
        needle = pointer_name.strip().lstrip("&*")
        sites: list[str] = []
        for m in _FREE_KIND_RE.finditer(self._snippet):
            # Find the matching closing paren by simple depth tracking.
            start = m.end() - 1
            depth = 0
            i = start
            while i < len(self._snippet):
                ch = self._snippet[i]
                if ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            args = self._snippet[start + 1 : i]
            if needle and needle in args:
                line = _line_of_offset(self._snippet, m.start())
                kind = m.group(1).strip().lower()
                sites.append(f"  line {line}: {kind}({args.strip()})")
        if not sites:
            return self._unavailable(
                f"free_sites:{pointer_name}",
                f"no free/delete/release call referencing {pointer_name!r} "
                "inside the provided snippet — it may be freed in a caller "
                "or callee that is not visible here",
            )
        header = f"// Snippet-local free/delete sites for: {pointer_name}"
        return "\n".join([header, *sites])

    def _callees(self, func_name: str) -> str:
        """List functions called inside the snippet (best-effort)."""
        # Match identifier followed by '(' that is not a definition or a keyword.
        call_re = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{0,127})\s*\(")
        keywords = {
            "if", "while", "for", "switch", "return", "sizeof", "alignof",
            "typeof", "do", "case", "catch", "throw", "new", "delete",
            "static_cast", "dynamic_cast", "const_cast", "reinterpret_cast",
        }
        seen: list[str] = []
        seen_set: set[str] = set()
        for m in call_re.finditer(self._snippet):
            name = m.group(1)
            if name in keywords or name in seen_set:
                continue
            seen_set.add(name)
            seen.append(name)
        if not seen:
            return self._unavailable(
                f"callees:{func_name}",
                "no callees detected in the snippet",
            )
        return (
            f"// Callees referenced within the snippet for {func_name or self._func_name!r}:\n"
            + "\n".join(f"  - {n}" for n in seen[:50])
            + (f"\n  ... and {len(seen) - 50} more" if len(seen) > 50 else "")
        )

    def _struct(self, type_name: str, lang: str) -> str:
        if not type_name:
            return self._unavailable("struct:", "empty type name")
        # Match `struct Foo {...}` / `class Foo {...}` / `class Foo:` (py).
        pattern = re.compile(
            rf"(?:struct|class|union)\s+{re.escape(type_name)}\b[^;{{]*\{{",
        )
        m = pattern.search(self._snippet)
        if not m:
            return self._unavailable(
                f"struct:{type_name}",
                f"definition of {type_name!r} is not in the snippet (likely "
                "declared in a header / sibling module)",
            )
        start = m.start()
        # Walk braces to find matching close.
        i = m.end() - 1
        depth = 0
        while i < len(self._snippet):
            ch = self._snippet[i]
            if ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = i + 1
                    break
            i += 1
        else:
            return self._unavailable(
                f"struct:{type_name}",
                "definition truncated in snippet",
            )
        line = _line_of_offset(self._snippet, start)
        return (
            f"// Struct/Class: {type_name} (snippet line {line})\n"
            f"{self._snippet[start:end]}"
        )

    def _macro(self, macro_name: str) -> str:
        if not macro_name:
            return self._unavailable("macro:", "empty macro name")
        pattern = re.compile(
            rf"^\s*#\s*define\s+{re.escape(macro_name)}(?:\s+(.*))?$",
            re.MULTILINE,
        )
        m = pattern.search(self._snippet)
        if not m:
            return self._unavailable(
                f"macro:{macro_name}",
                "macro is not defined inside the snippet",
            )
        body = (m.group(1) or "").strip()
        return f"// Macro: {macro_name}\n#define {macro_name} {body}"

    def _enum(self, enum_name: str) -> str:
        if not enum_name:
            return self._unavailable("enum:", "empty enum name")
        pattern = re.compile(
            rf"enum(?:\s+class)?\s+{re.escape(enum_name)}\s*\{{([^}}]*)\}}",
            re.DOTALL,
        )
        m = pattern.search(self._snippet)
        if not m:
            return self._unavailable(
                f"enum:{enum_name}",
                "enum is not defined inside the snippet",
            )
        body = m.group(1).strip()
        return f"// Enum: {enum_name}\nenum {enum_name} {{\n{body}\n}}"

    def _typedef(self, type_name: str) -> str:
        if not type_name:
            return self._unavailable("typedef:", "empty type name")
        pattern = re.compile(
            rf"typedef\s+([^;]*?\b{re.escape(type_name)})\s*;",
        )
        m = pattern.search(self._snippet)
        if not m:
            return self._unavailable(
                f"typedef:{type_name}",
                "typedef is not defined inside the snippet",
            )
        return f"// Typedef: {type_name}\ntypedef {m.group(1).strip()};"

    # ---- Helpers ----

    def _unavailable(self, request: str, reason: str) -> str:
        # Format matches the documented sentinel so the LLM and downstream
        # filters (e.g. the prefetched_context filter in client.analyze)
        # can recognise it. The reason is plain English for the LLM.
        return f"{self.UNAVAILABLE_PREFIX} ({request}) — {reason}"
