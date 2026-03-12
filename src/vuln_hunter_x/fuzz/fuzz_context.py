"""
Stage 7.2: Gather per-target fuzz context (signature + includes).

Loads function_signatures.csv and includes.csv for harness generation.
"""

from __future__ import annotations

import csv
import logging
from pathlib import Path

logger = logging.getLogger(__name__)


def _normalize_path(p: str) -> str:
    return p.replace("\\", "/").strip()


def load_function_signatures(repo_context_dir: Path) -> list[dict]:
    """
    Load function_signatures.csv and return list of function dicts.
    repo_context_dir: output/<lang>/<repo_name>/context.
    Each dict: name, file, start_line, end_line, params (list of {type, name}).
    """
    path = Path(repo_context_dir) / "function_signatures.csv"
    if not path.is_file():
        return []

    by_key: dict[tuple[str, str, int, int], list[dict]] = {}
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("name", "")
                file = _normalize_path(row.get("file", ""))
                start = int(row.get("start_line", 0))
                end = int(row.get("end_line", 0))
                key = (name, file, start, end)
                if key not in by_key:
                    by_key[key] = []
                by_key[key].append({
                    "param_index": int(row.get("param_index", 0)),
                    "param_type": row.get("param_type", ""),
                    "param_name": row.get("param_name", ""),
                })
    except Exception:
        logger.warning("Failed to load function_signatures.csv from %s", repo_context_dir, exc_info=True)
        return []

    out = []
    for (name, file, start, end), params in by_key.items():
        params.sort(key=lambda x: x["param_index"])
        out.append({
            "name": name,
            "file": file,
            "start_line": start,
            "end_line": end,
            "params": [{"type": p["param_type"], "name": p["param_name"]} for p in params],
        })
    return out


def load_includes(repo_context_dir: Path) -> dict[str, list[str]]:
    """
    Load includes.csv; return dict mapping file path -> list of include literal strings.
    repo_context_dir: output/<lang>/<repo_name>/context.
    """
    path = Path(repo_context_dir) / "includes.csv"
    if not path.is_file():
        return {}

    result: dict[str, list[str]] = {}
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                file = _normalize_path(row.get("file", ""))
                inc = (row.get("include_text") or "").strip()
                if file not in result:
                    result[file] = []
                if inc and inc not in result[file]:
                    result[file].append(inc)
    except Exception:
        logger.warning("Failed to load includes.csv from %s", repo_context_dir, exc_info=True)
    return result


def load_structs(repo_context_dir: Path) -> dict[str, list[str]]:
    """Load structs.csv; returns dict mapping struct name -> list of member names."""
    path = Path(repo_context_dir) / "structs.csv"
    if not path.is_file():
        return {}
    result: dict[str, list[str]] = {}
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("name", "")
                member = row.get("member_name", "")
                if name:
                    if name not in result:
                        result[name] = []
                    if member:
                        result[name].append(member)
    except Exception:
        logger.warning("Failed to load structs.csv from %s", repo_context_dir, exc_info=True)
    return result


def load_globals(repo_context_dir: Path) -> list[dict]:
    """Load globals.csv; returns list of dicts with name, file, type."""
    path = Path(repo_context_dir) / "globals.csv"
    if not path.is_file():
        return []
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            return list(reader)
    except Exception:
        logger.warning("Failed to load globals.csv from %s", repo_context_dir, exc_info=True)
        return []


def load_macros(repo_context_dir: Path) -> dict[str, str]:
    """Load macros.csv; returns dict mapping macro name -> body."""
    path = Path(repo_context_dir) / "macros.csv"
    if not path.is_file():
        return {}
    result: dict[str, str] = {}
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get("name", "")
                body = row.get("body", "")
                if name:
                    result[name] = body
    except Exception:
        logger.warning("Failed to load macros.csv from %s", repo_context_dir, exc_info=True)
    return result


def load_callers(repo_context_dir: Path) -> dict[str, list[str]]:
    """Load callers.csv; returns dict mapping callee_name -> list of unique caller names."""
    path = Path(repo_context_dir) / "callers.csv"
    if not path.is_file():
        return {}
    result: dict[str, list[str]] = {}
    try:
        with open(path, newline="", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                callee = row.get("callee_name", "")
                caller = row.get("caller_name", "")
                if callee and caller:
                    if callee not in result:
                        result[callee] = []
                    if caller not in result[callee]:
                        result[callee].append(caller)
    except Exception:
        logger.warning("Failed to load callers.csv from %s", repo_context_dir, exc_info=True)
    return result


def build_type_context_string(repo_context_dir: Path, max_chars: int = 2000) -> str:
    """Build compact C-like type definitions from structs, globals, macros. Truncated to max_chars."""
    parts: list[str] = []

    structs = load_structs(repo_context_dir)
    for name, members in structs.items():
        if members:
            members_str = ";\n    ".join(members) + ";"
            parts.append(f"struct {name} {{\n    {members_str}\n}};")
        else:
            parts.append(f"struct {name} {{}};")

    for g in load_globals(repo_context_dir):
        gtype = g.get("type", "")
        gname = g.get("name", "")
        if gtype and gname:
            parts.append(f"{gtype} {gname};")

    for name, body in load_macros(repo_context_dir).items():
        parts.append(f"#define {name} {body}")

    text = "\n\n".join(parts)
    if len(text) > max_chars:
        text = text[:max_chars] + "\n/* ... (truncated) */"
    return text


def get_target_context(
    target_function_info: dict,
    repo_context_dir: Path,
) -> dict:
    """
    Gather full context for one target: signature (params) and includes for the target file.
    repo_context_dir: output/<lang>/<repo_name>/context.

    target_function_info: from select_targets (name, file, start_line, end_line).
    Returns dict with: name, file, start_line, end_line, params, includes (list of "#include ..." strings).
    """
    sigs = load_function_signatures(repo_context_dir)
    includes_map = load_includes(repo_context_dir)

    name = target_function_info.get("name", "")
    file = _normalize_path(target_function_info.get("file", ""))
    start = target_function_info.get("start_line", 0)
    end = target_function_info.get("end_line", 0)

    params: list[dict] = []
    for s in sigs:
        if (s["name"], s["file"], s["start_line"], s["end_line"]) == (name, file, start, end):
            params = s.get("params", [])
            break

    includes = includes_map.get(file, [])

    # Find struct definitions matching param types
    all_structs = load_structs(repo_context_dir)
    struct_defs: dict[str, list[str]] = {}
    for p in params:
        ptype = p.get("type", "")
        base = ptype.replace("const", "").replace("struct", "").replace("*", "").strip()
        if base in all_structs:
            struct_defs[base] = all_structs[base]

    return {
        "name": name,
        "file": file,
        "start_line": start,
        "end_line": end,
        "params": params,
        "includes": includes,
        "struct_defs": struct_defs,
    }
