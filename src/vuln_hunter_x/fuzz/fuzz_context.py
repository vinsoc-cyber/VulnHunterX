"""
Stage 7.2: Gather per-target fuzz context (signature + includes).

Loads function_signatures.csv and includes.csv for harness generation.
"""

from __future__ import annotations

import csv
from pathlib import Path


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
        pass
    return result


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

    return {
        "name": name,
        "file": file,
        "start_line": start,
        "end_line": end,
        "params": params,
        "includes": includes,
    }
