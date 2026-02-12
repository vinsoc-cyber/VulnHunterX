"""
Stage 7.4: Compile and link harness with Stage 5 manifest.

Captures stderr/stdout and returns success/failure plus normalized error text.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

# Max lines of stderr to keep for LLM fix (normalized)
MAX_ERROR_LINES = 60


def load_manifest(manifest_path: Path) -> dict:
    """Load manifest.json; return dict with libs, objects, include_dirs, source_root."""
    path = Path(manifest_path)
    if not path.is_file():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _sanitized_entries(manifest: dict, key: str, source_root: Path) -> list[Path]:
    """Prefer build_sanitized paths; return list of absolute Paths."""
    entries = manifest.get(key) or []
    # Prefer entries under build_sanitized for linking (sanitizer-built)
    filtered = [e for e in entries if "build_sanitized" in str(e)]
    if not filtered:
        filtered = entries
    return [source_root / e if not Path(e).is_absolute() else Path(e) for e in filtered]


def build_harness(
    harness_cc: Path,
    manifest_path: Path,
    output_binary: Path | None = None,
    cxx: str = "clang++",
    timeout: int = 120,
) -> tuple[bool, str, str]:
    """
    Compile and link one harness with Stage 5 manifest.

    Args:
        harness_cc: Path to .cc file
        manifest_path: Path to manifest.json (output/<lang>/<repo>/sanitized_build/manifest.json)
        output_binary: Path for fuzz binary; default harness_cc.with_suffix('')
        cxx: C++ compiler
        timeout: Timeout in seconds

    Returns:
        (success, combined_stderr, command_used)
    """
    harness_cc = Path(harness_cc)
    manifest_path = Path(manifest_path)
    manifest = load_manifest(manifest_path)
    if not manifest:
        return False, "Manifest not found or invalid", ""

    source_root = Path(manifest.get("source_root", manifest_path.parent / "src"))
    include_dirs = manifest.get("include_dirs") or []
    if include_dirs and isinstance(include_dirs[0], str) and not Path(include_dirs[0]).is_absolute():
        include_dirs = [source_root / d for d in include_dirs]
    else:
        include_dirs = [Path(d) for d in include_dirs]

    objects = _sanitized_entries(manifest, "objects", source_root)
    libs = _sanitized_entries(manifest, "libs", source_root)

    out_bin = output_binary or harness_cc.with_suffix("")
    work_dir = harness_cc.parent
    cc_name = harness_cc.name
    obj_name = harness_cc.stem + ".o"

    flag_list = ["-fsanitize=fuzzer,address", "-g", "-O2"]
    include_args = [f"-I{d}" for d in include_dirs if d.exists()]

    # Compile step
    compile_cmd = [cxx, "-c"] + flag_list + include_args + [cc_name, "-o", obj_name]
    try:
        r = subprocess.run(
            compile_cmd,
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stderr = (r.stderr or "").strip()
        if r.returncode != 0:
            return False, _normalize_errors(stderr), " ".join(compile_cmd)
    except subprocess.TimeoutExpired:
        return False, "Compile timed out", " ".join(compile_cmd)
    except Exception as e:
        return False, str(e), " ".join(compile_cmd)

    # Link step: harness.o + objects + libs
    obj_path = work_dir / obj_name
    obj_files = [str(obj_path)] + [str(p) for p in objects if p.exists()]
    lib_files = [str(p) for p in libs if p.exists()]
    link_cmd = [cxx, "-o", str(out_bin)] + flag_list + obj_files + lib_files
    try:
        r = subprocess.run(
            link_cmd,
            cwd=work_dir,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stderr = (r.stderr or "").strip()
        stdout = (r.stdout or "").strip()
        combined = (stderr + "\n" + stdout).strip() if stderr or stdout else ""
        if r.returncode != 0:
            return False, _normalize_errors(combined or "Link failed"), " ".join(link_cmd)
    except subprocess.TimeoutExpired:
        return False, "Link timed out", " ".join(link_cmd)
    except Exception as e:
        return False, str(e), " ".join(link_cmd)

    return True, "", " ".join(link_cmd)


def _normalize_errors(text: str, max_lines: int = MAX_ERROR_LINES) -> str:
    """Trim and keep first N lines; drop redundant 'note:' lines if too long."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    # Optionally drop "note:" lines to save space
    if len(lines) > max_lines:
        lines = [ln for ln in lines if "note:" not in ln.lower() or "error" in ln.lower()][:max_lines]
    else:
        lines = lines[:max_lines]
    return "\n".join(lines)


def find_manifest_for_repo(output_dir: Path, lang: str, repo_name: str) -> Path | None:
    """Return path to manifest.json: output_dir/<lang>/<repo_name>/sanitized_build/manifest.json."""
    p = output_dir / lang / repo_name / "sanitized_build" / "manifest.json"
    return p if p.is_file() else None


def write_harness_status(
    repo_name: str,
    entries: list[dict],
    repo_fuzz_targets_dir: Path,
) -> Path:
    """
    Stage 7.6: Write status.json for a repo's harnesses.
    repo_fuzz_targets_dir: output/<lang>/<repo_name>/fuzz_targets.
    """
    repo_fuzz_targets_dir = Path(repo_fuzz_targets_dir)
    repo_fuzz_targets_dir.mkdir(parents=True, exist_ok=True)
    path = repo_fuzz_targets_dir / "status.json"
    # Serialize paths as str for JSON
    data = []
    for e in entries:
        data.append({
            "harness": str(e.get("harness", "")),
            "status": e.get("status", "unknown"),
            "errors": e.get("errors", "")[:2000],
        })
    path.write_text(json.dumps({"repo": repo_name, "harnesses": data}, indent=2), encoding="utf-8")
    return path
