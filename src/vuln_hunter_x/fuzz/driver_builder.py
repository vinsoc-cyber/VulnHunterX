# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""
Stage 7.4: Compile and link harness with Stage 5 manifest.

Captures stderr/stdout and returns success/failure plus normalized error text.
Supports selective linking: resolves minimal link dependencies per target
function based on symbol maps, library exports, and compile commands from the
enriched manifest.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from vuln_hunter_x.core.constants import BUILD_LOG_MAX_ERROR_CHARS

logger = logging.getLogger(__name__)

# Max lines of stderr to keep for LLM fix (normalized)
MAX_ERROR_LINES = 60


@dataclass
class BuildResult:
    """Rich result from build_harness(); backward-compatible with tuple unpacking."""

    success: bool
    errors: str  # normalized errors (for LLM consumption / status.json)
    compile_command: str
    link_command: str
    compile_errors: str  # raw compile stderr
    link_errors: str  # raw link stderr
    phase_failed: str  # "compile" | "link" | ""

    def __iter__(self):  # type: ignore[override]
        cmd = self.compile_command if self.phase_failed == "compile" else self.link_command
        return iter((self.success, self.errors, cmd))


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


def _extract_compile_flags(compile_commands: dict, source_file: str) -> list[str]:
    """Extract ``-D`` and ``-I`` flags from compile_commands for a source file.

    Returns a list of flag strings (e.g. ``["-DFOO=1", "-I/path"]``).
    """
    entry = compile_commands.get(source_file)
    if not entry:
        # Try matching by basename
        basename = Path(source_file).name
        for key, val in compile_commands.items():
            if Path(key).name == basename:
                entry = val
                break
    if not entry:
        return []

    command = entry.get("command", "")
    flags: list[str] = []
    # Extract -D and -I flags (with their arguments)
    for match in re.finditer(r"(-[DI]\S+|-[DI]\s+\S+)", command):
        flags.append(match.group(0).strip())
    return flags


def _resolve_link_deps(
    target_func: str,
    manifest: dict,
    source_root: Path,
) -> tuple[list[Path], list[Path], list[str]]:
    """Resolve minimal link dependencies for a target function.

    Uses the enriched manifest to determine exactly which objects and libraries
    are needed, rather than dumping all build artifacts.

    Args:
        target_func: Name of the target function.
        manifest: Loaded manifest dict with symbol maps.
        source_root: Absolute path to the source root.

    Returns:
        (needed_objects, needed_libs, extra_source_files)
        - needed_objects: specific .o files to link
        - needed_libs: .a libraries to link
        - extra_source_files: .c files to compile alongside (for static funcs)
    """
    lib_exports = manifest.get("lib_exports") or {}
    symbol_to_objects = manifest.get("symbol_to_objects") or {}
    static_symbols = set(manifest.get("static_symbols") or [])
    libs = manifest.get("libs") or []

    # 1. Library-exported: link only the relevant libraries
    if target_func in lib_exports:
        needed_lib_rels = lib_exports[target_func]
        # Prefer sanitized versions
        sanitized = [r for r in needed_lib_rels if "build_sanitized" in r]
        if sanitized:
            needed_lib_rels = sanitized
        needed_libs = [source_root / r for r in needed_lib_rels]
        return [], needed_libs, []

    # 2. Static: need to compile the source file alongside
    if target_func in static_symbols:
        # Find which .o contains this as a local symbol — the source is nearby
        for obj_path in source_root.rglob("*.o"):
            try:
                result = subprocess.run(
                    ["nm", "--defined-only", str(obj_path)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                for line in result.stdout.splitlines():
                    parts = line.split()
                    if len(parts) >= 3 and parts[2] == target_func and parts[1] == "t":
                        # Found it — derive source file from object path
                        # CMake pattern: CMakeFiles/<target>.dir/<path>.c.o
                        obj_rel = str(obj_path.relative_to(source_root))
                        src_match = re.search(r"\.dir/(.+\.c)\.o$", obj_rel)
                        if src_match:
                            src_rel = src_match.group(1)
                            src_path = source_root / src_rel
                            if src_path.is_file():
                                # Also need libraries for the rest of the symbols
                                sanitized_libs = [r for r in libs if "build_sanitized" in r]
                                if not sanitized_libs:
                                    sanitized_libs = libs
                                needed_libs = [source_root / r for r in sanitized_libs]
                                return [], needed_libs, [str(src_path)]
            except (subprocess.TimeoutExpired, FileNotFoundError):
                continue
        # Fallback: return all libs
        sanitized_libs = [r for r in libs if "build_sanitized" in r]
        if not sanitized_libs:
            sanitized_libs = libs
        return [], [source_root / r for r in sanitized_libs], []

    # 3. Object-global: link specific objects + libraries for remaining symbols
    if target_func in symbol_to_objects:
        obj_rels = symbol_to_objects[target_func]
        # Prefer sanitized
        sanitized = [r for r in obj_rels if "build_sanitized" in r]
        if sanitized:
            obj_rels = sanitized
        needed_objects = [source_root / r for r in obj_rels]
        # Also include libraries for transitive deps
        sanitized_libs = [r for r in libs if "build_sanitized" in r]
        if not sanitized_libs:
            sanitized_libs = libs
        needed_libs = [source_root / r for r in sanitized_libs]
        return needed_objects, needed_libs, []

    # 4. Unknown: fall back to all objects + libs (legacy behavior)
    return (
        _sanitized_entries(manifest, "objects", source_root),
        _sanitized_entries(manifest, "libs", source_root),
        [],
    )


def build_harness(
    harness_cc: Path,
    manifest_path: Path,
    output_binary: Path | None = None,
    cxx: str = "clang++",
    timeout: int = 120,
    target_info: dict | None = None,
    extra_include_dirs: list[str] | None = None,
    extra_lib_dirs: list[str] | None = None,
    extra_link_libs: list[str] | None = None,
) -> tuple[bool, str, str]:
    """
    Compile and link one harness with Stage 5 manifest.

    When *target_info* is provided (with ``linkability`` and ``name`` keys),
    uses selective linking to resolve only the minimal set of objects and
    libraries needed.  Falls back to linking all artifacts if *target_info*
    is ``None`` (legacy behavior).

    Args:
        harness_cc: Path to .cc file
        manifest_path: Path to manifest.json (output/<lang>/<repo>/sanitized_build/manifest.json)
        output_binary: Path for fuzz binary; default harness_cc.with_suffix('')
        cxx: C++ compiler
        timeout: Timeout in seconds
        target_info: Optional dict with ``name``, ``linkability``, ``file`` keys

    Returns:
        BuildResult (supports tuple unpacking as (success, errors, command)).
    """
    harness_cc = Path(harness_cc)
    manifest_path = Path(manifest_path)
    manifest = load_manifest(manifest_path)
    if not manifest:
        return BuildResult(
            success=False,
            errors="Manifest not found or invalid",
            compile_command="",
            link_command="",
            compile_errors="",
            link_errors="",
            phase_failed="compile",
        )

    source_root = Path(manifest.get("source_root", manifest_path.parent / "src"))
    include_dirs = manifest.get("include_dirs") or []
    if (
        include_dirs
        and isinstance(include_dirs[0], str)
        and not Path(include_dirs[0]).is_absolute()
    ):
        include_dirs = [source_root / d for d in include_dirs]
    else:
        include_dirs = [Path(d) for d in include_dirs]

    # Selective linking when target_info is available
    if target_info and target_info.get("name"):
        objects, libs, extra_sources = _resolve_link_deps(
            target_info["name"], manifest, source_root
        )
    else:
        objects = _sanitized_entries(manifest, "objects", source_root)
        libs = _sanitized_entries(manifest, "libs", source_root)
        extra_sources = []

    out_bin = output_binary or harness_cc.with_suffix("")
    work_dir = harness_cc.parent
    cc_name = harness_cc.name
    obj_name = harness_cc.stem + ".o"

    flag_list = ["-fsanitize=fuzzer,address", "-g", "-O2"]
    include_args = [f"-I{d}" for d in include_dirs if d.exists()]

    # Add project-specific flags from compile_commands.json
    compile_commands = manifest.get("compile_commands") or {}
    if target_info and target_info.get("file"):
        extra_flags = _extract_compile_flags(compile_commands, target_info["file"])
        include_args.extend(extra_flags)

    # Compute manifest and CLI-provided flags
    compiler_defines = [f"-D{d}" for d in (manifest.get("compiler_defines") or [])]
    manifest_extra_cflags = manifest.get("extra_cflags") or []
    extra_inc_args = [f"-I{d}" for d in (extra_include_dirs or [])]
    manifest_extra_ldflags = manifest.get("extra_ldflags") or []
    extra_lib_dir_args = [f"-L{d}" for d in (extra_lib_dirs or [])]
    extra_lib_args = [f"-l{lib}" for lib in (extra_link_libs or [])]

    # Compile step
    compile_cmd = (
        [cxx, "-c"]
        + flag_list
        + compiler_defines
        + manifest_extra_cflags
        + include_args
        + extra_inc_args
        + [cc_name, "-o", obj_name]
    )
    compile_cmd_str = " ".join(compile_cmd)

    # Build link command upfront so it's available even on compile failure
    obj_path = work_dir / obj_name
    obj_files = [str(obj_path)] + [str(p) for p in objects if p.exists()]
    lib_files = [str(p) for p in libs if p.exists()]
    system_libs = manifest.get("system_libs") or []
    link_cmd = (
        [cxx, "-o", str(out_bin)]
        + flag_list
        + manifest_extra_ldflags
        + obj_files
        + lib_files
        + extra_lib_dir_args
        + system_libs
        + extra_lib_args
    )
    link_cmd_str = " ".join(link_cmd)

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
            return BuildResult(
                success=False,
                errors=_normalize_errors(stderr),
                compile_command=compile_cmd_str,
                link_command=link_cmd_str,
                compile_errors=stderr,
                link_errors="",
                phase_failed="compile",
            )
    except subprocess.TimeoutExpired:
        return BuildResult(
            success=False,
            errors="Compile timed out",
            compile_command=compile_cmd_str,
            link_command=link_cmd_str,
            compile_errors="Compile timed out",
            link_errors="",
            phase_failed="compile",
        )
    except Exception as e:
        return BuildResult(
            success=False,
            errors=str(e),
            compile_command=compile_cmd_str,
            link_command=link_cmd_str,
            compile_errors=str(e),
            link_errors="",
            phase_failed="compile",
        )

    # Compile extra source files for static function support
    extra_obj_files: list[str] = []
    for src_file in extra_sources:
        src_path = Path(src_file)
        if not src_path.is_file():
            continue
        extra_obj = work_dir / (src_path.stem + "_extra.o")
        # Compile with sanitizers but WITHOUT -fsanitize=fuzzer (only harness needs fuzzer)
        extra_compile_flags = ["-fsanitize=address", "-g", "-O2"]
        extra_compile_flags.extend(include_args)
        # Add project compile flags for this source
        src_flags = _extract_compile_flags(
            compile_commands,
            str(src_path.relative_to(source_root))
            if source_root in src_path.parents
            else src_path.name,
        )
        extra_compile_flags.extend(src_flags)
        extra_cmd = [cxx, "-c"] + extra_compile_flags + [str(src_path), "-o", str(extra_obj)]
        try:
            r = subprocess.run(
                extra_cmd, cwd=work_dir, capture_output=True, text=True, timeout=timeout
            )
            if r.returncode == 0:
                extra_obj_files.append(str(extra_obj))
            else:
                logger.debug("Extra source compile failed for %s: %s", src_file, r.stderr[:500])
        except (subprocess.TimeoutExpired, Exception):
            pass

    # Link step: harness.o + extra objects + resolved objects + libs
    obj_path = work_dir / obj_name
    obj_files = [str(obj_path)] + extra_obj_files + [str(p) for p in objects if p.exists()]
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
            return BuildResult(
                success=False,
                errors=_normalize_errors(combined or "Link failed"),
                compile_command=compile_cmd_str,
                link_command=link_cmd_str,
                compile_errors="",
                link_errors=combined,
                phase_failed="link",
            )
    except subprocess.TimeoutExpired:
        return BuildResult(
            success=False,
            errors="Link timed out",
            compile_command=compile_cmd_str,
            link_command=link_cmd_str,
            compile_errors="",
            link_errors="Link timed out",
            phase_failed="link",
        )
    except Exception as e:
        return BuildResult(
            success=False,
            errors=str(e),
            compile_command=compile_cmd_str,
            link_command=link_cmd_str,
            compile_errors="",
            link_errors=str(e),
            phase_failed="link",
        )

    return BuildResult(
        success=True,
        errors="",
        compile_command=compile_cmd_str,
        link_command=link_cmd_str,
        compile_errors="",
        link_errors="",
        phase_failed="",
    )


def _normalize_errors(text: str, max_lines: int = MAX_ERROR_LINES) -> str:
    """Trim and keep first N lines; drop redundant 'note:' lines if too long."""
    lines = [ln for ln in text.splitlines() if ln.strip()]
    # Optionally drop "note:" lines to save space
    if len(lines) > max_lines:
        lines = [ln for ln in lines if "note:" not in ln.lower() or "error" in ln.lower()][
            :max_lines
        ]
    else:
        lines = lines[:max_lines]
    return "\n".join(lines)


def find_manifest_for_repo(output_dir: Path, lang: str, repo_name: str) -> Path | None:
    """Return path to manifest.json: output_dir/<lang>/<repo_name>/sanitized_build/manifest.json."""
    p = output_dir / lang / repo_name / "sanitized_build" / "manifest.json"
    return p if p.is_file() else None


def get_compiler_version(cxx: str = "clang++") -> str:
    """Run cxx --version and return the first line, or empty string on failure."""
    try:
        r = subprocess.run([cxx, "--version"], capture_output=True, text=True, timeout=10)
        first_line = (r.stdout or "").strip().splitlines()[0] if r.stdout else ""
        return first_line
    except Exception:
        return ""


def write_harness_status(
    repo_name: str,
    entries: list[dict],
    repo_fuzz_targets_dir: Path,
    skipped_targets: list[dict] | None = None,
) -> Path:
    """
    Stage 7.6: Write status.json for a repo's harnesses.

    repo_fuzz_targets_dir: output/<lang>/<repo_name>/fuzz_targets.
    skipped_targets: optional list of targets skipped due to unfuzzable linkability.
    """
    repo_fuzz_targets_dir = Path(repo_fuzz_targets_dir)
    repo_fuzz_targets_dir.mkdir(parents=True, exist_ok=True)
    path = repo_fuzz_targets_dir / "status.json"
    data = []
    for e in entries:
        data.append(
            {
                "harness": str(e.get("harness", "")),
                "status": e.get("status", "unknown"),
                "errors": e.get("errors", "")[:2000],
            }
        )
    output: dict = {"repo": repo_name, "harnesses": data}
    if skipped_targets:
        output["skipped_targets"] = skipped_targets
    path.write_text(json.dumps(output, indent=2), encoding="utf-8")
    return path


def write_build_log(
    repo_name: str,
    entries: list[dict],
    repo_fuzz_targets_dir: Path,
    compiler_version: str = "",
    manifest_path: str = "",
) -> Path:
    """
    Write build_log.json with full diagnostic detail for each harness build.
    repo_fuzz_targets_dir: output/<lang>/<repo_name>/fuzz_targets.
    """
    repo_fuzz_targets_dir = Path(repo_fuzz_targets_dir)
    repo_fuzz_targets_dir.mkdir(parents=True, exist_ok=True)
    path = repo_fuzz_targets_dir / "build_log.json"

    harnesses = []
    for e in entries:
        harness_entry: dict = {
            "harness": str(e.get("harness", "")),
            "status": e.get("status", "unknown"),
            "compile_command": e.get("compile_command", ""),
            "link_command": e.get("link_command", ""),
            "phase_failed": e.get("phase_failed", ""),
            "error_class": e.get("error_class", ""),
            "compile_errors_full": e.get("compile_errors", "")[:BUILD_LOG_MAX_ERROR_CHARS],
            "link_errors_full": e.get("link_errors", "")[:BUILD_LOG_MAX_ERROR_CHARS],
        }
        # Include LLM fix iteration history if present
        iteration_history = e.get("iteration_history")
        if iteration_history:
            harness_entry["fix_iterations"] = [
                {
                    "iteration": rec.iteration,
                    "errors": rec.errors[:BUILD_LOG_MAX_ERROR_CHARS],
                    "error_class": rec.error_class,
                    "llm_response_preview": rec.llm_response_preview,
                    "result": rec.result,
                }
                if hasattr(rec, "iteration")
                else rec  # already a dict
                for rec in iteration_history
            ]
        harnesses.append(harness_entry)

    data = {
        "repo": repo_name,
        "timestamp": datetime.now(UTC).isoformat(),
        "environment": {
            "compiler": compiler_version,
            "base_flags": ["-fsanitize=fuzzer,address", "-g", "-O2"],
            "manifest_path": manifest_path,
        },
        "harnesses": harnesses,
    }
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path
