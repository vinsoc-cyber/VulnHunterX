"""
Stage 5: Build with sanitizers (sub-stages 5.1–5.3).

Produces a sanitized build (debug + ASan/UBSan) in a separate directory
and writes a manifest for linking fuzz harnesses.

The manifest includes symbol visibility maps (via ``nm``), library export
tables, and ``compile_commands.json`` data when available.  This enables
downstream stages to classify targets by linkability and resolve minimal
link dependencies — inspired by the Futag project's approach to
dependency-aware fuzz target generation.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import shutil
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# Default sanitizer flags for C/C++
DEFAULT_SANITIZER_CFLAGS = "-fsanitize=address,undefined -g -fno-omit-frame-pointer"
DEFAULT_SANITIZER_LDFLAGS = "-fsanitize=address,undefined"


def build_sanitized_env(
    repo_config: dict[str, Any],
    lang: str,
) -> tuple[dict[str, str], str]:
    """
    Sub-stage 5.1: Prepare build environment (env vars and build command).

    Args:
        repo_config: Repo entry from repos.yaml (name, language, build_command, etc.)
        lang: Language (c or cpp).

    Returns:
        (env_dict, build_command)
        env_dict: CC, CXX, CFLAGS, CXXFLAGS, LDFLAGS for sanitized build.
        build_command: Command to run (use sanitized_build_command if set, else derive from build_command).
    """
    # Optional custom sanitizer flags from config
    sanitizer_flags = repo_config.get("sanitizer_flags") or {}
    cflags = sanitizer_flags.get("cflags", DEFAULT_SANITIZER_CFLAGS)
    ldflags = sanitizer_flags.get("ldflags", DEFAULT_SANITIZER_LDFLAGS)

    env = os.environ.copy()
    env["CC"] = "clang"
    env["CXX"] = "clang++"
    env["CFLAGS"] = cflags
    env["CXXFLAGS"] = cflags
    env["LDFLAGS"] = ldflags

    build_cmd = repo_config.get("sanitized_build_command") or repo_config.get("build_command") or ""
    if not build_cmd:
        return env, ""

    # For cmake/make out-of-tree builds, use build_sanitized dir so we don't clash with CodeQL build
    if "build" in build_cmd and ("cmake" in build_cmd or "make" in build_cmd):
        build_cmd = re.sub(r"\bbuild\b", "build_sanitized", build_cmd)

    # Inject compile_commands.json generation for CMake builds
    if "cmake" in build_cmd and "CMAKE_EXPORT_COMPILE_COMMANDS" not in build_cmd:
        build_cmd = re.sub(
            r"(cmake\s+)",
            r"\1-DCMAKE_EXPORT_COMPILE_COMMANDS=ON ",
            build_cmd,
            count=1,
        )

    return env, build_cmd.strip()


def run_sanitized_build(
    work_dir: Path,
    build_command: str,
    env: dict[str, str],
    timeout: int = 1800,
) -> tuple[bool, str]:
    """
    Sub-stage 5.2: Run sanitized build in work_dir.

    Args:
        work_dir: Directory where to run the build (e.g. copied repo).
        build_command: Shell command(s) to run.
        env: Environment with CC, CXX, CFLAGS, etc.
        timeout: Timeout in seconds.

    Returns:
        (success, message)
    """
    if not build_command:
        return False, "No build command"

    work_dir = Path(work_dir).resolve()
    if not work_dir.is_dir():
        return False, f"Work directory does not exist: {work_dir}"

    # Security note: build_command comes from repos.yaml which is a trusted,
    # operator-controlled config file. We use shell=True because build commands
    # are inherently shell expressions (e.g. "mkdir -p build && cd build && cmake ..").
    # The shlex.quote on work_dir prevents injection via directory names.
    try:
        result = subprocess.run(
            f"set -e; cd {shlex.quote(str(work_dir))}; {build_command}",
            shell=True,
            cwd=str(work_dir),
            env=env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        if result.returncode == 0:
            return True, "Build succeeded"
        err = (result.stderr or "") + (result.stdout or "")
        return False, err[:2000] or "Build failed"
    except subprocess.TimeoutExpired:
        return False, "Build timed out"
    except Exception as e:
        return False, str(e)


def _find_artifacts(root: Path) -> tuple[list[str], list[str]]:
    """Find static libs (.a) and object files (.o) under root."""
    libs: list[str] = []
    objects: list[str] = []
    for path in root.rglob("*.a"):
        try:
            rel = path.relative_to(root)
            libs.append(str(rel))
        except ValueError:
            pass
    for path in root.rglob("*.o"):
        try:
            rel = path.relative_to(root)
            objects.append(str(rel))
        except ValueError:
            pass
    return libs, objects


def _build_symbol_map(root: Path) -> tuple[dict[str, list[str]], set[str]]:
    """Build symbol-to-object mapping and identify static (file-local) symbols.

    Runs ``nm`` on every ``.o`` file under *root*.  Uppercase ``T`` in the
    nm output marks a globally visible text symbol; lowercase ``t`` marks a
    file-local (static) symbol.

    Returns:
        (symbol_to_objects, static_symbols)
        - symbol_to_objects: global symbol name → list of .o relative paths
        - static_symbols: set of symbol names that are *only* file-local
    """
    symbol_to_objects: dict[str, list[str]] = {}
    static_symbols: set[str] = set()
    global_symbols: set[str] = set()

    for obj_path in root.rglob("*.o"):
        try:
            rel = str(obj_path.relative_to(root))
        except ValueError:
            continue
        try:
            result = subprocess.run(
                ["nm", "--defined-only", str(obj_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            sym_type, sym_name = parts[1], parts[2]
            if sym_type == "T":
                global_symbols.add(sym_name)
                symbol_to_objects.setdefault(sym_name, []).append(rel)
            elif sym_type == "t":
                static_symbols.add(sym_name)

    # A symbol is truly static only if it never appears as global anywhere
    static_symbols -= global_symbols
    return symbol_to_objects, static_symbols


def _build_library_exports(root: Path, libs: list[str]) -> dict[str, list[str]]:
    """Map globally exported symbols to the ``.a`` libraries that define them.

    Runs ``nm -g --defined-only`` on each static library.

    Returns:
        lib_exports: symbol name → list of .a relative paths
    """
    lib_exports: dict[str, list[str]] = {}
    for lib_rel in libs:
        lib_path = root / lib_rel
        if not lib_path.is_file():
            continue
        try:
            result = subprocess.run(
                ["nm", "-g", "--defined-only", str(lib_path)],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                continue
        except (subprocess.TimeoutExpired, FileNotFoundError):
            continue

        for line in result.stdout.splitlines():
            parts = line.split()
            if len(parts) < 3:
                continue
            sym_type, sym_name = parts[1], parts[2]
            if sym_type == "T":
                lib_exports.setdefault(sym_name, []).append(lib_rel)
    return lib_exports


def _load_compile_commands(root: Path) -> dict[str, dict]:
    """Find and parse ``compile_commands.json`` under *root*.

    Searches common locations (``build_sanitized/``, ``build/``, root).
    Returns a mapping of source file path (relative to *root*) to its
    compile command entry ``{"directory": ..., "command": ..., "file": ...}``.
    """
    candidates = [
        root / "build_sanitized" / "compile_commands.json",
        root / "build" / "compile_commands.json",
        root / "compile_commands.json",
    ]
    cc_path = None
    for p in candidates:
        if p.is_file():
            cc_path = p
            break
    if cc_path is None:
        return {}

    try:
        entries = json.loads(cc_path.read_text(encoding="utf-8"))
    except Exception:
        logger.debug("Failed to parse compile_commands.json at %s", cc_path, exc_info=True)
        return {}

    result: dict[str, dict] = {}
    for entry in entries:
        file_path = entry.get("file", "")
        if not file_path:
            continue
        try:
            rel = str(Path(file_path).relative_to(root))
        except ValueError:
            # file_path might already be relative
            rel = file_path
        result[rel] = {
            "directory": entry.get("directory", ""),
            "command": entry.get("command", ""),
            "file": file_path,
        }
    return result


def write_manifest(
    build_src_dir: Path,
    manifest_path: Path,
    repo_root_for_includes: Path,
) -> None:
    """
    Sub-stage 5.3: Write manifest with libs, objects, and include_dirs.

    Args:
        build_src_dir: Directory containing the built tree (e.g. output/<lang>/<repo>/sanitized_build/src).
        manifest_path: Where to write manifest.json.
        repo_root_for_includes: Repository root for include paths (same as build_src_dir when we copied repo).
    """
    libs, objects = _find_artifacts(build_src_dir)
    # Include dirs: repo root and common build subdirs
    include_dirs = [str(repo_root_for_includes)]
    for sub in ("build_sanitized", "build", "include", "src"):
        d = build_src_dir / sub
        if d.is_dir():
            include_dirs.append(str(d))
    # Auto-discover directories containing header files (e.g. lib/, vorbis/)
    for h in build_src_dir.rglob("*.h"):
        hdir = str(h.parent)
        if hdir not in include_dirs:
            include_dirs.append(hdir)

    # Build symbol maps for linkability analysis
    symbol_to_objects, static_symbols = _build_symbol_map(build_src_dir)
    lib_exports = _build_library_exports(build_src_dir, sorted(libs))
    compile_commands = _load_compile_commands(build_src_dir)

    manifest = {
        "libs": sorted(libs),
        "objects": sorted(objects),
        "include_dirs": list(dict.fromkeys(include_dirs)),  # unique, order preserved
        "source_root": str(build_src_dir),
        "symbol_to_objects": symbol_to_objects,
        "static_symbols": sorted(static_symbols),
        "lib_exports": lib_exports,
        "compile_commands": compile_commands,
    }
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")


def build_sanitized(
    name: str,
    lang: str,
    repo_config: dict[str, Any],
    repos_dir: Path,
    sanitized_build_dir: Path,
    force: bool = False,
    timeout: int = 1800,
) -> tuple[bool, str, Path | None]:
    """
    Run full Stage 5: prepare env, copy repo, run sanitized build, write manifest.

    Args:
        name: Repository name.
        lang: Language (c or cpp).
        repo_config: Repo entry from repos.yaml.
        repos_dir: Path to repos directory (e.g. repos/).
        sanitized_build_dir: Output dir for this repo (e.g. output/<lang>/<name>/sanitized_build).
        force: If True, rebuild even if manifest exists.
        timeout: Build timeout in seconds.

    Returns:
        (success, message, manifest_path or None)
    """
    if lang not in ("c", "cpp"):
        return False, f"Sanitized build only supported for c/cpp, got {lang}", None

    repos_dir = Path(repos_dir).resolve()
    sanitized_build_dir = Path(sanitized_build_dir).resolve()
    repo_src = repos_dir / lang / name
    if not repo_src.is_dir():
        return False, f"Repository not found: {repo_src}", None

    out_dir = sanitized_build_dir
    src_copy = out_dir / "src"
    manifest_path = out_dir / "manifest.json"

    if manifest_path.is_file() and not force:
        return True, "Sanitized build already exists (use --force to rebuild)", manifest_path

    env, build_cmd = build_sanitized_env(repo_config, lang)
    if not build_cmd:
        return False, "No build_command for this repo", None

    # Copy repo to sanitized_build_dir/src (exclude .git)
    if src_copy.exists():
        shutil.rmtree(src_copy)
    shutil.copytree(
        repo_src, src_copy, ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__")
    )

    ok, msg = run_sanitized_build(src_copy, build_cmd, env, timeout=timeout)
    if not ok:
        return False, msg, None

    write_manifest(src_copy, manifest_path, src_copy)
    return True, "Sanitized build completed", manifest_path
