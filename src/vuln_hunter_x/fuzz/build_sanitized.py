"""
Stage 5: Build with sanitizers (sub-stages 5.1–5.3).

Produces a sanitized build (debug + ASan/UBSan) in a separate directory
and writes a manifest for linking fuzz harnesses.
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


def _has_main_symbol(obj_path: Path) -> bool:
    """Return True if the object file defines a ``main`` symbol.

    Uses ``nm -g`` to inspect global symbols.  Objects defining ``main``
    are executable entry points and must not be linked into fuzz harnesses
    (they conflict with libFuzzer's own ``main``).
    """
    try:
        result = subprocess.run(
            ["nm", "-g", str(obj_path)],
            capture_output=True,
            text=True,
            timeout=10,
        )
        for line in result.stdout.splitlines():
            parts = line.split()
            # nm output: "<addr> <type> <name>" — defined main has type T/t
            if len(parts) >= 3 and parts[-1] == "main" and parts[-2] in ("T", "t"):
                return True
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return False


def _find_artifacts(root: Path) -> tuple[list[str], list[str]]:
    """Find static libs (.a) and object files (.o) under root.

    Object files are deduplicated by basename.  When the same ``.o`` name
    appears in both a bare directory (e.g. ``lib/foo.o``) and a ``.libs/``
    sub-directory (e.g. ``lib/.libs/foo.o``), the ``.libs/`` version is
    preferred because it is position-independent and better suited for
    linking with libFuzzer harnesses.
    """
    libs: list[str] = []
    raw_objects: list[str] = []
    for path in root.rglob("*.a"):
        try:
            rel = path.relative_to(root)
            libs.append(str(rel))
        except ValueError:
            pass
    for path in root.rglob("*.o"):
        try:
            rel = path.relative_to(root)
            # Skip test object files (e.g. test_sharedbook-sharedbook.o) —
            # these are test executables and should never be linked into fuzz harnesses
            if rel.name.startswith("test_"):
                continue
            raw_objects.append(str(rel))
        except ValueError:
            pass

    # Deduplicate objects by basename — prefer .libs/ versions (PIC)
    seen: dict[str, str] = {}
    for obj in raw_objects:
        base = Path(obj).name
        if base in seen:
            if ".libs" in obj:
                seen[base] = obj
        else:
            seen[base] = obj
    objects = list(seen.values())

    # Filter out executable objects (those defining main()) — these conflict
    # with libFuzzer's own main() and cause "multiple definition" link errors
    objects = [o for o in objects if not _has_main_symbol(root / o)]

    return libs, objects


def _inject_install_step(build_cmd: str, install_dir: Path) -> str:
    """Append a ``make install`` step so that built artifacts land in *install_dir*.

    For **autotools** (``./configure && make``): inject ``--prefix=<install_dir>``
    into the ``./configure`` call and append ``&& make install``.

    For **CMake** (``cmake`` present): inject ``-DCMAKE_INSTALL_PREFIX=<install_dir>``
    and append ``&& cmake --install <build_dir>``.

    If the build system is unrecognised, return the original command unchanged.
    """
    prefix = str(install_dir)

    if "./configure" in build_cmd:
        # Autotools: inject --prefix into configure invocation
        cmd = build_cmd.replace("./configure", f"./configure --prefix={prefix}", 1)
        # Install is best-effort — if it fails (libtool issues, missing dirs),
        # the build still succeeds and write_manifest() falls back to in-tree artifacts
        cmd += " && (make install || true)"
        return cmd

    if "cmake" in build_cmd.lower():
        # CMake: inject CMAKE_INSTALL_PREFIX
        # Find the cmake configure call (e.g. "cmake .." or "cmake -S . -B build")
        cmd = re.sub(
            r"(cmake\s)",
            rf"\1-DCMAKE_INSTALL_PREFIX={prefix} ",
            build_cmd,
            count=1,
        )
        # Try to find the build dir for cmake --install
        m = re.search(r"-B\s+(\S+)", cmd)
        cmake_build_dir = m.group(1) if m else "build_sanitized"
        cmd += f" && (cmake --install {cmake_build_dir} || true)"
        return cmd

    # Meson: inject --prefix
    if "meson setup" in build_cmd:
        cmd = build_cmd.replace("meson setup", f"meson setup --prefix={prefix}", 1)
        m = re.search(r"meson setup\s+\S+\s+(\S+)", cmd)
        meson_build_dir = m.group(1) if m else "build"
        cmd += f" && (meson install -C {meson_build_dir} || true)"
        return cmd

    # Unknown build system — try appending make install as best-effort
    if "make" in build_cmd:
        return build_cmd + f" && (make install prefix={prefix} || true)"

    return build_cmd


# Well-known symbol patterns → Debian/Ubuntu package suggestions
_COMMON_DEPS: dict[str, str] = {
    "oggpack_": "libogg-dev",
    "ogg_stream": "libogg-dev",
    "png_": "libpng-dev",
    "deflate": "zlib1g-dev",
    "compress": "zlib1g-dev",
    "SSL_": "libssl-dev",
    "jpeg_": "libjpeg-dev",
    "FLAC__": "libflac-dev",
    "snd_": "libasound2-dev",
    "curl_": "libcurl4-openssl-dev",
    "xml": "libxml2-dev",
}


def suggest_missing_deps(errors: str) -> list[str]:
    """Suggest system packages based on undefined-reference patterns in *errors*."""
    suggestions: list[str] = []
    lower = errors.lower()
    for pattern, pkg in _COMMON_DEPS.items():
        if pattern.lower() in lower and pkg not in suggestions:
            suggestions.append(pkg)
    return suggestions


def _discover_system_libs(source_root: Path) -> list[str]:
    """Discover **external** library dependencies by parsing .pc files in the build tree.

    Only extracts ``-l`` flags from ``Libs.private:`` (external deps like ``-lm``)
    — **not** ``Libs:`` which contains the project's own ``-l`` flags (those are
    already linked directly via ``.a`` files in the manifest).

    Also resolves ``Requires:`` / ``Requires.private:`` dependencies via system
    pkg-config.  Falls back gracefully if pkg-config is unavailable.
    """
    system_libs: list[str] = []
    seen_pkgs: set[str] = set()

    for pc in source_root.rglob("*.pc"):
        # Skip -uninstalled variants
        if "uninstalled" in pc.stem:
            continue
        try:
            text = pc.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            # Only collect from Libs.private (external deps like -lm, -lpthread)
            # Skip Libs: — those are the project's OWN libs already in the manifest as .a files
            if line.startswith("Libs.private:"):
                for token in line.split()[1:]:
                    if token.startswith("-l") and token not in system_libs:
                        system_libs.append(token)
            # Collect Requires dependencies (e.g. "ogg" for vorbis)
            if line.startswith("Requires") and ":" in line:
                deps = line.split(":", 1)[1].strip()
                for dep in re.split(r"[,\s]+", deps):
                    dep = dep.strip()
                    if dep and not dep[0].isdigit() and dep not in (">=", "<=", "=", ">", "<"):
                        seen_pkgs.add(dep)

    # Try to resolve required packages via system pkg-config
    for pkg in seen_pkgs:
        try:
            result = subprocess.run(
                ["pkg-config", "--libs", pkg],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                for token in result.stdout.strip().split():
                    if token.startswith("-l") and token not in system_libs:
                        system_libs.append(token)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

    return system_libs


def _discover_compiler_defines(source_root: Path) -> list[str]:
    """Extract -D compiler defines from compile_commands.json or config.h.

    Strategy 1: Parse compile_commands.json (CMake projects) for -D flags.
    Strategy 2: Scan config.h for ``#define HAVE_*`` patterns.
    Always includes ``-DHAVE_CONFIG_H`` if any config.h exists.
    """
    defines: list[str] = []
    seen: set[str] = set()

    # Strategy 1: compile_commands.json (CMake projects)
    for ccj in source_root.rglob("compile_commands.json"):
        try:
            entries = json.loads(ccj.read_text(encoding="utf-8"))
            for entry in entries:
                cmd = entry.get("command") or entry.get("arguments", "")
                tokens = cmd if isinstance(cmd, list) else cmd.split()
                for token in tokens:
                    if (
                        token.startswith("-D")
                        and token not in seen
                        and "sanitize" not in token.lower()
                    ):
                        seen.add(token)
                        defines.append(token)
        except Exception:
            pass
        break  # only use first compile_commands.json found

    # Strategy 2: config.h for #define HAVE_* patterns
    if not defines:
        for cfg_h in source_root.rglob("config.h"):
            try:
                for line in cfg_h.read_text(encoding="utf-8", errors="replace").splitlines():
                    line = line.strip()
                    if line.startswith("#define HAVE_") or line.startswith("#define PACKAGE_"):
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            name = parts[1]
                            val = parts[2] if len(parts) > 2 else None
                            flag = f"-D{name}={val}" if val else f"-D{name}"
                            if flag not in seen:
                                seen.add(flag)
                                defines.append(flag)
            except Exception:
                pass
            break  # only use first config.h found

    # Always add -DHAVE_CONFIG_H if config.h exists in the tree
    if any(source_root.rglob("config.h")) and "-DHAVE_CONFIG_H" not in seen:
        defines.insert(0, "-DHAVE_CONFIG_H")

    return defines


def write_manifest(
    build_src_dir: Path,
    manifest_path: Path,
    repo_root_for_includes: Path,
) -> None:
    """
    Sub-stage 5.3: Write manifest with libs, objects, and include_dirs.

    If an ``install/`` directory exists alongside *manifest_path* (produced by
    ``make install``), the manifest prefers the clean installed artifacts:
    static libs from ``install/lib/``, headers from ``install/include/``, and
    ``.pc`` metadata from ``install/lib/pkgconfig/``.  This eliminates the need
    for raw ``.o`` deduplication and test-object filtering.

    Falls back to in-tree artifact scraping when no install prefix is present.
    """
    install_dir = manifest_path.parent / "install"
    use_install = (install_dir / "lib").is_dir() or (install_dir / "usr" / "local" / "lib").is_dir()

    if use_install:
        # Resolve the actual root (some installs land in install/usr/local/)
        if (install_dir / "usr" / "local" / "lib").is_dir():
            effective_root = install_dir / "usr" / "local"
        elif (install_dir / "usr" / "lib").is_dir():
            effective_root = install_dir / "usr"
        else:
            effective_root = install_dir

        # Libs: only .a from the install prefix (clean, no test objects)
        libs = []
        for p in sorted((effective_root / "lib").rglob("*.a")):
            try:
                libs.append(str(p.relative_to(effective_root)))
            except ValueError:
                libs.append(str(p))
        objects: list[str] = []  # no raw .o needed when using installed .a

        # Include dirs: install prefix includes + build tree headers (for internal headers)
        include_dirs: list[str] = []
        inc_root = effective_root / "include"
        if inc_root.is_dir():
            include_dirs.append(str(inc_root))
            for d in inc_root.iterdir():
                if d.is_dir():
                    include_dirs.append(str(d))
        # Also keep build tree headers for internal headers not installed
        include_dirs.append(str(repo_root_for_includes))
        for h in build_src_dir.rglob("*.h"):
            hdir = str(h.parent)
            if hdir not in include_dirs:
                include_dirs.append(hdir)

        source_root = str(effective_root)
        system_libs = _discover_system_libs(effective_root)
        # Also check build tree .pc files as fallback
        if not system_libs:
            system_libs = _discover_system_libs(build_src_dir)
    else:
        # Fallback: in-tree artifact scraping (original behavior)
        libs_list, objects = _find_artifacts(build_src_dir)
        libs = libs_list
        include_dirs = [str(repo_root_for_includes)]
        for sub in ("build_sanitized", "build", "include", "src"):
            d = build_src_dir / sub
            if d.is_dir():
                include_dirs.append(str(d))
        for h in build_src_dir.rglob("*.h"):
            hdir = str(h.parent)
            if hdir not in include_dirs:
                include_dirs.append(hdir)
        source_root = str(build_src_dir)
        system_libs = _discover_system_libs(build_src_dir)

    compiler_defines = _discover_compiler_defines(build_src_dir)

    manifest = {
        "libs": list(dict.fromkeys(libs)),
        "objects": list(dict.fromkeys(objects)),
        "include_dirs": list(dict.fromkeys(include_dirs)),
        "source_root": source_root,
        "system_libs": system_libs,
        "compiler_defines": compiler_defines,
        "manifest_version": 2,
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

    # Inject --prefix for install step (autotools and CMake)
    install_dir = out_dir / "install"
    install_dir.mkdir(parents=True, exist_ok=True)
    install_cmd = _inject_install_step(build_cmd, install_dir)

    ok, msg = run_sanitized_build(src_copy, install_cmd, env, timeout=timeout)
    if not ok:
        suggestions = suggest_missing_deps(msg)
        if suggestions:
            msg += f"\n\nSuggested missing packages: {', '.join(suggestions)}"
        return False, msg, None

    write_manifest(src_copy, manifest_path, src_copy)
    return True, "Sanitized build completed", manifest_path
