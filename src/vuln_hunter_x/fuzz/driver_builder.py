"""
Stage 7.4: Compile and link harness with Stage 5 manifest.

Captures stderr/stdout and returns success/failure plus normalized error text.
"""

from __future__ import annotations

import json
import logging
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


def build_harness(
    harness_cc: Path,
    manifest_path: Path,
    output_binary: Path | None = None,
    cxx: str = "clang++",
    timeout: int = 120,
    extra_include_dirs: list[str] | None = None,
    extra_lib_dirs: list[str] | None = None,
    extra_link_libs: list[str] | None = None,
) -> BuildResult:
    """
    Compile and link one harness with Stage 5 manifest.

    Args:
        harness_cc: Path to .cc file
        manifest_path: Path to manifest.json (output/<lang>/<repo>/sanitized_build/manifest.json)
        output_binary: Path for fuzz binary; default harness_cc.with_suffix('')
        cxx: C++ compiler
        timeout: Timeout in seconds
        extra_include_dirs: Additional -I paths from config/CLI
        extra_lib_dirs: Additional -L paths from config/CLI
        extra_link_libs: Additional -l libraries from config/CLI

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

    objects = _sanitized_entries(manifest, "objects", source_root)
    libs = _sanitized_entries(manifest, "libs", source_root)

    # New manifest fields (backwards compatible with v1 manifests)
    compiler_defines = manifest.get("compiler_defines") or []
    manifest_extra_cflags = manifest.get("extra_cflags") or []
    manifest_extra_ldflags = manifest.get("extra_ldflags") or []

    out_bin = output_binary or harness_cc.with_suffix("")
    work_dir = harness_cc.parent
    cc_name = harness_cc.name
    obj_name = harness_cc.stem + ".o"

    flag_list = ["-fsanitize=fuzzer,address", "-g", "-O2"]
    include_args = [f"-I{d}" for d in include_dirs if d.exists()]

    # Extra flags from config/CLI
    extra_inc_args = [f"-I{d}" for d in (extra_include_dirs or [])]
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

    # Link step: harness.o + objects + libs
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
) -> Path:
    """
    Stage 7.6: Write status.json for a repo's harnesses.
    repo_fuzz_targets_dir: output/<lang>/<repo_name>/fuzz_targets.
    """
    repo_fuzz_targets_dir = Path(repo_fuzz_targets_dir)
    repo_fuzz_targets_dir.mkdir(parents=True, exist_ok=True)
    path = repo_fuzz_targets_dir / "status.json"
    data = []
    for e in entries:
        entry: dict = {
            "harness": str(e.get("harness", "")),
            "status": e.get("status", "unknown"),
            "errors": e.get("errors", "")[:2000],
        }
        # Additive fields (backward compatible)
        if e.get("compile_command"):
            entry["compile_command"] = e["compile_command"]
        if e.get("link_command"):
            entry["link_command"] = e["link_command"]
        if e.get("phase_failed"):
            entry["phase_failed"] = e["phase_failed"]
        if e.get("error_class"):
            entry["error_class"] = e["error_class"]
        if e.get("fix_iterations_count") is not None:
            entry["fix_iterations"] = e["fix_iterations_count"]
        data.append(entry)
    path.write_text(json.dumps({"repo": repo_name, "harnesses": data}, indent=2), encoding="utf-8")
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
