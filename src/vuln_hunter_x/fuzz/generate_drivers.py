"""
Stage 7.1–7.3: Select targets, gather context, generate harness sources.
Stage 7.4–7.6: Optionally build, LLM fix loop, write status.

Wires together target selection (with linkability filtering), harness
generation (with source-inclusion for static functions), selective linking,
and LLM fix loops with symbol context.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import Path

from vuln_hunter_x.core.constants import DEFAULT_MAX_FIX_ITERATIONS
from vuln_hunter_x.core.types import Finding
from vuln_hunter_x.fuzz.build_sanitized import write_manifest
from vuln_hunter_x.fuzz.driver_builder import (
    build_harness,
    find_manifest_for_repo,
    load_manifest,
    write_harness_status,
)
from vuln_hunter_x.fuzz.driver_fix_loop import (
    classify_errors,
    fix_harness_with_llm,
    make_llm_fix_fn,
)
from vuln_hunter_x.fuzz.driver_generator import generate_harness
from vuln_hunter_x.fuzz.fuzz_context import build_type_context_string, get_target_context
from vuln_hunter_x.fuzz.target_selection import (
    _file_has_main,
    select_targets,
)

logger = logging.getLogger(__name__)


def _harness_basename(finding: Finding) -> str:
    """Unique basename for one harness (no extension)."""
    rule = re.sub(r"[^a-zA-Z0-9]", "_", finding.rule_id.replace("/", "_"))
    file_part = re.sub(r"[^a-zA-Z0-9]", "_", finding.file)
    return f"{rule}_{file_part}_{finding.start_line}"


def generate_fuzz_drivers(
    output_dir: Path,
    repo_filter: str | None = None,
    lang_filter: str | None = None,
    verdict_filter: str = "tp,nmd",
    use_verification: bool = True,
    dry_run: bool = False,
) -> list[tuple[Finding, dict, Path | None]]:
    """
    Run sub-stages 7.1–7.3: select targets, gather context, write .cc files.
    Uses output_dir/<lang>/<repo>/verification_results, context, fuzz_targets.

    Returns list of (finding, target_info, output_path or None if dry_run/skip).
    """
    targets = select_targets(
        output_dir=output_dir,
        repo_filter=repo_filter,
        lang_filter=lang_filter,
        verdict_filter=verdict_filter,
        use_verification=use_verification,
    )

    # Load manifests for source_root info
    repo_manifests: dict[tuple[str, str], dict] = {}

    out: list[tuple[Finding, dict, Path | None]] = []
    for finding, _verdict, target_info in targets:
        repo_context_dir = output_dir / finding.lang / finding.repo_name / "context"
        ctx = get_target_context(target_info, repo_context_dir)
        repo_targets = output_dir / finding.lang / finding.repo_name / "fuzz_targets"
        basename = _harness_basename(finding)
        cc_path = repo_targets / f"{basename}.cc"
        if dry_run:
            out.append((finding, target_info, None))
            continue

        # Get manifest for source_root and linkability context
        key = (finding.lang, finding.repo_name)
        if key not in repo_manifests:
            mp = find_manifest_for_repo(output_dir, finding.lang, finding.repo_name)
            repo_manifests[key] = load_manifest(mp) if mp else {}
        manifest = repo_manifests[key]
        source_root = manifest.get("source_root", "")

        linkability = target_info.get("linkability", "unknown")
        has_main = _file_has_main(target_info.get("file", ""), repo_context_dir)

        path = generate_harness(
            finding_rule_id=finding.rule_id,
            finding_file=finding.file,
            finding_line=finding.start_line,
            target_context=ctx,
            output_path=cc_path,
            repo_name=finding.repo_name,
            linkability=linkability,
            source_root=source_root,
            file_has_main=has_main,
        )
        out.append((finding, target_info, path))
    return out


def build_and_record(
    results: list[tuple[Finding, dict, Path | None]],
    output_dir: Path,
    llm_fix: bool = False,
    max_fix_iterations: int = DEFAULT_MAX_FIX_ITERATIONS,
    llm_provider: str = "openai",
    llm_model: str = "gpt-4o",
    llm_max_tokens: int = 4000,
    extra_include_dirs: list[str] | None = None,
    extra_lib_dirs: list[str] | None = None,
    extra_link_libs: list[str] | None = None,
) -> list[tuple[str, list[dict]]]:
    """
    Stage 7.4–7.6: Build each harness, optionally run LLM fix loop, write status.json per repo.
    Uses output_dir/<lang>/<repo>/sanitized_build and output_dir/<lang>/<repo>/fuzz_targets.

    results: from generate_fuzz_drivers (finding, target_info, cc_path).
    Returns list of (repo_name, status_entries).
    """
    by_repo: dict[tuple[str, str], list[tuple[Finding, dict, Path | None]]] = {}
    for finding, info, path in results:
        if path is None:
            continue
        key = (finding.lang, finding.repo_name)
        by_repo.setdefault(key, []).append((finding, info, path))

    out: list[tuple[str, list[dict]]] = []
    for (lang, repo_name), items in by_repo.items():
        manifest_path = find_manifest_for_repo(output_dir, lang, repo_name)
        repo_fuzz_targets = output_dir / lang / repo_name / "fuzz_targets"

        # Refresh manifest to pick up any write_manifest() improvements (e.g. new include dirs)
        if manifest_path:
            source_root = manifest_path.parent / "src"
            if source_root.is_dir():
                write_manifest(source_root, manifest_path, source_root)

        if not manifest_path:
            entries = [
                {"harness": str(p), "status": "manifest_missing", "errors": "No manifest.json"}
                for _, _, p in items
                if p
            ]
            write_harness_status(repo_name, entries, repo_fuzz_targets)
            out.append((repo_name, entries))
            continue

        # Build LLM fix function per-repo (with symbol context)
        llm_fn: Callable[[str, str, str], str] | None = None
        if llm_fix:
            _ctx_dir = output_dir / lang / repo_name / "context"
            _type_ctx = build_type_context_string(_ctx_dir)
            _symbol_ctx = _build_symbol_context(manifest_path)
            llm_fn = make_llm_fix_fn(
                llm_provider,
                llm_model,
                llm_max_tokens,
                type_context=_type_ctx,
                symbol_context=_symbol_ctx,
            )

        entries = []
        for _finding, _info, cc_path in items:
            if cc_path is None:
                continue
            harness_name = cc_path.name
            binary_path = cc_path.with_suffix("")

            # Capture last BuildResult from build_fn via closure
            _last_br: list = [None]

            def build_fn(_cc=cc_path, _m=manifest_path, _out=binary_path, _ti=_info, _br=_last_br):
                result = build_harness(_cc, _m, _out, target_info=_ti)
                _br[0] = result
                return result

            if llm_fn is not None:
                fix_result = fix_harness_with_llm(
                    cc_path, build_fn, llm_fn, max_iterations=max_fix_iterations
                )
                status = fix_result.status
                iterations_used = fix_result.iterations_used
                last_errors = fix_result.last_errors
                err_class = classify_errors(last_errors) if last_errors else ""

                logger.info(
                    "[%s] %s: %s (fix iterations=%d)",
                    repo_name,
                    harness_name,
                    status,
                    iterations_used,
                )

                # Extract commands from the last captured BuildResult
                br = _last_br[0]
                compile_cmd = br.compile_command if br else ""
                link_cmd = br.link_command if br else ""
                compile_errors = br.compile_errors if br else ""
                link_errors = br.link_errors if br else ""

                # Determine phase from status
                if status == "link_failed":
                    phase = "link"
                elif status in ("compile_failed", "llm_fix_failed"):
                    phase = "compile"
                else:
                    phase = ""

                entries.append(
                    {
                        "harness": harness_name,
                        "status": status,
                        "errors": last_errors,
                        "compile_command": compile_cmd,
                        "link_command": link_cmd,
                        "phase_failed": phase,
                        "error_class": err_class,
                        "compile_errors": compile_errors,
                        "link_errors": link_errors,
                        "fix_iterations_count": iterations_used,
                        "iteration_history": fix_result.iteration_history,
                    }
                )
            else:
                ok, err, _cmd = build_harness(
                    cc_path, manifest_path, binary_path, target_info=_info
                )
                status = (
                    "compiled"
                    if ok
                    else (
                        "link_failed"
                        if "undefined reference" in err or "ld returned" in err.lower()
                        else "compile_failed"
                    )
                )
                entries.append({"harness": harness_name, "status": status, "errors": err})

        # Load skipped targets if available
        skipped_path = repo_fuzz_targets / "skipped_targets.json"
        skipped = []
        if skipped_path.is_file():
            try:
                import json

                skipped = json.loads(skipped_path.read_text()).get("skipped_targets", [])
            except Exception:
                pass

        write_harness_status(repo_name, entries, repo_fuzz_targets, skipped_targets=skipped)
        out.append((repo_name, entries))
    return out


def _build_symbol_context(manifest_path: Path) -> str:
    """Build a compact symbol context string for LLM fix prompts.

    Includes library exports and static symbol lists from the manifest.
    """
    manifest = load_manifest(manifest_path)
    if not manifest:
        return ""

    parts: list[str] = []
    lib_exports = manifest.get("lib_exports") or {}
    if lib_exports:
        # Show first 50 library-exported symbols
        exported = sorted(lib_exports.keys())[:50]
        parts.append("Library-exported symbols (linkable via .a):")
        parts.append(", ".join(exported))
        if len(lib_exports) > 50:
            parts.append(f"  ... and {len(lib_exports) - 50} more")

    static_symbols = manifest.get("static_symbols") or []
    if static_symbols:
        parts.append(f"\nStatic (file-local) symbols ({len(static_symbols)} total):")
        parts.append(", ".join(sorted(static_symbols)[:30]))

    return "\n".join(parts)[:2000]
