"""
Stage 7.1–7.3: Select targets, gather context, generate harness sources.
Stage 7.4–7.6: Optionally build, LLM fix loop, write status.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Callable

from vuln_hunter_x.core.types import Finding
from vuln_hunter_x.fuzz.driver_generator import generate_harness
from vuln_hunter_x.fuzz.fuzz_context import build_type_context_string, get_target_context
from vuln_hunter_x.fuzz.target_selection import select_targets
from vuln_hunter_x.fuzz.driver_builder import (
    build_harness,
    find_manifest_for_repo,
    write_harness_status,
)
from vuln_hunter_x.fuzz.driver_fix_loop import fix_harness_with_llm, make_llm_fix_fn


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
        path = generate_harness(
            finding_rule_id=finding.rule_id,
            finding_file=finding.file,
            finding_line=finding.start_line,
            target_context=ctx,
            output_path=cc_path,
            repo_name=finding.repo_name,
        )
        out.append((finding, target_info, path))
    return out


def build_and_record(
    results: list[tuple[Finding, dict, Path | None]],
    output_dir: Path,
    llm_fix: bool = False,
    max_fix_iterations: int = 3,
    llm_provider: str = "openai",
    llm_model: str = "gpt-4o",
    llm_max_tokens: int = 4000,
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

    llm_fn: Callable[[str, str, str], str] | None = None
    if llm_fix:
        # Build per-repo type context for LLM fix prompt; use first repo if mixed
        _type_ctx = ""
        for (lang, repo_name), _ in by_repo.items():
            _ctx_dir = output_dir / lang / repo_name / "context"
            _type_ctx = build_type_context_string(_ctx_dir)
            if _type_ctx:
                break
        llm_fn = make_llm_fix_fn(llm_provider, llm_model, llm_max_tokens, type_context=_type_ctx)

    out: list[tuple[str, list[dict]]] = []
    for (lang, repo_name), items in by_repo.items():
        manifest_path = find_manifest_for_repo(output_dir, lang, repo_name)
        repo_fuzz_targets = output_dir / lang / repo_name / "fuzz_targets"
        if not manifest_path:
            entries = [{"harness": str(p), "status": "manifest_missing", "errors": "No manifest.json"} for _, _, p in items if p]
            write_harness_status(repo_name, entries, repo_fuzz_targets)
            out.append((repo_name, entries))
            continue
        entries = []
        for _finding, _info, cc_path in items:
            if cc_path is None:
                continue
            harness_name = cc_path.name
            binary_path = cc_path.with_suffix("")

            def build_fn(_cc=cc_path, _m=manifest_path, _out=binary_path):
                return build_harness(_cc, _m, _out)

            if llm_fn is not None:
                status, _iterations, last_errors = fix_harness_with_llm(
                    cc_path, build_fn, llm_fn, max_iterations=max_fix_iterations
                )
                entries.append({"harness": harness_name, "status": status, "errors": last_errors})
            else:
                ok, err, _cmd = build_harness(cc_path, manifest_path, binary_path)
                status = "compiled" if ok else ("link_failed" if "undefined reference" in err or "ld returned" in err.lower() else "compile_failed")
                entries.append({"harness": harness_name, "status": status, "errors": err})
        write_harness_status(repo_name, entries, repo_fuzz_targets)
        out.append((repo_name, entries))
    return out
