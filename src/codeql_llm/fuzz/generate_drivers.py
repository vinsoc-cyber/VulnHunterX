"""
Stage 7.1–7.3: Select targets, gather context, generate harness sources.

Orchestrates target_selection, fuzz_context, and driver_generator.
"""

from __future__ import annotations

import re
from pathlib import Path

from codeql_llm.core.types import Finding
from codeql_llm.fuzz.target_selection import select_targets
from codeql_llm.fuzz.fuzz_context import get_target_context
from codeql_llm.fuzz.driver_generator import generate_harness


def _harness_basename(finding: Finding) -> str:
    """Unique basename for one harness (no extension)."""
    rule = re.sub(r"[^a-zA-Z0-9]", "_", finding.rule_id.replace("/", "_"))
    file_part = re.sub(r"[^a-zA-Z0-9]", "_", finding.file)
    return f"{rule}_{file_part}_{finding.start_line}"


def generate_fuzz_drivers(
    results_dir: Path,
    context_dir: Path,
    output_dir: Path,
    fuzz_targets_dir: Path,
    repo_filter: str | None = None,
    lang_filter: str | None = None,
    verdict_filter: str = "tp,nmd",
    use_verification: bool = True,
    dry_run: bool = False,
) -> list[tuple[Finding, dict, Path | None]]:
    """
    Run sub-stages 7.1–7.3: select targets, gather context, write .cc files.

    Returns list of (finding, target_info, output_path or None if dry_run/skip).
    """
    targets = select_targets(
        results_dir=results_dir,
        context_dir=context_dir,
        output_dir=output_dir,
        repo_filter=repo_filter,
        lang_filter=lang_filter,
        verdict_filter=verdict_filter,
        use_verification=use_verification,
    )

    out: list[tuple[Finding, dict, Path | None]] = []
    for finding, _verdict, target_info in targets:
        ctx = get_target_context(target_info, finding.repo_name, context_dir)
        repo_targets = fuzz_targets_dir / finding.repo_name
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
