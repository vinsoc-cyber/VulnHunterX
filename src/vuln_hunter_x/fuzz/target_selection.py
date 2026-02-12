"""
Stage 7.1: Select fuzz targets from SARIF and verification results.

Resolves (file, line) → enclosing function via functions.csv or function_signatures.csv.
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

from vuln_hunter_x.core.types import Finding, Verdict

# Verdict values we use for filtering
VERDICT_TP = "True Positive"
VERDICT_NMD = "Needs More Data"
VERDICT_FP = "False Positive"


def _finding_from_dict(d: dict) -> Finding:
    """Build Finding from verdict JSON finding dict."""
    f = d.get("finding") if isinstance(d.get("finding"), dict) else d
    return Finding(
        rule_id=f.get("rule_id", ""),
        message=f.get("message", ""),
        file=f.get("file", ""),
        start_line=int(f.get("start_line", 0)),
        end_line=int(f.get("end_line", 0)),
        repo_name=f.get("repo_name", ""),
        lang=f.get("lang", "c"),
        sarif_path=f.get("sarif_path", ""),
    )


def load_verification_verdicts(
    output_dir: Path,
    repo_filter: str | None = None,
    lang_filter: str | None = None,
    verdict_filter: list[str] | None = None,
) -> list[tuple[Finding, str]]:
    """
    Load verification result JSONs from output_dir/<lang>/<repo>/verification_results/
    and return (finding, verdict) for matching verdicts.

    verdict_filter: e.g. ["True Positive", "Needs More Data"]. If None, all verdicts.
    """
    if verdict_filter is None:
        verdict_filter = [VERDICT_TP, VERDICT_NMD]
    output_dir = Path(output_dir)
    if not output_dir.is_dir():
        return []

    out: list[tuple[Finding, str]] = []
    for lang_dir in output_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        lang = lang_dir.name
        if lang_filter and lang != lang_filter:
            continue
        if lang not in ("c", "cpp"):
            continue
        for repo_dir in lang_dir.iterdir():
            if not repo_dir.is_dir():
                continue
            repo_name = repo_dir.name
            if repo_filter and repo_name.lower() != repo_filter.lower():
                continue
            ver_dir = repo_dir / "verification_results"
            if not ver_dir.is_dir():
                continue
            for json_file in ver_dir.glob("*.json"):
                if json_file.name.startswith("summary_"):
                    continue
                try:
                    data = json.loads(json_file.read_text())
                    verdict = (data.get("verdict") or "").strip()
                    if verdict not in verdict_filter:
                        continue
                    finding = _finding_from_dict(data)
                    out.append((finding, verdict))
                except Exception:
                    continue
    return out


def get_findings_from_sarif(
    output_dir: Path,
    repo_filter: str | None = None,
    lang_filter: str | None = None,
) -> list[Finding]:
    """Discover SARIF files and parse all findings (for --verdict all)."""
    from vuln_hunter_x.sarif.parser import discover_sarif_files, parse_sarif_file

    output_dir = Path(output_dir)
    tuples = discover_sarif_files(output_dir)
    findings: list[Finding] = []
    for sarif_path, lang, repo_name in tuples:
        if lang not in ("c", "cpp"):
            continue
        if lang_filter and lang != lang_filter:
            continue
        if repo_filter and repo_name.lower() != repo_filter.lower():
            continue
        try:
            findings.extend(parse_sarif_file(sarif_path, lang, repo_name))
        except Exception:
            continue
    return findings


def _normalize_path(p: str) -> str:
    return p.replace("\\", "/").strip()


def find_enclosing_function(
    file: str,
    line: int,
    repo_context_dir: Path,
) -> dict | None:
    """
    Resolve (file, line) to enclosing function using functions.csv or function_signatures.csv.

    repo_context_dir: output/<lang>/<repo_name>/context (contains functions.csv, etc.)
    Returns dict with name, file, start_line, end_line or None if not found.
    """
    repo_ctx = Path(repo_context_dir)
    file_norm = _normalize_path(file)

    # Prefer functions.csv (one row per function with start/end)
    funcs_csv = repo_ctx / "functions.csv"
    if funcs_csv.is_file():
        try:
            with open(funcs_csv, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                candidates = []
                for row in reader:
                    fn = _normalize_path(row.get("file", ""))
                    if fn != file_norm:
                        continue
                    start = int(row.get("start_line", 0))
                    end = int(row.get("end_line", 0))
                    if start <= line <= end:
                        candidates.append((end - start, {"name": row.get("name", ""), "file": fn, "start_line": start, "end_line": end}))
                if candidates:
                    # Smallest containing range (innermost function)
                    candidates.sort(key=lambda x: x[0])
                    return candidates[0][1]
        except Exception:
            pass

    # Fallback: function_signatures.csv (group by name, file, start_line, end_line)
    sigs_csv = repo_ctx / "function_signatures.csv"
    if sigs_csv.is_file():
        try:
            with open(sigs_csv, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                candidates = []
                seen = set()
                for row in reader:
                    fn = _normalize_path(row.get("file", ""))
                    if fn != file_norm:
                        continue
                    start = int(row.get("start_line", 0))
                    end = int(row.get("end_line", 0))
                    if start <= line <= end:
                        key = (row.get("name", ""), fn, start, end)
                        if key not in seen:
                            seen.add(key)
                            candidates.append((end - start, {"name": key[0], "file": fn, "start_line": start, "end_line": end}))
                if candidates:
                    candidates.sort(key=lambda x: x[0])
                    return candidates[0][1]
        except Exception:
            pass

    return None


def select_targets(
    output_dir: Path,
    repo_filter: str | None = None,
    lang_filter: str | None = None,
    verdict_filter: str = "tp,nmd",
    use_verification: bool = True,
) -> list[tuple[Finding, str, dict]]:
    """
    Stage 7.1: Produce list of (finding, verdict, target_function_info).
    Uses output_dir/<lang>/<repo>/verification_results and output_dir/<lang>/<repo>/context.

    verdict_filter: "tp,nmd" (default), "tp", "all", etc. "all" = use SARIF only.
    use_verification: if True and verdict_filter not "all", load from output_dir.
    """
    output_dir = Path(output_dir)
    if verdict_filter.lower() == "all":
        findings = get_findings_from_sarif(output_dir, repo_filter=repo_filter, lang_filter=lang_filter)
        verdicts_for_finding = [(f, "all") for f in findings]
    else:
        verdict_map = {"tp": [VERDICT_TP], "nmd": [VERDICT_NMD], "fp": [VERDICT_FP]}
        wanted = []
        for v in verdict_filter.lower().replace(" ", "").split(","):
            v = v.strip()
            if v == "tp":
                wanted.extend(verdict_map["tp"])
            elif v == "nmd":
                wanted.extend(verdict_map["nmd"])
            elif v == "fp":
                wanted.extend(verdict_map["fp"])
            else:
                wanted.append(v)
        if not wanted:
            wanted = [VERDICT_TP, VERDICT_NMD]
        if use_verification and output_dir.is_dir():
            verdicts_for_finding = load_verification_verdicts(
                output_dir, repo_filter=repo_filter, lang_filter=lang_filter, verdict_filter=wanted
            )
        else:
            verdicts_for_finding = []

    targets: list[tuple[Finding, str, dict]] = []
    for finding, verdict in verdicts_for_finding:
        if finding.lang not in ("c", "cpp"):
            continue
        repo_context_dir = output_dir / finding.lang / finding.repo_name / "context"
        info = find_enclosing_function(
            finding.file,
            finding.start_line,
            repo_context_dir,
        )
        if info is None:
            continue
        targets.append((finding, verdict, info))
    return targets
