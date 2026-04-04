"""
Stage 7.1: Select fuzz targets from SARIF and verification results.

Resolves (file, line) → enclosing function via functions.csv or function_signatures.csv.
Classifies targets by *linkability* (library-exported, object-global, static,
executable-source) so that unfuzzable targets are skipped with a logged warning.
"""

from __future__ import annotations

import csv
import json
import logging
from pathlib import Path
from typing import TypedDict

from vuln_hunter_x.core.types import Finding
from vuln_hunter_x.fuzz.fuzz_context import load_callers, load_structs

logger = logging.getLogger(__name__)

# Linkability classification constants
LINKABILITY_LIBRARY_EXPORTED = "library_exported"
LINKABILITY_OBJECT_GLOBAL = "object_global"
LINKABILITY_STATIC = "static"
LINKABILITY_EXECUTABLE_SOURCE = "executable_source"
LINKABILITY_UNKNOWN = "unknown"

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
                    logger.debug("Failed to load verdict from %s", json_file, exc_info=True)
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
            logger.debug("Failed to parse SARIF %s", sarif_path, exc_info=True)
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
                        # is_static column added by updated functions.ql
                        is_static_raw = row.get("is_static", "")
                        is_static = is_static_raw.lower() in ("true", "1", "yes")
                        candidates.append(
                            (
                                end - start,
                                {
                                    "name": row.get("name", ""),
                                    "file": fn,
                                    "start_line": start,
                                    "end_line": end,
                                    "is_static": is_static,
                                },
                            )
                        )
                if candidates:
                    # Smallest containing range (innermost function)
                    candidates.sort(key=lambda x: x[0])
                    return candidates[0][1]
        except Exception:
            logger.debug("Failed to read functions.csv in %s", repo_context_dir, exc_info=True)

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
                            candidates.append(
                                (
                                    end - start,
                                    {
                                        "name": key[0],
                                        "file": fn,
                                        "start_line": start,
                                        "end_line": end,
                                    },
                                )
                            )
                if candidates:
                    candidates.sort(key=lambda x: x[0])
                    return candidates[0][1]
        except Exception:
            logger.debug(
                "Failed to read function_signatures.csv in %s", repo_context_dir, exc_info=True
            )

    return None


# CWE IDs associated with memory corruption — high fuzz value
_MEMORY_CORRUPTION_CWES = frozenset(
    {
        "CWE-119",
        "CWE-120",
        "CWE-121",
        "CWE-122",
        "CWE-125",
        "CWE-416",
        "CWE-415",
        "CWE-787",
        "CWE-190",
        "CWE-193",
    }
)


def _file_has_main(file_path: str, repo_context_dir: Path) -> bool:
    """Check whether *file_path* contains a ``main()`` function via functions.csv."""
    funcs_csv = Path(repo_context_dir) / "functions.csv"
    if not funcs_csv.is_file():
        return False
    file_norm = _normalize_path(file_path)
    try:
        with open(funcs_csv, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                if row.get("name") == "main" and _normalize_path(row.get("file", "")) == file_norm:
                    return True
    except Exception:
        pass
    return False


def classify_target_linkability(
    func_name: str,
    func_file: str,
    manifest: dict,
    *,
    is_static_from_codeql: bool | None = None,
    repo_context_dir: Path | None = None,
) -> str:
    """Classify a function's linkability for fuzz target generation.

    Uses the enriched manifest (symbol maps, library exports) and optionally
    the ``is_static`` column from CodeQL.

    Returns one of:
        - ``"library_exported"``: symbol in a .a library (ideal for fuzzing)
        - ``"object_global"``: global in a .o but not in any library
        - ``"static"``: file-local / static (not linkable from external harness)
        - ``"executable_source"``: in a source file that contains main()
        - ``"unknown"``: no symbol info available
    """
    lib_exports = manifest.get("lib_exports") or {}
    static_symbols = set(manifest.get("static_symbols") or [])
    symbol_to_objects = manifest.get("symbol_to_objects") or {}

    # 1. Check library exports first (ideal)
    if func_name in lib_exports:
        return LINKABILITY_LIBRARY_EXPORTED

    # 2. Check if CodeQL flagged it as static
    if is_static_from_codeql is True:
        return LINKABILITY_STATIC

    # 3. Check nm-based static symbols
    if func_name in static_symbols:
        return LINKABILITY_STATIC

    # 4. Check if it's a global symbol in an object file
    if func_name in symbol_to_objects:
        # Check if the containing source file has main() → executable source
        if repo_context_dir is not None and _file_has_main(func_file, repo_context_dir):
            return LINKABILITY_EXECUTABLE_SOURCE
        return LINKABILITY_OBJECT_GLOBAL

    # 5. Fallback: if the file has main(), it's likely an executable source
    if repo_context_dir is not None and _file_has_main(func_file, repo_context_dir):
        return LINKABILITY_EXECUTABLE_SOURCE

    return LINKABILITY_UNKNOWN


class StructMember(TypedDict):
    """Typed representation of a struct member entry."""

    name: str
    type: str


StructDefs = dict[str, list[str] | list[StructMember]]


def score_target(
    target_info: dict,
    struct_defs: StructDefs | None = None,
    callers_map: dict[str, list[str]] | None = None,
    finding: Finding | None = None,
    linkability: str = LINKABILITY_UNKNOWN,
) -> int:
    """
    Score a fuzz target by estimated fuzzability.

    +20 for library-exported linkability (ideal fuzz target)
    +10 per primitive param (int, char*, size_t, bool, float, double)
    +5 for object-global linkability
    +2 per struct param with known definition
    +2 per known caller
    +8 for buffer+length param pattern (char*/uint8_t* with size_t)
    +15 for memory corruption CWE association
    -3 if > 6 params
    -5 for single-caller private helpers (likely internal)
    -15 for static linkability
    -25 for executable-source linkability
    """
    PRIMITIVE_TOKENS = {"int", "char", "size_t", "bool", "uint", "long", "short", "float", "double"}
    params = target_info.get("params", [])
    score = 0

    has_buffer_param = False
    has_size_param = False

    for p in params:
        ptype_orig = p.get("type") or ""
        ptype_lower = ptype_orig.lower()
        base = ptype_orig.replace("const", "").replace("struct", "").replace("*", "").strip()
        if any(tok in ptype_lower for tok in PRIMITIVE_TOKENS):
            score += 10
        elif struct_defs and base in struct_defs:
            score += 2

        # Detect buffer+length pattern
        if (
            "char *" in ptype_lower
            or "uint8_t *" in ptype_lower
            or "void *" in ptype_lower
            or "unsigned char *" in ptype_lower
        ):
            has_buffer_param = True
        if "size_t" in ptype_lower and "*" not in ptype_orig:
            has_size_param = True

    if has_buffer_param and has_size_param:
        score += 8  # Natural fuzz entry point pattern

    if len(params) > 6:
        score -= 3

    func_name = target_info.get("name", "")
    if callers_map and func_name in callers_map:
        num_callers = len(callers_map[func_name])
        score += 2 * num_callers
        # Penalize single-caller private helpers
        if num_callers == 1 and func_name.startswith("_"):
            score -= 5

    # CWE-aware scoring bonus
    if (
        finding
        and hasattr(finding, "cwe_ids")
        and finding.cwe_ids
        and any(cwe in _MEMORY_CORRUPTION_CWES for cwe in finding.cwe_ids)
    ):
        score += 15

    # Linkability scoring
    linkability_bonus = {
        LINKABILITY_LIBRARY_EXPORTED: 20,
        LINKABILITY_OBJECT_GLOBAL: 5,
        LINKABILITY_STATIC: -15,
        LINKABILITY_EXECUTABLE_SOURCE: -25,
        LINKABILITY_UNKNOWN: 0,
    }
    score += linkability_bonus.get(linkability, 0)

    return score


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
        findings = get_findings_from_sarif(
            output_dir, repo_filter=repo_filter, lang_filter=lang_filter
        )
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
        # Skip main() — it's a program entry point, not a library API to fuzz.
        # Fuzzing main() would conflict with libFuzzer's own main().
        if info["name"] == "main":
            continue
        targets.append((finding, verdict, info))

    # Deduplicate: multiple findings in same function → keep highest-severity
    seen_functions: dict[tuple[str, str, int], tuple[Finding, str, dict]] = {}
    for finding, verdict, info in targets:
        func_key = (info["name"], info["file"], info["start_line"])
        existing = seen_functions.get(func_key)
        if existing is None:
            seen_functions[func_key] = (finding, verdict, info)
        else:
            # Keep TP over NMD over FP
            verdict_priority = {VERDICT_TP: 3, VERDICT_NMD: 2, VERDICT_FP: 1}
            if verdict_priority.get(verdict, 0) > verdict_priority.get(existing[1], 0):
                seen_functions[func_key] = (finding, verdict, info)
    targets = list(seen_functions.values())

    # Classify linkability and filter unfuzzable targets
    from vuln_hunter_x.fuzz.driver_builder import find_manifest_for_repo, load_manifest

    repo_manifests: dict[tuple[str, str], dict] = {}
    skipped_targets: list[dict] = []

    for finding, _verdict, info in list(targets):
        key = (finding.lang, finding.repo_name)
        if key not in repo_manifests:
            manifest_path = find_manifest_for_repo(output_dir, finding.lang, finding.repo_name)
            repo_manifests[key] = load_manifest(manifest_path) if manifest_path else {}

        manifest = repo_manifests[key]
        repo_context_dir = output_dir / finding.lang / finding.repo_name / "context"

        linkability = classify_target_linkability(
            func_name=info["name"],
            func_file=info["file"],
            manifest=manifest,
            is_static_from_codeql=info.get("is_static"),
            repo_context_dir=repo_context_dir,
        )
        info["linkability"] = linkability

    # Separate fuzzable from unfuzzable
    fuzzable: list[tuple[Finding, str, dict]] = []
    for finding, verdict, info in targets:
        linkability = info.get("linkability", LINKABILITY_UNKNOWN)
        if linkability in (LINKABILITY_STATIC, LINKABILITY_EXECUTABLE_SOURCE):
            reason = (
                "static function, not linkable from external harness"
                if linkability == LINKABILITY_STATIC
                else "executable-local function (file contains main())"
            )
            logger.warning(
                "Skipping '%s' (%s:%d): %s",
                info["name"],
                info["file"],
                info["start_line"],
                reason,
            )
            skipped_targets.append(
                {
                    "function": info["name"],
                    "file": info["file"],
                    "line": info["start_line"],
                    "reason": reason,
                    "linkability": linkability,
                }
            )
        else:
            fuzzable.append((finding, verdict, info))
    targets = fuzzable

    # Store skipped targets for status.json (accessible via the returned list)
    # We attach them to the output_dir via a side-channel JSON
    if skipped_targets:
        _write_skipped_targets(output_dir, skipped_targets)

    # Score and sort by fuzzability (best targets first)
    if targets:
        # Build per-repo enrichment data for scoring
        repo_structs: dict[tuple[str, str], dict] = {}
        repo_callers: dict[tuple[str, str], dict] = {}
        for finding, _verdict, _info in targets:
            key = (finding.lang, finding.repo_name)
            if key not in repo_structs:
                repo_context_dir = output_dir / finding.lang / finding.repo_name / "context"
                repo_structs[key] = load_structs(repo_context_dir)
                repo_callers[key] = load_callers(repo_context_dir)
        targets.sort(
            key=lambda t: score_target(
                t[2],
                struct_defs=repo_structs.get((t[0].lang, t[0].repo_name)),
                callers_map=repo_callers.get((t[0].lang, t[0].repo_name)),
                finding=t[0],
                linkability=t[2].get("linkability", LINKABILITY_UNKNOWN),
            ),
            reverse=True,
        )

    return targets


def _write_skipped_targets(output_dir: Path, skipped: list[dict]) -> None:
    """Write skipped (unfuzzable) targets to a JSON file for status reporting."""
    # Group by repo
    by_repo: dict[str, list[dict]] = {}
    for entry in skipped:
        # Derive repo from file path or use a generic key
        by_repo.setdefault("_all", []).append(entry)

    # Write to each repo's fuzz_targets dir
    for lang_dir in output_dir.iterdir():
        if not lang_dir.is_dir() or lang_dir.name not in ("c", "cpp"):
            continue
        for repo_dir in lang_dir.iterdir():
            if not repo_dir.is_dir():
                continue
            fuzz_dir = repo_dir / "fuzz_targets"
            fuzz_dir.mkdir(parents=True, exist_ok=True)
            skip_path = fuzz_dir / "skipped_targets.json"
            # Filter skipped targets for this repo
            repo_skipped = [
                s for s in skipped if any(s["file"].startswith(prefix) for prefix in ("src/", ""))
            ]
            if repo_skipped:
                skip_path.write_text(
                    json.dumps({"skipped_targets": repo_skipped}, indent=2),
                    encoding="utf-8",
                )
