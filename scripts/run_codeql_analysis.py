#!/usr/bin/env python3
"""
Phase 3: Run CodeQL static analysis on databases and output SARIF (and optional findings JSON).

For each CodeQL database under databases/<lang>/<name>/, runs the appropriate
security-extended suite and writes SARIF to output/sarif/<lang>/<name>.sarif.
Optionally converts SARIF to a simple findings JSON for Phase 4.

Usage:
  python scripts/run_codeql_analysis.py [--dry-run] [--lang LANG] [--repo NAME] [--json]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

# Load .env from repo root
_REPO_ROOT = Path(__file__).resolve().parent.parent
if _REPO_ROOT.joinpath(".env").exists():
    try:
        from dotenv import load_dotenv
        load_dotenv(_REPO_ROOT / ".env")
    except ImportError:
        pass

# CodeQL suite pack references (codeql pack download may be required)
_SUITES: dict[str, str] = {
    "c": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
    "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
    "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
}


def discover_dbs(databases_dir: Path) -> list[tuple[Path, str, str]]:
    """Discover CodeQL DBs under databases/<lang>/<name>/. Returns [(db_path, lang, name), ...]."""
    out: list[tuple[Path, str, str]] = []
    if not databases_dir.is_dir():
        return out
    for lang_dir in databases_dir.iterdir():
        if not lang_dir.is_dir():
            continue
        lang = lang_dir.name.lower()
        if lang not in _SUITES:
            continue
        for name_dir in lang_dir.iterdir():
            if not name_dir.is_dir():
                continue
            # CodeQL 2.x: DB root has codeql-database.yml
            if (name_dir / "codeql-database.yml").exists():
                out.append((name_dir, lang, name_dir.name))
            elif (name_dir / "log").exists():
                # Older layout: log dir indicates DB root
                out.append((name_dir, lang, name_dir.name))
    return out


def finalize_db(db_path: Path, codeql_path: str, dry_run: bool) -> bool:
    """Run codeql database finalize so the DB can be queried. Returns True if ready to query."""
    if dry_run:
        print(f"  [dry-run] codeql database finalize {db_path}")
        return True
    try:
        result = subprocess.run(
            [codeql_path, "database", "finalize", str(db_path)],
            capture_output=True,
            text=True,
            timeout=1800,
            cwd=_REPO_ROOT,
        )
        if result.returncode == 0:
            return True
        # Already finalized or no longer under construction -> treat as success
        err = (result.stderr or "") + (result.stdout or "")
        if "already finalized" in err.lower() or "no longer under construction" in err.lower():
            return True
        print(f"  finalize failed: {result.stderr or result.stdout}", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print("  finalize timed out", file=sys.stderr)
        return False


def run_queries(
    db_path: Path,
    suite: str,
    sarif_path: Path,
    codeql_path: str,
    dry_run: bool,
) -> bool:
    """Run CodeQL suite on DB and write SARIF via codeql database analyze."""
    if dry_run:
        print(f"  [dry-run] codeql database finalize {db_path}; codeql database analyze ... -o {sarif_path}")
        return True
    if not finalize_db(db_path, codeql_path, dry_run=False):
        return False
    sarif_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            [
                codeql_path,
                "database",
                "analyze",
                str(db_path),
                "--format=sarifv2.1.0",
                f"--output={sarif_path}",
                "--",
                suite,
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=3600,
            cwd=_REPO_ROOT,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"  analyze failed: {e.stderr or e}", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print("  analyze timed out", file=sys.stderr)
        return False


def sarif_to_findings(sarif_path: Path) -> list[dict]:
    """Parse SARIF and return list of findings: [{rule_id, message, file, start_line, end_line}, ...]."""
    if not sarif_path.is_file():
        return []
    try:
        data = json.loads(sarif_path.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    findings: list[dict] = []
    runs = data.get("runs") or []
    for run in runs:
        results = run.get("results") or []
        artifacts = {a.get("index"): a for a in (run.get("artifacts") or []) if "index" in a}
        for r in results:
            rule_id = (r.get("ruleId") or r.get("rule", {}).get("id") or "")
            msg_obj = r.get("message") or {}
            message = msg_obj.get("text") or (msg_obj.get("messageId") or "")
            locs = r.get("locations") or []
            for loc in locs:
                phys = loc.get("physicalLocation") or {}
                art_ref = phys.get("artifactLocation") or {}
                uri = art_ref.get("uri") or ""
                art_index = art_ref.get("index")
                if art_index is not None and art_index in artifacts:
                    uri = (artifacts[art_index].get("location", {}).get("uri") or uri)
                region = phys.get("region") or {}
                start_line = region.get("startLine") or 0
                end_line = region.get("endLine") or start_line
                findings.append({
                    "rule_id": rule_id,
                    "message": message,
                    "file": uri,
                    "start_line": start_line,
                    "end_line": end_line,
                })
            if not locs:
                findings.append({
                    "rule_id": rule_id,
                    "message": message,
                    "file": "",
                    "start_line": 0,
                    "end_line": 0,
                })
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 3: Run CodeQL static analysis and output SARIF (and optional JSON).",
    )
    parser.add_argument(
        "--databases-dir",
        type=Path,
        default=_REPO_ROOT / "databases",
        help="Base dir containing CodeQL databases",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "output",
        help="Base dir for SARIF and findings output",
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript"],
        help="Only process DBs of this language",
    )
    parser.add_argument(
        "--repo",
        metavar="NAME",
        help="Only process DB with this repo name",
    )
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Also write findings JSON (output/findings/<lang>/<name>.json)",
    )
    args = parser.parse_args()

    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    if not args.dry_run and not shutil.which(codeql_path):
        print(f"CodeQL not found: {codeql_path}. Set CODEQL_PATH or install CodeQL CLI.", file=sys.stderr)
        return 1

    dbs = discover_dbs(args.databases_dir)
    if args.lang:
        dbs = [(p, lang, name) for p, lang, name in dbs if lang == args.lang]
    if args.repo:
        dbs = [(p, lang, name) for p, lang, name in dbs if name.lower() == args.repo.lower()]
    if not dbs:
        print("No CodeQL databases found. Run Phase 2 first (clone_and_db.py).", file=sys.stderr)
        return 1

    print("Phase 3: Run CodeQL static analysis\n")
    ok_count = 0
    for db_path, lang, name in dbs:
        suite = _SUITES.get(lang)
        if not suite:
            print(f"[{name}] skip: no suite for language {lang}", file=sys.stderr)
            continue
        sarif_path = args.output_dir / "sarif" / lang / f"{name}.sarif"
        print(f"[{name}] {lang} -> {sarif_path}")
        if run_queries(db_path, suite, sarif_path, codeql_path, args.dry_run):
            ok_count += 1
            if args.json and sarif_path.is_file():
                findings = sarif_to_findings(sarif_path)
                json_path = args.output_dir / "findings" / lang / f"{name}.json"
                json_path.parent.mkdir(parents=True, exist_ok=True)
                json_path.write_text(json.dumps(findings, indent=2))
                print(f"  -> {len(findings)} findings -> {json_path}")
        else:
            print(f"[{name}] analyze failed", file=sys.stderr)

    print(f"\nDone. Processed {ok_count}/{len(dbs)} databases.")
    return 0 if ok_count == len(dbs) else 1


if __name__ == "__main__":
    sys.exit(main())
