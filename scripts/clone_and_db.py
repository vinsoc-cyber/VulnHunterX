#!/usr/bin/env python3
"""
Phase 2: Clone repos and create CodeQL databases.

Clones repositories from config/repos.yaml into repos/<lang>/<name>/ and
creates CodeQL databases in databases/<lang>/<name>/.

Usage:
  python scripts/clone_and_db.py [--dry-run] [--lang LANG] [--repo NAME] [--skip-clone] [--skip-db]
"""

from __future__ import annotations

import argparse
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

# CodeQL language identifier (codeql database create --language=...)
# Use cpp for both C and C++; CodeQL indexes both.
_CODEQL_LANG: dict[str, str] = {
    "c": "cpp",
    "cpp": "cpp",
    "python": "python",
    "javascript": "javascript",
}


def load_config(config_path: Path) -> list[dict]:
    """Load repos from YAML config. Returns list of repo dicts."""
    try:
        import yaml
    except ImportError:
        sys.exit("pyyaml required: pip install pyyaml")
    if not config_path.is_file():
        sys.exit(f"Config not found: {config_path}")
    with config_path.open() as f:
        data = yaml.safe_load(f)
    repos = data.get("repos") or []
    if not isinstance(repos, list):
        sys.exit("config/repos.yaml: 'repos' must be a list")
    return repos


def clone_repo(url: str, dest: Path, dry_run: bool) -> bool:
    """Clone repo into dest. Returns True on success."""
    if dest.exists() and (dest / ".git").exists():
        return True
    if dry_run:
        print(f"  [dry-run] git clone {url} {dest}")
        return True
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            check=True,
            capture_output=True,
            text=True,
            timeout=300,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"  clone failed: {e.stderr or e}", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print("  clone timed out", file=sys.stderr)
        return False


def create_codeql_db(
    repo_root: Path,
    db_path: Path,
    language: str,
    build_command: str | None,
    codeql_path: str,
    dry_run: bool,
) -> bool:
    """Create CodeQL database. Returns True on success."""
    ql_lang = _CODEQL_LANG.get(language.lower(), language.lower())
    if ql_lang == "cpp" and not build_command:
        print(f"  skip: C/C++ requires build_command in config", file=sys.stderr)
        return False
    if db_path.exists():
        # Consider existing DB as success (idempotent)
        return True
    if dry_run:
        cmd = f"codeql database create {db_path} --language={ql_lang} --source-root={repo_root}"
        if build_command:
            cmd += f' --command="{build_command}"'
        print(f"  [dry-run] {cmd}")
        return True
    db_path.parent.mkdir(parents=True, exist_ok=True)
    cmd: list[str] = [
        codeql_path,
        "database",
        "create",
        str(db_path),
        "--language=" + ql_lang,
        "--source-root=" + str(repo_root),
    ]
    if build_command:
        cmd += ["--command=" + build_command]
    try:
        subprocess.run(
            cmd,
            cwd=str(repo_root),
            check=True,
            capture_output=True,
            text=True,
            timeout=1800,
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"  codeql database create failed: {e.stderr or e}", file=sys.stderr)
        return False
    except subprocess.TimeoutExpired:
        print("  codeql database create timed out", file=sys.stderr)
        return False


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Phase 2: Clone repos and create CodeQL databases.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=_REPO_ROOT / "config" / "repos.yaml",
        help="Path to repos YAML config",
    )
    parser.add_argument(
        "--lang",
        choices=["c", "cpp", "python", "javascript"],
        help="Only process repos of this language",
    )
    parser.add_argument(
        "--repo",
        metavar="NAME",
        help="Only process repo with this name",
    )
    parser.add_argument("--skip-clone", action="store_true", help="Skip clone step")
    parser.add_argument("--skip-db", action="store_true", help="Skip CodeQL DB creation")
    parser.add_argument("--dry-run", action="store_true", help="Print actions only")
    parser.add_argument(
        "--repos-dir",
        type=Path,
        default=_REPO_ROOT / "repos",
        help="Base dir for cloned repos",
    )
    parser.add_argument(
        "--databases-dir",
        type=Path,
        default=_REPO_ROOT / "databases",
        help="Base dir for CodeQL databases",
    )
    args = parser.parse_args()

    codeql_path = os.environ.get("CODEQL_PATH", "codeql")
    if not args.skip_db and not args.dry_run:
        if not shutil.which(codeql_path):
            print(f"CodeQL not found: {codeql_path}. Set CODEQL_PATH or install CodeQL CLI.", file=sys.stderr)
            return 1

    repos = load_config(args.config)
    # Filter by --lang and --repo
    if args.lang:
        repos = [r for r in repos if (r.get("language") or "").lower() == args.lang]
    if args.repo:
        repos = [r for r in repos if (r.get("name") or "").lower() == args.repo.lower()]
    if not repos:
        print("No repos match filters.", file=sys.stderr)
        return 1

    print("Phase 2: Clone repos and create CodeQL databases\n")
    ok_count = 0
    for r in repos:
        name = r.get("name") or "unknown"
        url = r.get("url") or ""
        lang = (r.get("language") or "python").lower()
        build_cmd = r.get("build_command")
        if not url:
            print(f"[{name}] skip: no url", file=sys.stderr)
            continue
        repo_dir = args.repos_dir / lang / name
        db_dir = args.databases_dir / lang / name
        print(f"[{name}] {lang}")

        if not args.skip_clone:
            if not clone_repo(url, repo_dir, args.dry_run):
                print(f"[{name}] clone failed", file=sys.stderr)
                continue
        if args.skip_db:
            ok_count += 1
        elif repo_dir.exists():
            if create_codeql_db(
                repo_dir,
                db_dir,
                lang,
                build_cmd,
                codeql_path,
                args.dry_run,
            ):
                ok_count += 1
            else:
                print(f"[{name}] codeql db failed", file=sys.stderr)
        elif args.dry_run:
            ok_count += 1

    print(f"\nDone. Processed {ok_count}/{len(repos)} repos.")
    return 0 if ok_count == len(repos) else 1


if __name__ == "__main__":
    sys.exit(main())
