#!/usr/bin/env python3
"""
Phase 2: Clone repos and create CodeQL databases.

Clones repositories from config/repos.yaml into repos/<lang>/<name>/ and
creates CodeQL databases in databases/<lang>/<name>/.
Build commands are written to repo_root/.codeql_build.sh and that script path is passed to CodeQL, so &&, ;, cd, etc. work and CodeQL does not split the command by spaces.

Usage:
  python scripts/clone_and_db.py [--dry-run] [--lang LANG] [--repo NAME] [--skip-clone] [--skip-db]
  python scripts/clone_and_db.py --repo zlib --ask-llm   # On failure, ask LLM for fix recommendations
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

# Optional: litellm for --ask-llm
try:
    import litellm
except ImportError:
    litellm = None

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


def _write_build_script(repo_root: Path, build_command: str) -> Path:
    """Write build command to a script file so CodeQL gets a single path (no space-splitting)."""
    script = repo_root / ".codeql_build.sh"
    lines = ["#!/bin/sh", "set -e", ""]
    for part in build_command.strip().split("\n"):
        part = part.strip()
        if part:
            lines.append(part)
    script.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def create_codeql_db(
    repo_root: Path,
    db_path: Path,
    language: str,
    build_command: str | None,
    codeql_path: str,
    dry_run: bool,
) -> tuple[bool, str]:
    """Create CodeQL database. Returns (success, error_output). error_output is stderr+stdout on failure."""
    ql_lang = _CODEQL_LANG.get(language.lower(), language.lower())
    if ql_lang == "cpp" and not build_command:
        print(f"  skip: C/C++ requires build_command in config", file=sys.stderr)
        return False, "C/C++ requires build_command"
    if db_path.exists():
        return True, ""
    if dry_run:
        cmd = f"codeql database create {db_path} --language={ql_lang} --source-root={repo_root}"
        if build_command:
            cmd += f" --command=\"./.codeql_build.sh\"  # script with: {build_command!r}"
        print(f"  [dry-run] {cmd}")
        return True, ""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    codeql_cmd: list[str] = [
        codeql_path,
        "database",
        "create",
        str(db_path),
        "--language=" + ql_lang,
        "--source-root=" + str(repo_root),
    ]
    if build_command:
        script_path = _write_build_script(repo_root, build_command)
        codeql_cmd += ["--command=" + str(script_path)]
    try:
        result = subprocess.run(
            codeql_cmd,
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=1800,
        )
        if result.returncode == 0:
            return True, ""
        err = (result.stderr or "") + (result.stdout or "")
        print(f"  codeql database create failed: {result.stderr or result.stdout or 'unknown'}", file=sys.stderr)
        return False, err
    except subprocess.TimeoutExpired as e:
        err = (e.stdout or "") + (e.stderr or "") if e.stdout or e.stderr else "timed out"
        print("  codeql database create timed out", file=sys.stderr)
        return False, err


def ask_llm_for_recommendation(
    repo_name: str,
    language: str,
    build_command: str | None,
    error_output: str,
    output_dir: Path | None = None,
    repo_url: str = "",
) -> None:
    """Send CodeQL/build error and repo context to LLM; print concrete fix commands and suggested build_command."""
    if litellm is None:
        print("  [ask-llm] litellm not installed; pip install litellm", file=sys.stderr)
        return
    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    ollama_model = os.environ.get("OLLAMA_MODEL", "ollama/llama3.2")
    api_base = (os.environ.get("OLLAMA_API_BASE") or os.environ.get("OLLAMA_BASE_URL") or "").strip()
    use_ollama = not api_key or os.environ.get("LLM_PROVIDER", "").lower() == "ollama"
    if use_ollama:
        model = ollama_model if ollama_model.startswith("ollama/") else f"ollama/{ollama_model}"
    else:
        if not api_key:
            print("  [ask-llm] OPENAI_API_KEY not set; set it or use LLM_PROVIDER=ollama", file=sys.stderr)
            return

    lib_info = f"Library/project: {repo_name}\nRepo: {repo_url or 'unknown'}\nLanguage: {language}"
    prompt = f"""CodeQL database create failed when building a CodeQL database for static analysis.

**Library info:**
{lib_info}

**Build command used (from config):**
{build_command or 'none'}

**Full error output from CodeQL / build:**
---
{error_output[:15000]}
---

**Your task:**
1. Analyze the error and the project (known C/C++ build systems: autotools, CMake, Makefile).
2. Give concrete fix steps. For each step, provide the **exact shell command(s)** the user should run (e.g. "Run: sudo apt install cmake ninja-build" or "Run: cd build && cmake -G Ninja .. && ninja").
3. If the build command in config is wrong or incomplete, suggest a replacement. Output a line starting with "Suggested build_command:" followed by the exact string to put in config/repos.yaml (one line, use && for chaining), e.g. "Suggested build_command: mkdir -p build && cd build && cmake .. && make".

Be specific and actionable. Include exact commands to run."""

    if output_dir:
        output_dir.mkdir(parents=True, exist_ok=True)
        err_file = output_dir / f"db_error_{language}_{repo_name}.txt"
        err_file.write_text(error_output, encoding="utf-8")
        print(f"  [ask-llm] Error saved to {err_file}", file=sys.stderr)

    try:
        kwargs: dict = {
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "max_tokens": 1200,
        }
        if use_ollama and api_base:
            kwargs["api_base"] = api_base.rstrip("/")
        if api_key and not use_ollama:
            kwargs["api_key"] = api_key
        resp = litellm.completion(**kwargs)
        text = (resp.choices[0].message.content or "").strip()
        print("\n  --- LLM recommendations ---")
        print(text)
        print("  --- end ---\n")
    except Exception as e:
        print(f"  [ask-llm] LLM call failed: {e}", file=sys.stderr)


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
        "--ask-llm",
        action="store_true",
        help="On CodeQL DB failure, send error to LLM and print fix recommendations",
    )
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
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=_REPO_ROOT / "output",
        help="Dir for saved error logs (output/db_errors/) when --ask-llm",
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
            ok, err_out = create_codeql_db(
                repo_dir,
                db_dir,
                lang,
                build_cmd,
                codeql_path,
                args.dry_run,
            )
            if ok:
                ok_count += 1
            else:
                print(f"[{name}] codeql db failed", file=sys.stderr)
                if args.ask_llm and err_out:
                    ask_llm_for_recommendation(
                        name,
                        lang,
                        build_cmd,
                        err_out,
                        output_dir=args.output_dir / "db_errors",
                        repo_url=r.get("url") or "",
                    )
        elif args.dry_run:
            ok_count += 1

    print(f"\nDone. Processed {ok_count}/{len(repos)} repos.")
    return 0 if ok_count == len(repos) else 1


if __name__ == "__main__":
    sys.exit(main())
