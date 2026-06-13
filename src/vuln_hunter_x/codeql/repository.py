# SPDX-License-Identifier: MIT
# Copyright (c) 2026 VinSOC Cyber

"""Repository cloning and management."""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
from pathlib import Path

import yaml

from vuln_hunter_x.core.constants import TIMEOUT_CODEQL_DB_CREATE
from vuln_hunter_x.core.validation import (
    normalize_ollama_model,
    openai_compat_kwargs,
    validate_repo_name,
)

logger = logging.getLogger(__name__)

# Pattern for validating git URLs (https, git, ssh protocols or local paths)
_GIT_URL_RE = re.compile(
    r"^(https?://|git://|ssh://|git@)[\w\.\-/~:@]+$"
    r"|^/[\w\.\-/]+$"  # absolute local path
)


def load_repos_config(config_path: Path) -> list[dict]:
    """
    Load repositories from YAML config.

    Args:
        config_path: Path to repos.yaml

    Returns:
        List of repo dictionaries
    """
    if not config_path.is_file():
        return []

    with open(config_path) as f:
        data = yaml.safe_load(f)

    repos = data.get("repos") or []
    if not isinstance(repos, list):
        return []

    return repos


def clone_repo(
    url: str,
    dest: Path,
    depth: int = 1,
    dry_run: bool = False,
) -> tuple[bool, str]:
    """
    Clone a git repository.

    Args:
        url: Git repository URL
        dest: Destination directory
        depth: Clone depth (1 for shallow)
        dry_run: Only print what would be done

    Returns:
        Tuple of (success, message)
    """
    if dest.exists() and (dest / ".git").exists():
        return True, "Already cloned"

    if dry_run:
        return True, f"[dry-run] git clone {url} {dest}"

    dest.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["git", "clone"]
    if depth > 0:
        cmd.extend(["--depth", str(depth)])
    cmd.extend([url, str(dest)])

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode == 0:
            return True, "Cloned successfully"
        return False, result.stderr or result.stdout
    except subprocess.TimeoutExpired:
        return False, "Clone timed out"
    except Exception as e:
        return False, str(e)


def detect_build_command(repo_root: Path, language: str) -> str | None:
    """Infer a build command for C/C++ by inspecting build-system files in repo_root.

    Returns None if no recognized build system is found. Autotools is preferred
    over CMake because projects that ship both (e.g. libvorbis) are typically
    configured via their autotools path upstream.
    """
    if language.lower() not in ("c", "cpp"):
        return None

    def has(*names: str) -> bool:
        return any((repo_root / n).exists() for n in names)

    if has("autogen.sh"):
        return "./autogen.sh && ./configure && make"
    if (repo_root / "configure").is_file():
        return "./configure && make"
    if has("configure.ac", "configure.in"):
        return "autoreconf -fi && ./configure && make"
    if has("CMakeLists.txt"):
        return "cmake -B build -S . && cmake --build build"
    if has("meson.build"):
        return "meson setup build && ninja -C build"
    if has("Makefile", "GNUmakefile", "makefile"):
        return "make"
    return None


def write_build_script(repo_root: Path, build_command: str) -> Path:
    """
    Write build command to a shell script for CodeQL.

    Args:
        repo_root: Repository root directory
        build_command: Build command string

    Returns:
        Path to the build script
    """
    script = repo_root / ".codeql_build.sh"
    lines = ["#!/bin/sh", "set -e", ""]

    for part in build_command.strip().split("\n"):
        part = part.strip()
        if part:
            lines.append(part)

    script.write_text("\n".join(lines) + "\n", encoding="utf-8")
    script.chmod(0o755)
    return script


def ask_llm_for_build_help(
    repo_name: str,
    language: str,
    build_command: str | None,
    error_output: str,
    repo_url: str = "",
) -> str | None:
    """
    Ask LLM for build error recommendations.

    Args:
        repo_name: Repository name
        language: Programming language
        build_command: The build command that failed
        error_output: Error output from CodeQL/build
        repo_url: Repository URL

    Returns:
        LLM recommendation or None
    """
    try:
        import litellm
    except ImportError:
        return None

    api_key = os.environ.get("OPENAI_API_KEY", "").strip()
    model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    ollama_model = os.environ.get("OLLAMA_MODEL", "ollama/llama3.2")
    api_base = os.environ.get("OLLAMA_API_BASE", "").strip()

    use_ollama = not api_key or os.environ.get("LLM_PROVIDER", "").lower() == "ollama"
    if use_ollama:
        model = normalize_ollama_model(ollama_model)
    elif not api_key:
        return None

    prompt = f"""CodeQL database create failed when building a CodeQL database for static analysis.

**Library info:**
Library/project: {repo_name}
Repo: {repo_url or "unknown"}
Language: {language}

**Build command used (from config):**
{build_command or "none"}

**Full error output from CodeQL / build:**
---
{error_output[:15000]}
---

**Your task:**
1. Analyze the error and the project (known C/C++ build systems: autotools, CMake, Makefile).
2. Give concrete fix steps. For each step, provide the **exact shell command(s)** the user should run.
3. If the build command in config is wrong or incomplete, suggest a replacement. Output a line starting with "Suggested build_command:" followed by the exact string to put in config/repos.yaml.

Be specific and actionable. Include exact commands to run."""

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
            kwargs.update(
                openai_compat_kwargs(
                    provider="openai",
                    model=model,
                    stream=False,
                )
            )

        resp = litellm.completion(**kwargs)
        return (resp.choices[0].message.content or "").strip()
    except Exception:
        logger.warning("LLM build help request failed for %s", repo_name, exc_info=True)
        return None


def _has_source_files(repo_dir: Path, ql_lang: str) -> bool:
    """Return True if repo_dir contains at least one file for ql_lang."""
    signals = {
        "go": ["**/*.go", "go.mod"],
        "python": ["**/*.py"],
        "javascript": ["**/*.js", "**/*.ts"],
        "php": ["**/*.php"],
        "java": ["**/*.java"],
        "csharp": ["**/*.cs"],
    }
    patterns = signals.get(ql_lang)
    if not patterns:
        return True
    for pattern in patterns:
        try:
            next(repo_dir.glob(pattern))
            return True
        except StopIteration:
            continue
    return False


class RepositoryManager:
    """Manages repository cloning and CodeQL database creation."""

    CODEQL_LANG_MAP = {
        "c": "cpp",
        "cpp": "cpp",
        "python": "python",
        "javascript": "javascript",
        "php": "php",
        "java": "java",
        "go": "go",
        "csharp": "csharp",
    }

    def __init__(
        self,
        repos_dir: Path,
        output_dir: Path,
        codeql_path: str = "codeql",
    ):
        self.repos_dir = Path(repos_dir)
        self.output_dir = Path(output_dir)
        self.codeql_path = codeql_path

    def clone_and_create_db(
        self,
        name: str,
        url: str,
        language: str,
        build_command: str | None = None,
        local_path: Path | None = None,
        skip_clone: bool = False,
        skip_db: bool = False,
        dry_run: bool = False,
        ask_llm: bool = False,
        timeout: int = TIMEOUT_CODEQL_DB_CREATE,
    ) -> tuple[bool, str]:
        """
        Clone repository and create CodeQL database.

        Args:
            name: Repository name
            url: Git URL
            language: Programming language
            build_command: Build command for C/C++
            local_path: Use existing local directory instead of cloning
            skip_clone: Skip git clone
            skip_db: Skip database creation
            dry_run: Only print actions
            ask_llm: Ask LLM on failure
            timeout: CodeQL database creation timeout in seconds

        Returns:
            Tuple of (success, message)
        """
        try:
            validate_repo_name(name)
        except ValueError as e:
            return False, str(e)

        repo_dir = Path(local_path).resolve() if local_path else (self.repos_dir / language / name).resolve()
        db_dir = (self.output_dir / language / name / "database").resolve()

        # Clone
        if not skip_clone:
            ok, msg = clone_repo(url, repo_dir, dry_run=dry_run)
            if not ok:
                return False, f"Clone failed: {msg}"

        if skip_db:
            return True, "Cloned (DB skipped)"

        if not repo_dir.exists() and not dry_run:
            return False, "Repository not found"

        # Create database
        ql_lang = self.CODEQL_LANG_MAP.get(language.lower(), language.lower())

        if ql_lang == "cpp" and not build_command:
            build_command = detect_build_command(repo_dir, language)
            if not build_command:
                return False, (
                    f"C/C++ requires build_command and none could be auto-detected in {repo_dir}. "
                    "Pass --build-command (e.g. \"./autogen.sh && ./configure && make\" or "
                    "\"cmake -B build && cmake --build build\")."
                )
            logger.info("[%s] auto-detected build command: %s", name, build_command)

        # Pre-flight: verify the repo actually contains source files for the target language.
        if not dry_run and not _has_source_files(repo_dir, ql_lang):
            lang_display = language.lower()
            return False, (
                f"No {lang_display} source files found in {repo_dir}. "
                f"Verify that --lang {lang_display} matches the repository's actual language."
            )

        if db_dir.exists():
            if dry_run:
                return True, "Database already exists"
            # Validate existing DB for all languages by running finalize
            try:
                r = subprocess.run(
                    [self.codeql_path, "database", "finalize", str(db_dir)],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
                out = (r.stderr or "") + (r.stdout or "")
                out_lower = out.lower()
                if r.returncode == 0:
                    return True, "Database already exists"
                if (
                    "already finalized" in out_lower
                    or "no longer under construction" in out_lower
                    or "nothing to do" in out_lower
                ):
                    return True, "Database already exists"
                if (
                    "could not process" in out_lower
                    or "no source code" in out_lower
                    or "no-source-code-seen" in out_lower
                ):
                    shutil.rmtree(db_dir)
                    # Fall through to create database
                else:
                    return (
                        False,
                        f"Existing database could not be finalized: {(out[:500] + '...') if len(out) > 500 else out}",
                    )
            except subprocess.TimeoutExpired:
                return False, "Existing database finalization check timed out"
            except Exception as e:
                return False, f"Existing database finalization check failed: {e}"

        if dry_run:
            return True, f"[dry-run] Would create database at {db_dir}"

        db_dir.parent.mkdir(parents=True, exist_ok=True)

        cmd = [
            self.codeql_path,
            "database",
            "create",
            str(db_dir),
            f"--language={ql_lang}",
            f"--source-root={repo_dir}",
        ]

        if build_command:
            script_path = write_build_script(repo_dir, build_command)
            cmd.append(f"--command={script_path.resolve()}")
        elif ql_lang == "csharp":
            # C# is compiled; without an explicit build command, use CodeQL's
            # buildless extractor so users don't need a working `dotnet build`.
            cmd.append("--build-mode=none")

        try:
            result = subprocess.run(
                cmd,
                cwd=str(repo_dir),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode == 0:
                return True, "Database created"

            # Clean up any partial database directory so re-runs start fresh.
            if db_dir.exists():
                shutil.rmtree(db_dir, ignore_errors=True)

            error = (result.stderr or "") + (result.stdout or "")
            error_lower = error.lower()

            # Build an actionable prefix before the raw log.
            prefix = ""
            if "resolved 0 packages" in error_lower:
                prefix = (
                    "No Go packages could be resolved (go list found 0 packages). "
                    "Ensure go.mod is present and dependencies are available "
                    "(try: go mod download or go mod vendor). "
                )
            elif "no source code" in error_lower or "no-source-code-seen" in error_lower:
                prefix = (
                    "No source code was extracted. "
                    f"Check that --lang {language.lower()} matches the repository's actual language. "
                )

            if ask_llm:
                recommendation = ask_llm_for_build_help(name, language, build_command, error, url)
                if recommendation:
                    return (
                        False,
                        f"{prefix}Database creation failed.\n\nLLM Recommendation:\n{recommendation}",
                    )

            err_msg = (
                error
                if len(error) <= 800
                else (error[:200] + "\n... (truncated) ...\n" + error[-600:])
            )
            return False, f"{prefix}Database creation failed: {err_msg}"

        except subprocess.TimeoutExpired:
            # Clean up any partial database directory so re-runs start fresh.
            if db_dir.exists():
                shutil.rmtree(db_dir, ignore_errors=True)
            return False, (
                f"Database creation timed out after {timeout}s. "
                "Increase with --db-timeout or CODEQL_DB_CREATE_TIMEOUT."
            )
        except Exception as e:
            return False, str(e)

    def process_repos_config(
        self,
        config_path: Path,
        lang_filter: str | None = None,
        repo_filter: str | None = None,
        skip_clone: bool = False,
        skip_db: bool = False,
        dry_run: bool = False,
        ask_llm: bool = False,
        timeout: int = TIMEOUT_CODEQL_DB_CREATE,
    ) -> list[tuple[str, bool, str]]:
        """
        Process all repos from config file.

        Returns:
            List of (name, success, message) tuples
        """
        repos = load_repos_config(config_path)

        if lang_filter:
            repos = [r for r in repos if r.get("language", "").lower() == lang_filter]
        if repo_filter:
            repos = [r for r in repos if r.get("name", "").lower() == repo_filter.lower()]

        results: list[tuple[str, bool, str]] = []

        for repo in repos:
            name = repo.get("name", "unknown")
            url = repo.get("url", "")
            language = repo.get("language", "python").lower()
            build_cmd = repo.get("build_command")

            if not url:
                results.append((name, False, "No URL"))
                continue

            ok, msg = self.clone_and_create_db(
                name=name,
                url=url,
                language=language,
                build_command=build_cmd,
                skip_clone=skip_clone,
                skip_db=skip_db,
                dry_run=dry_run,
                ask_llm=ask_llm,
                timeout=timeout,
            )
            results.append((name, ok, msg))

        return results
