# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

"""CodeQL database creation and management."""

from __future__ import annotations

import subprocess
from pathlib import Path

from vuln_hunter_x.core.constants import TIMEOUT_CODEQL_DB_CREATE
from vuln_hunter_x.core.types import RepositoryInfo


class DatabaseManager:
    """
    Manages CodeQL database creation and management.

    Supports creating databases for C/C++, Python, and JavaScript.
    """

    # Default build commands per language
    DEFAULT_BUILD_COMMANDS: dict[str, str] = {
        "c": "./configure && make",
        "cpp": "cmake -B build && cmake --build build",
        "python": "",  # No build needed
        "javascript": "npm install --ignore-scripts",  # Just install deps
        "php": "",  # No build needed
        "java": "",  # CodeQL auto-detects Maven/Gradle
        "go": "",  # CodeQL auto-detects Go builds
        "csharp": "",  # Buildless: --build-mode=none (see create_database)
    }

    def __init__(
        self,
        codeql_path: str = "codeql",
        repos_dir: Path | None = None,
        output_dir: Path | None = None,
    ):
        self.codeql_path = codeql_path
        self.repos_dir = repos_dir or Path("repos")
        self.output_dir = output_dir or Path("output")

    def create_database(
        self,
        repo: RepositoryInfo,
        overwrite: bool = False,
        timeout: int = TIMEOUT_CODEQL_DB_CREATE,
    ) -> tuple[bool, str]:
        """
        Create a CodeQL database for a repository.

        Args:
            repo: Repository information
            overwrite: Whether to overwrite existing database
            timeout: CodeQL database creation timeout in seconds

        Returns:
            Tuple of (success, message)
        """
        lang = repo.lang
        # C and C++ both use CodeQL's "cpp" language; all others map directly
        codeql_lang = "cpp" if lang in ("c", "cpp") else lang

        source_root = repo.local_path or (self.repos_dir / lang / repo.name)
        db_path = repo.database_path or (self.output_dir / lang / repo.name / "database")

        if not Path(source_root).is_dir():
            return False, f"Repository not found: {source_root}"

        if Path(db_path).exists() and not overwrite:
            return True, f"Database already exists: {db_path}"

        # Build command
        build_cmd = repo.build_command or self.DEFAULT_BUILD_COMMANDS.get(lang, "")

        # Create database
        cmd = [
            self.codeql_path,
            "database",
            "create",
            str(db_path),
            f"--language={codeql_lang}",
            f"--source-root={source_root}",
            "--overwrite" if overwrite else "",
        ]

        if build_cmd:
            cmd.extend(["--command", build_cmd])
        elif codeql_lang == "csharp":
            # C# is compiled; without an explicit build use CodeQL's buildless
            # extractor so users don't need a working `dotnet build`.
            cmd.append("--build-mode=none")

        # Filter empty strings
        cmd = [c for c in cmd if c]

        try:
            result = subprocess.run(
                cmd,
                cwd=str(source_root),
                capture_output=True,
                text=True,
                timeout=timeout,
            )

            if result.returncode == 0:
                return True, f"Database created: {db_path}"
            else:
                return False, result.stderr or result.stdout

        except subprocess.TimeoutExpired:
            return False, f"Database creation timed out after {timeout}s"
        except Exception as e:
            return False, str(e)

    def finalize_database(self, db_path: Path) -> tuple[bool, str]:
        """
        Finalize an incomplete CodeQL database.

        Args:
            db_path: Path to the database

        Returns:
            Tuple of (success, message)
        """
        cmd = [self.codeql_path, "database", "finalize", str(db_path)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode == 0:
                return True, "Database finalized"
            else:
                return False, result.stderr or result.stdout

        except Exception as e:
            return False, str(e)

    def get_database_language(self, db_path: Path) -> str | None:
        """Get the language of a CodeQL database."""
        codeql_db_scheme = db_path / "codeql-database.yml"
        if not codeql_db_scheme.is_file():
            return None

        import yaml

        try:
            with open(codeql_db_scheme) as f:
                data = yaml.safe_load(f)
            if isinstance(data, dict):
                lang = data.get("primaryLanguage")
                return str(lang) if lang is not None else None
            return None
        except Exception:
            return None

    def list_databases(
        self,
        lang_filter: str | None = None,
    ) -> list[tuple[Path, str, str]]:
        """
        List all databases under output_dir/<lang>/<repo_name>/database.

        Args:
            lang_filter: Optional language filter

        Returns:
            List of (db_path, lang, repo_name) tuples
        """
        databases: list[tuple[Path, str, str]] = []

        if not self.output_dir.is_dir():
            return databases

        for lang_dir in self.output_dir.iterdir():
            if not lang_dir.is_dir():
                continue

            lang = lang_dir.name
            if lang_filter and lang != lang_filter:
                continue

            for repo_dir in lang_dir.iterdir():
                if not repo_dir.is_dir():
                    continue
                repo_name = repo_dir.name
                db_dir = repo_dir / "database"
                if (db_dir / "codeql-database.yml").is_file():
                    databases.append((db_dir, lang, repo_name))

        return databases
