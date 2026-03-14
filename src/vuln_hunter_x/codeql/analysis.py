"""CodeQL static analysis operations."""

from __future__ import annotations

import subprocess
from collections.abc import Callable
from pathlib import Path

from vuln_hunter_x.core.constants import (
    CODEQL_QUERY_TIMEOUT_SEC,
    CODEQL_RAM_MB,
    CODEQL_THREADS,
    TIMEOUT_CODEQL_ANALYSIS,
)


class CodeQLAnalyzer:
    """
    Runs CodeQL analysis on databases.

    Supports security-extended and code-scanning query suites.
    """

    # Default query suites per language
    DEFAULT_SUITES: dict[str, str] = {
        "cpp": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "c": "codeql/cpp-queries:codeql-suites/cpp-security-extended.qls",
        "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
        "javascript": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
        "php": "codeql/php-queries:codeql-suites/php-security-extended.qls",
        "java": "codeql/java-queries:codeql-suites/java-security-extended.qls",
    }

    def __init__(
        self,
        codeql_path: str = "codeql",
        output_dir: Path | None = None,
        verbose: bool = False,
        threads: int = CODEQL_THREADS,
        ram_mb: int = CODEQL_RAM_MB,
        query_timeout: int = CODEQL_QUERY_TIMEOUT_SEC,
    ):
        self.codeql_path = codeql_path
        self.output_dir = output_dir or Path("output")
        self.verbose = verbose
        self.threads = threads
        self.ram_mb = ram_mb
        self.query_timeout = query_timeout
        self._log: Callable[[str], None] = lambda msg: None

    def set_logger(self, log_func: Callable[[str], None]) -> None:
        """Set a logging function for verbose output."""
        self._log = log_func

    def _clean_stale_locks(self, db_path: Path) -> None:
        """Remove stale CodeQL cache lock files from a previous crashed run."""
        for lock_file in db_path.rglob(".lock"):
            self._log(f"  Removing stale lock: {lock_file}")
            lock_file.unlink(missing_ok=True)

    def run_analysis(
        self,
        db_path: Path,
        lang: str,
        output_name: str | None = None,
        suite: str | None = None,
    ) -> tuple[bool, Path | None, str]:
        """
        Run CodeQL analysis on a database.

        Args:
            db_path: Path to the CodeQL database
            lang: Language (c, cpp, python, javascript)
            output_name: Name for output file (default: database name)
            suite: Query suite (default: language-specific security suite)

        Returns:
            Tuple of (success, sarif_path, message)
        """
        codeql_lang = "cpp" if lang in ("c", "cpp") else lang
        suite = suite or self.DEFAULT_SUITES.get(codeql_lang, self.DEFAULT_SUITES["cpp"])
        # output_name is repo name; SARIF goes to output_dir/<lang>/<repo_name>/<repo_name>.sarif
        output_name = (
            output_name or db_path.parent.name if db_path.name == "database" else db_path.name
        )

        sarif_dir = self.output_dir / lang / output_name
        sarif_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = sarif_dir / f"{output_name}.sarif"

        self._log(f"  Database: {db_path}")
        self._log(f"  Suite: {suite}")
        self._log(f"  Output: {sarif_path}")

        # Clean stale lock files from previous crashed/timed-out runs
        self._clean_stale_locks(db_path)

        # Check and finalize if needed
        self._log("  Checking database status...")
        finalized = self._is_finalized(db_path)
        self._log(f"  Database finalized: {finalized}")

        if not finalized:
            self._log("  Finalizing database...")
            success, msg = self._finalize(db_path)
            if not success:
                err = f"Finalization failed: {msg}"
                msg_lower = msg.lower()
                if (
                    "could not process" in msg_lower
                    or "no source code" in msg_lower
                    or "no-source-code-seen" in msg_lower
                ):
                    err += (
                        "\n\nTo fix: remove the database and re-run clone so it is recreated with a proper build:\n"
                        f"  rm -rf {db_path}\n"
                        f"  vuln-hunter-x clone --repo {output_name}"
                    )
                return False, None, err
            self._log(f"  Finalization: {msg}")

        # Run analysis
        self._log("  Running CodeQL analysis...")
        cmd = [
            self.codeql_path,
            "database",
            "analyze",
            str(db_path),
            suite,
            "--format=sarifv2.1.0",
            f"--output={sarif_path}",
            "--sarif-add-snippets",
            f"--threads={self.threads}",
            f"--ram={self.ram_mb}",
            f"--timeout={self.query_timeout}",
        ]
        self._log(f"  Command: {' '.join(cmd)}")

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=TIMEOUT_CODEQL_ANALYSIS,
            )

            if result.returncode == 0:
                # Count results in SARIF
                findings_count = self._count_sarif_results(sarif_path)
                return True, sarif_path, f"Analysis completed ({findings_count} findings)"
            else:
                error_msg = result.stderr or result.stdout
                self._log(f"  Error output: {error_msg[:500]}")
                return False, None, error_msg

        except subprocess.TimeoutExpired:
            return False, None, f"Analysis timed out ({TIMEOUT_CODEQL_ANALYSIS}s limit)"
        except Exception as e:
            return False, None, str(e)

    def _count_sarif_results(self, sarif_path: Path) -> int:
        """Count the number of results in a SARIF file."""
        if not sarif_path.is_file():
            return 0
        try:
            import json

            data = json.loads(sarif_path.read_text())
            count = 0
            for run in data.get("runs", []):
                count += len(run.get("results", []))
            return count
        except Exception:
            return 0

    def run_tool_query(
        self,
        db_path: Path,
        query_path: Path,
        output_path: Path,
    ) -> tuple[bool, str]:
        """
        Run a tool query and output to CSV.

        Args:
            db_path: Path to the CodeQL database
            query_path: Path to the .ql file
            output_path: Path for CSV output

        Returns:
            Tuple of (success, message)
        """
        bqrs_path = output_path.with_suffix(".bqrs")

        # Run query
        cmd_run = [
            self.codeql_path,
            "query",
            "run",
            str(query_path),
            f"--database={db_path}",
            f"--output={bqrs_path}",
        ]

        try:
            result = subprocess.run(
                cmd_run,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode != 0:
                return False, result.stderr or result.stdout

            # Decode to CSV
            cmd_decode = [
                self.codeql_path,
                "bqrs",
                "decode",
                "--format=csv",
                f"--output={output_path}",
                str(bqrs_path),
            ]

            result = subprocess.run(
                cmd_decode,
                capture_output=True,
                text=True,
                timeout=120,
            )

            # Clean up bqrs
            if bqrs_path.exists():
                bqrs_path.unlink()

            if result.returncode == 0:
                return True, f"Query output: {output_path}"
            else:
                return False, result.stderr or result.stdout

        except Exception as e:
            return False, str(e)

    def _is_finalized(self, db_path: Path) -> bool:
        """Check if database is finalized by looking for completion stamps."""
        # Check for completion stamps in various language DBs
        for lang_db in ["db-cpp", "db-python", "db-javascript", "db-java"]:
            stamp = db_path / lang_db / "trap" / "completion-stamp"
            if stamp.exists():
                return True

        # Also check codeql-database.yml for finalized status
        db_yml = db_path / "codeql-database.yml"
        if db_yml.exists():
            try:
                import yaml

                data = yaml.safe_load(db_yml.read_text())
                # If there's no "inProgress" or it's False, consider it finalized
                if not data.get("inProgress", False):
                    return True
            except Exception:
                pass

        return False

    def _finalize(self, db_path: Path) -> tuple[bool, str]:
        """Finalize the database. Returns success even if already finalized."""
        cmd = [self.codeql_path, "database", "finalize", str(db_path)]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            output = (result.stderr or "") + (result.stdout or "")
            output_lower = output.lower()

            if result.returncode == 0:
                return True, "Finalized successfully"

            # Treat "already finalized" as success
            if "already finalized" in output_lower:
                return True, "Already finalized"

            # Treat "no longer under construction" as success
            if "no longer under construction" in output_lower:
                return True, "Already finalized (not under construction)"

            # Treat "nothing to do" as success
            if "nothing to do" in output_lower:
                return True, "Already finalized (nothing to do)"

            return False, output

        except subprocess.TimeoutExpired:
            return False, "Finalization timed out (10 minute limit)"
        except Exception as e:
            return False, str(e)

    def download_packs(self) -> tuple[bool, str]:
        """Download required CodeQL packs."""
        packs = [
            "codeql/cpp-queries",
            "codeql/python-queries",
            "codeql/javascript-queries",
            "codeql/php-queries",
            "codeql/java-queries",
        ]

        for pack in packs:
            cmd = [self.codeql_path, "pack", "download", pack]

            try:
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if result.returncode != 0:
                    return False, f"Failed to download {pack}: {result.stderr}"

            except Exception as e:
                return False, f"Error downloading {pack}: {e}"

        return True, "All packs downloaded"
