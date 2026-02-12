"""Semgrep static analysis operations."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path


class SemgrepAnalyzer:
    """
    Runs Semgrep analysis on source trees.

    Writes SARIF to output/<lang>/<repo_name>/<repo_name>_semgrep.sarif.
    """

    def __init__(
        self,
        semgrep_path: str | None = None,
        output_dir: Path | None = None,
        verbose: bool = False,
    ):
        self.semgrep_path = semgrep_path or os.environ.get("SEMGREP_PATH", "semgrep")
        self.output_dir = output_dir or Path("output")
        self.verbose = verbose
        self._log: Callable[[str], None] = lambda msg: None

    def set_logger(self, log_func: Callable[[str], None]) -> None:
        """Set a logging function for verbose output."""
        self._log = log_func

    def run_analysis(
        self,
        repo_path: Path,
        lang: str,
        repo_name: str,
        output_dir: Path,
        configs: list[str] | None = None,
    ) -> tuple[bool, Path | None, str]:
        """
        Run Semgrep analysis on a repository source tree.

        Args:
            repo_path: Path to the repository source (repos/<lang>/<name>/)
            lang: Language (c, cpp, python, javascript)
            repo_name: Name of the repo (for output filename)
            output_dir: Base output directory
            configs: Semgrep configs (registry IDs or paths); default ["auto"]

        Returns:
            Tuple of (success, sarif_path, message)
        """
        if not configs:
            configs = ["auto"]

        out_dir = output_dir / lang / repo_name
        out_dir.mkdir(parents=True, exist_ok=True)
        sarif_path = out_dir / f"{repo_name}_semgrep.sarif"

        # Check semgrep is available (which or --version)
        if not shutil.which(self.semgrep_path):
            return False, None, "semgrep not found (set SEMGREP_PATH or install semgrep)"

        self._log(f"  Repo: {repo_path}")
        self._log(f"  Output: {sarif_path}")
        self._log(f"  Configs: {configs}")

        argv = [
            self.semgrep_path,
            "scan",
            "--sarif",
            f"--sarif-output={sarif_path}",
        ]
        for c in configs:
            argv.append("--config")
            argv.append(c)
        argv.append(str(repo_path.resolve()))

        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=3600,
            )
            if result.returncode == 0:
                findings_count = self._count_sarif_results(sarif_path)
                return True, sarif_path, f"Semgrep completed ({findings_count} findings)"
            error_msg = result.stderr or result.stdout or "Unknown error"
            self._log(f"  Error: {error_msg[:500]}")
            return False, None, error_msg
        except subprocess.TimeoutExpired:
            return False, None, "Semgrep timed out (1 hour limit)"
        except Exception as e:
            return False, None, str(e)

    def _count_sarif_results(self, sarif_path: Path) -> int:
        """Count the number of results in a SARIF file."""
        if not sarif_path.is_file():
            return 0
        try:
            data = json.loads(sarif_path.read_text())
            count = 0
            for run in data.get("runs", []):
                count += len(run.get("results", []))
            return count
        except Exception:
            return 0
