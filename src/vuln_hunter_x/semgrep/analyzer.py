"""Semgrep static analysis operations."""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from collections.abc import Callable
from pathlib import Path

logger = logging.getLogger(__name__)

# Semgrep configs must be: local file paths, "auto", or registry rules (e.g. "p/security-audit")
_VALID_CONFIG_RE = re.compile(r"^(auto|p/[\w\-/]+|r/[\w\-/\.]+)$")


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
        """Initialize the Semgrep analyzer.

        Args:
            semgrep_path: Path to the semgrep binary (default: from SEMGREP_PATH env or "semgrep").
            output_dir: Base output directory for SARIF results.
            verbose: Enable verbose logging output.
        """
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

        # Validate configs: allow local paths, "auto", or known registry patterns
        validated_configs = []
        for c in configs:
            if _VALID_CONFIG_RE.match(c):
                validated_configs.append(c)
            elif Path(c).is_file() or Path(c).is_dir():
                validated_configs.append(str(Path(c).resolve()))
            else:
                logger.warning("Skipping invalid Semgrep config: %s", c)
        if not validated_configs:
            return False, None, "No valid Semgrep configs after validation"

        self._log(f"  Repo: {repo_path}")
        self._log(f"  Output: {sarif_path}")
        self._log(f"  Configs: {validated_configs}")

        argv = [
            self.semgrep_path,
            "scan",
            "--sarif",
            f"--sarif-output={sarif_path}",
        ]
        for c in validated_configs:
            argv.append("--config")
            argv.append(c)
        argv.append(str(repo_path.resolve()))

        if self.verbose:
            self._log("  Command: " + " ".join(argv))

        start = time.perf_counter()
        try:
            result = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=3600,
            )
            elapsed = time.perf_counter() - start

            if self.verbose and (result.stdout or result.stderr):
                combined = (result.stdout or "") + (result.stderr or "")
                lines = combined.strip().splitlines()
                last_n = lines[-40:] if len(lines) > 40 else lines
                self._log("  Semgrep output (last 40 lines):")
                for line in last_n:
                    self._log(f"    {line}")

            if result.returncode == 0:
                findings_count = self._count_sarif_results(sarif_path)
                rules_count = self._count_sarif_rules(sarif_path)
                msg = f"Semgrep completed in {elapsed:.1f}s ({findings_count} findings"
                if rules_count > 0:
                    msg += f", {rules_count} rules"
                msg += ")"
                return True, sarif_path, msg
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
        except (json.JSONDecodeError, OSError, ValueError):
            return 0

    def _count_sarif_rules(self, sarif_path: Path) -> int:
        """Count the number of rules in a SARIF file (from tool.driver.rules)."""
        if not sarif_path.is_file():
            return 0
        try:
            data = json.loads(sarif_path.read_text())
            total = 0
            for run in data.get("runs", []):
                rules = run.get("tool", {}).get("driver", {}).get("rules", [])
                if isinstance(rules, list):
                    total += len(rules)
            return total
        except (json.JSONDecodeError, OSError, ValueError):
            return 0
