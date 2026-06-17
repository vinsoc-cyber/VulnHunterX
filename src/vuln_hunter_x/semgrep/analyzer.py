# SPDX-License-Identifier: LGPL-2.1-only
# Copyright (c) 2026 VinSOC Cyber

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

    Subclasses (e.g. OpenGrepAnalyzer) override class constants to
    reuse the same logic with a different binary.
    """

    TOOL_NAME: str = "semgrep"
    TOOL_LABEL: str = "Semgrep"
    SARIF_SUFFIX: str = "_semgrep"
    ENV_VAR: str = "SEMGREP_PATH"
    DEFAULT_BINARY: str = "semgrep"

    def __init__(
        self,
        semgrep_path: str | None = None,
        output_dir: Path | None = None,
        verbose: bool = False,
    ):
        """Initialize the analyzer.

        Args:
            semgrep_path: Path to the binary (default: from ENV_VAR or DEFAULT_BINARY).
            output_dir: Base output directory for SARIF results.
            verbose: Enable verbose logging output.
        """
        self.binary_path = semgrep_path or os.environ.get(self.ENV_VAR, self.DEFAULT_BINARY)
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
        sarif_path = out_dir / f"{repo_name}{self.SARIF_SUFFIX}.sarif"

        # Check binary is available
        if not shutil.which(self.binary_path):
            return (
                False,
                None,
                f"{self.TOOL_NAME} not found (set {self.ENV_VAR} or install {self.TOOL_NAME})",
            )

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
            self.binary_path,
            "scan",
            "--sarif",
            f"--sarif-output={sarif_path}",
        ]
        for c in validated_configs:
            argv.append("--config")
            argv.append(c)
        argv.append(str(repo_path.resolve()))

        # Always record the resolved command so scans are reproducible and a
        # silent "0 results" outcome can be debugged from logs alone.
        cmd_str = " ".join(argv)
        logger.info("%s argv: %s", self.TOOL_LABEL, cmd_str)
        if self.verbose:
            self._log("  Command: " + cmd_str)

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
                self._log(f"  {self.TOOL_LABEL} output (last 40 lines):")
                for line in last_n:
                    self._log(f"    {line}")

            if result.returncode == 0:
                findings_count = self._count_sarif_results(sarif_path)
                rules_count = self._count_sarif_rules(sarif_path)
                msg = f"{self.TOOL_LABEL} completed in {elapsed:.1f}s ({findings_count} findings"
                if rules_count > 0:
                    msg += f", {rules_count} rules"
                msg += ")"
                # Fail loud on the silent-failure pattern: the tool loaded rules
                # and exited cleanly but produced zero results. On real source
                # this almost always means the rules did not target the language
                # (e.g. bare `auto` on Go), or registry packs failed to fetch.
                if findings_count == 0 and rules_count > 0:
                    warn = (
                        f"{self.TOOL_LABEL} loaded {rules_count} rules but produced "
                        f"0 results on {repo_path} — likely the configs do not target "
                        f"'{lang}' or registry packs failed to load. Configs: "
                        f"{validated_configs}"
                    )
                    logger.warning(warn)
                    self._log(f"  WARNING: {warn}")
                    self._log_registry_errors(result.stderr or result.stdout or "")
                    msg += " [WARNING: 0 results with rules loaded]"
                return True, sarif_path, msg
            error_msg = result.stderr or result.stdout or "Unknown error"
            logger.error("%s failed (rc=%s): %s", self.TOOL_LABEL, result.returncode, error_msg[:500])
            self._log(f"  Error: {error_msg[:500]}")
            return False, None, error_msg
        except subprocess.TimeoutExpired:
            return False, None, f"{self.TOOL_LABEL} timed out (1 hour limit)"
        except Exception as e:
            return False, None, str(e)

    # Substrings in tool output that point to a config/registry/network failure
    # rather than a genuinely clean codebase.
    _REGISTRY_ERROR_HINTS = (
        "not found",
        "could not parse",
        "failed to download",
        "failed to load",
        "no rules",
        "registry",
        "network",
        "timed out",
        "unable to resolve",
        "401",
        "403",
        "login",
    )

    def _log_registry_errors(self, output: str) -> None:
        """Surface lines that hint at registry/network/config failures.

        Called when the tool exits 0 but produces no results, to distinguish a
        clean scan from a silent misconfiguration.
        """
        if not output:
            return
        hits = [
            line.strip()
            for line in output.splitlines()
            if any(h in line.lower() for h in self._REGISTRY_ERROR_HINTS)
        ]
        if not hits:
            return
        logger.warning("%s possible config/registry issues:", self.TOOL_LABEL)
        for line in hits[:20]:
            logger.warning("  %s", line)
            self._log(f"    {line}")

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
