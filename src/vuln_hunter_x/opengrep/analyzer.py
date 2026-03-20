"""OpenGrep static analysis operations.

OpenGrep is an open-source fork of Semgrep (LGPL 2.1) with the same
CLI interface and rule format.  This analyzer reuses all logic from
SemgrepAnalyzer, overriding only tool-specific constants.
"""

from __future__ import annotations

from vuln_hunter_x.semgrep.analyzer import SemgrepAnalyzer


class OpenGrepAnalyzer(SemgrepAnalyzer):
    """Runs OpenGrep analysis on source trees.

    Writes SARIF to output/<lang>/<repo_name>/<repo_name>_opengrep.sarif.
    """

    TOOL_NAME: str = "opengrep"
    TOOL_LABEL: str = "OpenGrep"
    SARIF_SUFFIX: str = "_opengrep"
    ENV_VAR: str = "OPENGREP_PATH"
    DEFAULT_BINARY: str = "opengrep"
